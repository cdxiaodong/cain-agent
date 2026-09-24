"""SDKExecutor — Cain 的统一 Agent 执行引擎入口(Phase 1 架构件)。

把 Claude Agent SDK 的 ``query()`` 收敛为项目统一的执行引擎,后续
Orchestrator / Hook / Skills 全部挂在它上面。

设计要点(对照 DESIGN.md §3.2 事故教训驱动设计):

- **只读原则**:`allowed_tools` 默认空列表 = 零工具,不给工具就没有爪牙。
- **Hook 硬拦截挂载点**:PreToolUse 钩子在此注册并透传给 SDK,
  ScopeGuardHook(安全地基,任务 2)将挂在这里,不靠 prompt 自律。
- **死循环烧 token 对策**:idle 超时(默认 300s)+ 墙钟总预算双防线,
  任一触发即优雅中断并返回已收集的部分结果,不抛裸异常。
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    HookCallback,
    HookMatcher,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    query,
)
from claude_agent_sdk.types import HookEvent

DEFAULT_IDLE_TIMEOUT = 300.0
"""默认消息流空闲超时秒数(DESIGN.md §3.2:idle_timeout=300s)。"""

INTERRUPT_IDLE_TIMEOUT = "idle_timeout"
"""中断原因:消息流超过 idle_timeout 没有新消息。"""

INTERRUPT_TOTAL_BUDGET = "total_budget"
"""中断原因:单次 run 的墙钟总预算触顶。"""


@dataclass
class ToolCallRecord:
    """一次工具调用的结构化记录(供审计日志 / 报告使用)。"""

    tool_use_id: str
    name: str
    input: dict[str, Any]
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )
    completed: bool = False
    succeeded: bool = False
    response_hash: str | None = None
    status_code: int | None = None


_HTTP_STATUS_LINE_RE = re.compile(r"(?im)^HTTP/\S+\s+(\d{3})\b")
"""Matches a genuine status line (``curl -D -``/``-i`` style: ``HTTP/2 200``)."""

_BARE_STATUS_CODE_RE = re.compile(r"\A[1-5]\d{2}\Z")
"""Matches output that *is*, in its entirety, a 3-digit status code — the
``curl -s -o /dev/null -w '%{http_code}'`` idiom, which prints nothing else."""


def _tool_output_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts)
    return ""


def complete_tool_call(record: ToolCallRecord, output: object, *, succeeded: bool) -> None:
    """Attach non-secret execution facts to a tool call without persisting response text.

    ``status_code`` is only ever set from an unambiguous signal: a real
    ``HTTP/x.y NNN`` status line, or output that consists of nothing but a
    3-digit code. A prior looser fallback scanned the *entire* tool output for
    any bare 3-digit number in [100, 599] and took the last one found —  which
    reliably misfired on Cloudflare-fronted targets, where the response
    headers include an ``Alt-Svc: h3=":443"`` (or similar) header: "443"
    sorts after the real "HTTP/2 200" status line, so it silently overwrote
    the recorded status. Never guess a status code from unrelated digits in
    the body/headers — leave it ``None`` when there is no unambiguous line.
    """
    text = _tool_output_text(output)
    record.completed = True
    record.succeeded = succeeded
    record.response_hash = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    status_lines = list(_HTTP_STATUS_LINE_RE.finditer(text))
    if status_lines:
        record.status_code = int(status_lines[-1].group(1))
        return
    bare = _BARE_STATUS_CODE_RE.match(text.strip())
    if bare:
        record.status_code = int(bare.group())


@dataclass
class ExecutorResult:
    """``SDKExecutor.run`` 的结构化收敛结果。

    无论正常结束、被超时/预算中断、还是 SDK 侧抛错,都返回本对象:
    - 中断时 ``interrupted=True`` 且 ``interrupt_reason`` 标明触发防线;
    - SDK 侧异常收敛进 ``error`` 字段并置 ``is_error=True``,裸异常绝不逃逸到调用方。
    """

    text: str = ""
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    usage: dict[str, Any] | None = None
    total_cost_usd: float | None = None
    session_id: str | None = None
    num_turns: int = 0
    is_error: bool = False
    interrupted: bool = False
    interrupt_reason: str | None = None
    error: str | None = None


class SDKExecutor:
    """Claude Agent SDK 的最小封装,项目统一的执行引擎入口。

    参数:
        allowed_tools: 工具白名单,默认空列表 = 零工具(只读原则)。
        hooks: SDK 原生 hook 配置,原样透传给 ``ClaudeAgentOptions``。
        idle_timeout: 消息流空闲超时秒数,超过即优雅中断(默认 300s)。
        total_budget: 单次 ``run`` 的墙钟总预算秒数,触顶即优雅中断;``None`` 表示不限。
        resume_session_id: 断点续跑的 session id(预留,对应 SDK 的 ``resume``)。
        max_turns: 最大对话轮数(可选,原样透传)。
    """

    def __init__(
        self,
        *,
        allowed_tools: list[str] | None = None,
        hooks: dict[HookEvent, list[HookMatcher]] | None = None,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        total_budget: float | None = None,
        resume_session_id: str | None = None,
        max_turns: int | None = None,
    ) -> None:
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive")
        if total_budget is not None and total_budget <= 0:
            raise ValueError("total_budget must be positive when set")
        self.allowed_tools: list[str] = list(allowed_tools) if allowed_tools else []
        self.hooks: dict[HookEvent, list[HookMatcher]] = (
            {event: list(matchers) for event, matchers in hooks.items()} if hooks else {}
        )
        self.idle_timeout = idle_timeout
        self.total_budget = total_budget
        self.resume_session_id = resume_session_id
        self.max_turns = max_turns

    def add_pre_tool_use_hook(self, callback: HookCallback, *, matcher: str | None = None) -> None:
        """注册一个 PreToolUse hook —— ScopeGuardHook 等硬拦截钩子的挂载点。

        参数:
            callback: 符合 SDK ``HookCallback`` 签名的可调用对象。
            matcher: 工具名匹配模式(如 ``"Bash"``、``"Write|Edit"``),``None`` 表示所有工具。
        """
        matchers = self.hooks.setdefault("PreToolUse", [])
        matchers.append(HookMatcher(matcher=matcher, hooks=[callback]))

    def build_options(self) -> ClaudeAgentOptions:
        """把 executor 配置翻译为 SDK 的 ``ClaudeAgentOptions``(独立成方法便于单测断言)。"""
        return ClaudeAgentOptions(
            allowed_tools=list(self.allowed_tools),
            hooks={event: list(m) for event, m in self.hooks.items()} if self.hooks else None,
            resume=self.resume_session_id,
            max_turns=self.max_turns,
        )

    def _interrupt_reason(self, idle_deadline: float, total_deadline: float | None) -> str:
        """判断是哪条防线先触顶。"""
        if total_deadline is not None and total_deadline <= idle_deadline:
            return INTERRUPT_TOTAL_BUDGET
        return INTERRUPT_IDLE_TIMEOUT

    async def run(self, prompt: str) -> ExecutorResult:
        """执行一次 prompt,把消息流收敛为 ``ExecutorResult``。

        idle 超时或总预算触顶时优雅中断,返回已收集的部分结果;SDK 侧异常
        收敛进 ``result.error``,不向调用方抛裸异常。
        """
        result = ExecutorResult()
        texts: list[str] = []
        final_text: str | None = None

        start = time.monotonic()
        idle_deadline = start + self.idle_timeout
        total_deadline = start + self.total_budget if self.total_budget is not None else None

        stream = query(prompt=prompt, options=self.build_options())
        iterator = stream.__aiter__()
        try:
            while True:
                now = time.monotonic()
                deadline = idle_deadline if total_deadline is None else min(idle_deadline, total_deadline)
                remaining = deadline - now
                if remaining <= 0:
                    result.interrupted = True
                    result.interrupt_reason = self._interrupt_reason(idle_deadline, total_deadline)
                    break
                try:
                    message = await asyncio.wait_for(iterator.__anext__(), timeout=remaining)
                except StopAsyncIteration:
                    break
                except TimeoutError:
                    result.interrupted = True
                    result.interrupt_reason = self._interrupt_reason(idle_deadline, total_deadline)
                    break

                # 每收到一条消息就重置 idle 倒计时;total 倒计时只增不减。
                idle_deadline = time.monotonic() + self.idle_timeout

                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            texts.append(block.text)
                        elif isinstance(block, ToolUseBlock):
                            result.tool_calls.append(
                                ToolCallRecord(tool_use_id=block.id, name=block.name, input=block.input)
                            )
                elif isinstance(message, UserMessage) and isinstance(message.content, list):
                    by_id = {call.tool_use_id: call for call in result.tool_calls}
                    for block in message.content:
                        if isinstance(block, ToolResultBlock) and block.tool_use_id in by_id:
                            complete_tool_call(
                                by_id[block.tool_use_id],
                                block.content,
                                succeeded=not bool(block.is_error),
                            )
                elif isinstance(message, SystemMessage):
                    if message.subtype == "init":
                        session_id = message.data.get("session_id")
                        if isinstance(session_id, str):
                            result.session_id = session_id
                elif isinstance(message, ResultMessage):
                    result.usage = message.usage
                    result.total_cost_usd = message.total_cost_usd
                    result.session_id = message.session_id
                    result.num_turns = message.num_turns
                    result.is_error = message.is_error
                    final_text = message.result
        except Exception as exc:  # noqa: BLE001 — 引擎边界,异常必须收敛进结果对象
            result.is_error = True
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            aclose = getattr(stream, "aclose", None)
            if aclose is not None:
                with contextlib.suppress(Exception):
                    await aclose()

        result.text = "".join(texts) if texts else (final_text or "")
        return result
