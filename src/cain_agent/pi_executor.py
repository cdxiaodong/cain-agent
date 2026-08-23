"""PiExecutor — 第二执行引擎:经 Node 桥进程驱动 agent 运行时。

与 ``SDKExecutor`` 同接口(duck-type):``add_pre_tool_use_hook`` /
``build_options`` / ``async run -> ExecutorResult``。Orchestrator /
FindingsPipeline / StageHandler 不感知后端差异,``cain-agent run --backend pi``
即可整链路切换。

架构(stdio JSON 行协议,子进程为 Node 桥 ``toolchain/pi/bridge.mjs``):

    Python(PiExecutor)                Node(bridge.mjs)
    ───────────────────                ────────────────
    {"type":"run",...}    ──stdin──▶   起 Agent、注册 Bash 工具
    {"type":"verdict",...}◀─stdin──   tool_request:工具调用前回判
    {"type":"tool_request"}──stdout▶   (Python 侧跑 ScopeGuardHook)
    {"type":"tool_result"}──stdout▶   审计记录(无论放行与否)
    {"type":"text"}        ─stdout▶   助手文本增量
    {"type":"done"}        ─stdout▶   最终收敛(usage / turns / error)

安全语义与 ``SDKExecutor`` 对齐,一处都不降级:

- **scope 判定单点在 Python**:桥不自带放行逻辑,每笔工具调用必须拿到
  Python 侧 verdict 才会执行;注册的 PreToolUse hook(通常是 ScopeGuardHook)
  原样复用——发现与校验双会话、默认拒绝、deny 优先,全部不变。
- **零工具只读通道**:`allowed_tools=[]` 时桥不给模型注册任何工具,校验
  Agent 只能输出结构化 JSON。
- **双防线**:idle 超时(每条 stdout 消息重置)+ 墙钟总预算,触顶即杀桥
  进程并返回已收集的部分结果,裸异常不逃逸。
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cain_agent.executor import (
    DEFAULT_IDLE_TIMEOUT,
    INTERRUPT_IDLE_TIMEOUT,
    INTERRUPT_TOTAL_BUDGET,
    ExecutorResult,
    ToolCallRecord,
)

DEFAULT_BRIDGE_PATH = (
    Path(__file__).resolve().parent.parent.parent / "toolchain" / "pi" / "bridge.mjs"
)
"""Node 桥脚本默认位置(仓库布局 src/cain_agent/../../toolchain/pi/)."""

HookEntry = tuple[Callable[..., Any], str | None]
"""(callback, matcher):callback 契约与 SDK HookCallback 一致 —— ``async
(input_data, tool_use_id, context) -> dict``;空 dict = 放行,含 deny 决策的
dict = 拒绝。matcher 为正则(如 ``"Bash"``、``"Write|Edit"``),None 匹配全部。"""


def _matcher_hits(matcher: str | None, tool_name: str) -> bool:
    """True if *matcher* regex fully matches *tool_name*(None = 全匹配)."""
    if matcher is None:
        return True
    return re.fullmatch(matcher, tool_name) is not None


def _decision_denies(decision: dict[str, Any]) -> bool:
    """按 SDK 语义解读 hook 决策:空 dict 放行;明确 deny 或无法识别的非空决策按拒绝(保守)."""
    if not decision:
        return False
    specific = decision.get("hookSpecificOutput")
    if isinstance(specific, dict):
        verdict = str(specific.get("permissionDecision", ""))
        return verdict != "allow"
    return True


class PiExecutor:
    """经 Node 桥驱动 agent 运行时的第二执行引擎(接口对齐 ``SDKExecutor``).

    参数:
        provider / model: 桥侧 LLM provider 与模型 id(多 provider 由桥的
            统一 LLM 层支持);``model=None`` 用 provider 默认模型。
        allowed_tools: 工具白名单;空列表 = 零工具只读通道(校验 Agent 用)。
            目前桥内工具为 ``Bash``(与现有 hook matcher 大小写一致)。
        idle_timeout / total_budget: 与 ``SDKExecutor`` 相同的双防线秒数。
        max_turns: 最大对话轮数(可选,透传桥)。
        node_bin: Node 解释器(默认 ``node``)。
        bridge_path: 桥脚本路径(默认仓库内 ``toolchain/pi/bridge.mjs``)。
    """

    def __init__(
        self,
        *,
        provider: str = "anthropic",
        model: str | None = None,
        allowed_tools: list[str] | None = None,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        total_budget: float | None = None,
        max_turns: int | None = None,
        node_bin: str = "node",
        bridge_path: str | Path | None = None,
    ) -> None:
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive")
        if total_budget is not None and total_budget <= 0:
            raise ValueError("total_budget must be positive when set")
        self.provider = provider
        self.model = model
        self.allowed_tools: list[str] = list(allowed_tools) if allowed_tools else []
        self.idle_timeout = idle_timeout
        self.total_budget = total_budget
        self.max_turns = max_turns
        self.node_bin = node_bin
        self.bridge_path = Path(bridge_path) if bridge_path else DEFAULT_BRIDGE_PATH
        self._hooks: list[HookEntry] = []

    # -- 构造面 ----------------------------------------------------------

    def add_pre_tool_use_hook(
        self, callback: Callable[..., Any], *, matcher: str | None = None
    ) -> None:
        """注册 PreToolUse hook —— 与 ``SDKExecutor`` 相同的挂载点签名."""
        self._hooks.append((callback, matcher))

    def build_options(self) -> dict[str, Any]:
        """把 executor 配置收敛为可断言快照(对应 ``SDKExecutor.build_options``)."""
        return {
            "backend": "pi",
            "provider": self.provider,
            "model": self.model,
            "allowed_tools": list(self.allowed_tools),
            "idle_timeout": self.idle_timeout,
            "total_budget": self.total_budget,
            "max_turns": self.max_turns,
            "bridge_path": str(self.bridge_path),
        }

    # -- 运行面 ----------------------------------------------------------

    async def _spawn_bridge(self) -> Any:
        """起桥子进程;测试注入 fake 进程时覆写本方法。"""
        if not self.bridge_path.exists():
            raise FileNotFoundError(
                f"pi bridge not found: {self.bridge_path} "
                "(run `npm install` under toolchain/pi/ — see toolchain/pi/README.md)"
            )
        return await asyncio.create_subprocess_exec(
            self.node_bin,
            str(self.bridge_path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def _judge(
        self, tool_use_id: str, name: str, tool_input: dict[str, Any]
    ) -> bool:
        """跑全部匹配的 PreToolUse hook,任一 deny 即拒绝(deny 优先)."""
        input_data = {"tool_name": name, "tool_input": tool_input}
        for callback, matcher in self._hooks:
            if not _matcher_hits(matcher, name):
                continue
            decision = await callback(input_data, tool_use_id, None)
            if _decision_denies(decision if isinstance(decision, dict) else {}):
                return False
        return True

    async def _send(self, stream: Any, payload: dict[str, Any]) -> None:
        stream.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        await stream.drain()

    def _interrupt_reason(self, idle_deadline: float, total_deadline: float | None) -> str:
        """判断是哪条防线先触顶(与 ``SDKExecutor`` 相同语义)."""
        if total_deadline is not None and total_deadline <= idle_deadline:
            return INTERRUPT_TOTAL_BUDGET
        return INTERRUPT_IDLE_TIMEOUT

    async def run(self, prompt: str) -> ExecutorResult:
        """执行一次 prompt:驱动桥进程直到 done / 防线触顶 / 进程退出。

        结果收敛规则与 ``SDKExecutor.run`` 一致:中断带 ``interrupted=True``,
        桥侧异常收敛进 ``error``,部分结果(文本/工具记录)照常返回。
        """
        result = ExecutorResult()
        texts: list[str] = []
        final_text: str | None = None

        if not self.bridge_path.exists():
            result.is_error = True
            result.error = (
                f"pi bridge not found: {self.bridge_path} — "
                "run `npm install` under toolchain/pi/ first "
                "(see toolchain/pi/README.md)"
            )
            return result

        start = time.monotonic()
        idle_deadline = start + self.idle_timeout
        total_deadline = start + self.total_budget if self.total_budget is not None else None

        proc: Any = None
        try:
            proc = await self._spawn_bridge()
            await self._send(
                proc.stdin,
                {
                    "type": "run",
                    "prompt": prompt,
                    "tools": list(self.allowed_tools),
                    "provider": self.provider,
                    "model": self.model,
                    "maxTurns": self.max_turns,
                },
            )
            while True:
                now = time.monotonic()
                deadline = (
                    idle_deadline if total_deadline is None else min(idle_deadline, total_deadline)
                )
                remaining = deadline - now
                if remaining <= 0:
                    result.interrupted = True
                    result.interrupt_reason = self._interrupt_reason(idle_deadline, total_deadline)
                    break
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
                except TimeoutError:
                    result.interrupted = True
                    result.interrupt_reason = self._interrupt_reason(idle_deadline, total_deadline)
                    break
                if not line:
                    break  # 桥退出(EOF):按已有部分结果收敛
                try:
                    event = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue  # 非 JSON 行(桥的杂散输出)跳过,不致命

                # 每条消息重置 idle 倒计时;total 倒计时只增不减。
                idle_deadline = time.monotonic() + self.idle_timeout

                etype = event.get("type")
                if etype == "text":
                    delta = event.get("delta")
                    if isinstance(delta, str):
                        texts.append(delta)
                elif etype == "tool_request":
                    tid = str(event.get("id") or "")
                    name = str(event.get("name") or "")
                    raw_input = event.get("input")
                    tool_input = raw_input if isinstance(raw_input, dict) else {}
                    allow = await self._judge(tid, name, tool_input)
                    result.tool_calls.append(
                        ToolCallRecord(tool_use_id=tid, name=name, input=tool_input)
                    )
                    await self._send(
                        proc.stdin,
                        {"type": "verdict", "id": tid, "allow": allow},
                    )
                elif etype == "done":
                    result.usage = event.get("usage")
                    result.num_turns = int(event.get("numTurns") or 0)
                    result.is_error = bool(event.get("error"))
                    result.error = (
                        str(event["error"]) if event.get("error") is not None else None
                    )
                    final_text = event.get("text") if isinstance(event.get("text"), str) else None
                    break
        except Exception as exc:  # noqa: BLE001 — 引擎边界,异常必须收敛进结果对象
            result.is_error = True
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            if proc is not None:
                with _suppress_all():
                    proc.kill()
                with _suppress_all():
                    await proc.wait()

        result.text = "".join(texts) if texts else (final_text or "")
        return result


class _suppress_all:
    """吞掉 kill/wait 阶段的一切异常(OSError / ProcessLookupError / 无 kill 方法)."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc_info: object) -> bool:
        return True
