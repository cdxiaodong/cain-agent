"""SDKExecutor 单元测试 —— 全程 mock SDK 的 query(),不烧 token。

覆盖验收要求:默认零工具白名单、hook 注册透传、idle 超时中断路径,
另钉死 total_budget 中断、结果收敛、SDK 异常不逃逸三条引擎边界行为。
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    HookContext,
    HookInput,
    HookJSONOutput,
    HookMatcher,
    Message,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
)

from cain_agent.executor import (
    INTERRUPT_IDLE_TIMEOUT,
    INTERRUPT_TOTAL_BUDGET,
    SDKExecutor,
)


def _install_fake_query(
    monkeypatch: pytest.MonkeyPatch,
    messages: list[Message],
    *,
    hang_after: float | None = None,
    raise_error: Exception | None = None,
) -> list[ClaudeAgentOptions | None]:
    """把 cain_agent.executor.query 换成假消息流,返回捕获到的 options 列表。"""

    seen_options: list[ClaudeAgentOptions | None] = []

    async def fake_query(**kwargs: Any) -> AsyncIterator[Message]:
        seen_options.append(kwargs.get("options"))
        if raise_error is not None:
            raise raise_error
        for msg in messages:
            yield msg
        if hang_after is not None:
            await asyncio.sleep(hang_after)

    monkeypatch.setattr("cain_agent.executor.query", fake_query)
    return seen_options


def _result_message(**overrides: Any) -> ResultMessage:
    kwargs: dict[str, Any] = {
        "subtype": "success",
        "duration_ms": 1,
        "duration_api_ms": 1,
        "is_error": False,
        "num_turns": 1,
        "session_id": "sess-1",
        "total_cost_usd": 0.001,
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "result": "done",
    }
    kwargs.update(overrides)
    return ResultMessage(**kwargs)


def test_default_allowed_tools_is_empty_whitelist(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install_fake_query(monkeypatch, [_result_message()])
    result = asyncio.run(SDKExecutor().run("ping"))
    assert seen[0] is not None
    assert seen[0].allowed_tools == []
    assert result.is_error is False


def test_allowed_tools_whitelist_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install_fake_query(monkeypatch, [_result_message()])
    asyncio.run(SDKExecutor(allowed_tools=["Read", "Bash"]).run("ping"))
    assert seen[0] is not None
    assert seen[0].allowed_tools == ["Read", "Bash"]


def test_no_hooks_registered_gives_none_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install_fake_query(monkeypatch, [_result_message()])
    asyncio.run(SDKExecutor().run("ping"))
    assert seen[0] is not None
    assert seen[0].hooks is None


def test_hooks_registration_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    async def guard(
        input_data: HookInput, tool_use_id: str | None, context: HookContext
    ) -> HookJSONOutput:
        return {}

    async def audit(
        input_data: HookInput, tool_use_id: str | None, context: HookContext
    ) -> HookJSONOutput:
        return {}

    executor = SDKExecutor(hooks={"PreToolUse": [HookMatcher(matcher="Bash", hooks=[guard])]})
    executor.add_pre_tool_use_hook(audit)  # ScopeGuardHook 挂载点

    seen = _install_fake_query(monkeypatch, [_result_message()])
    asyncio.run(executor.run("ping"))

    assert seen[0] is not None
    matchers = seen[0].hooks["PreToolUse"]  # type: ignore[index]
    assert len(matchers) == 2
    assert matchers[0].matcher == "Bash"
    assert matchers[0].hooks == [guard]
    assert matchers[1].matcher is None
    assert matchers[1].hooks == [audit]


def test_resume_session_id_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install_fake_query(monkeypatch, [_result_message()])
    asyncio.run(SDKExecutor(resume_session_id="sess-42").run("ping"))
    assert seen[0] is not None
    assert seen[0].resume == "sess-42"


def test_run_collects_text_tool_calls_and_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    messages: list[Message] = [
        AssistantMessage(
            content=[
                TextBlock(text="先看一下 "),
                ToolUseBlock(id="tu-1", name="Read", input={"file_path": "/tmp/a"}),
                TextBlock(text="目标主机"),
            ],
            model="mock-model",
        ),
        _result_message(),
    ]
    _install_fake_query(monkeypatch, messages)

    result = asyncio.run(SDKExecutor().run("recon"))

    assert result.text == "先看一下 目标主机"
    assert result.tool_calls[0].name == "Read"
    assert result.tool_calls[0].tool_use_id == "tu-1"
    assert result.tool_calls[0].input == {"file_path": "/tmp/a"}
    assert result.usage == {"input_tokens": 10, "output_tokens": 5}
    assert result.total_cost_usd == 0.001
    assert result.session_id == "sess-1"
    assert result.num_turns == 1
    assert result.interrupted is False
    assert result.interrupt_reason is None


def test_idle_timeout_interrupts_and_returns_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    messages: list[Message] = [
        AssistantMessage(content=[TextBlock(text="partial-output")], model="mock-model"),
    ]
    # 流给出一条消息后就再也不出声 —— 模拟 agent 卡死
    _install_fake_query(monkeypatch, messages, hang_after=60.0)

    result = asyncio.run(SDKExecutor(idle_timeout=0.05).run("hang"))

    assert result.interrupted is True
    assert result.interrupt_reason == INTERRUPT_IDLE_TIMEOUT
    assert result.text == "partial-output"  # 部分结果不丢


def test_total_budget_interrupts_before_idle(monkeypatch: pytest.MonkeyPatch) -> None:
    # idle 给足 60s,总预算只给 0.05s —— 必须先触顶 total_budget
    _install_fake_query(monkeypatch, [], hang_after=60.0)

    result = asyncio.run(SDKExecutor(idle_timeout=60.0, total_budget=0.05).run("burn"))

    assert result.interrupted is True
    assert result.interrupt_reason == INTERRUPT_TOTAL_BUDGET


def test_sdk_error_is_captured_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_query(monkeypatch, [], raise_error=RuntimeError("boom"))

    result = asyncio.run(SDKExecutor().run("explode"))

    assert result.is_error is True
    assert result.error is not None and "RuntimeError" in result.error
    assert "boom" in result.error


def test_invalid_timeouts_rejected() -> None:
    with pytest.raises(ValueError):
        SDKExecutor(idle_timeout=0)
    with pytest.raises(ValueError):
        SDKExecutor(total_budget=-1)
