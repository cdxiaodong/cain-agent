"""PiExecutor 测试 — 第二执行引擎的协议收敛、scope 复用、双防线与 CLI 开关。

全部用 fake 子进程驱动(注入 ``_spawn_bridge``),零 Node / 零网络 / 零 token;
桥脚本本身(toolchain/pi/bridge.mjs)是外部运行时代码,协议契约在这里钉死。
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from cain_agent.cli import _build_executor, _build_validation_executor, build_parser
from cain_agent.executor import INTERRUPT_IDLE_TIMEOUT, ExecutorResult
from cain_agent.pi_executor import PiExecutor, _decision_denies, _matcher_hits
from cain_agent.scope import Scope, ScopeGuardHook

BRIDGE = Path(__file__).resolve().parent.parent / "toolchain" / "pi" / "bridge.mjs"


# ---------------------------------------------------------------------------
# fakes


class FakeStdin:
    def __init__(self) -> None:
        self.written: list[dict[str, Any]] = []

    def write(self, data: bytes) -> None:
        text = data.decode("utf-8").strip()
        if text:
            self.written.append(json.loads(text))

    async def drain(self) -> None:
        return None


class FakeStdout:
    """Pre-scripted JSON lines; optional per-line delay to exercise timeouts."""

    def __init__(self, lines: list[dict[str, Any]], delay: float = 0.0) -> None:
        self._lines = [  # type: ignore[var-annotated]
            (json.dumps(line, ensure_ascii=False) + "\n").encode("utf-8") for line in lines
        ]
        self._delay = delay

    async def readline(self) -> bytes:
        if self._delay:
            await asyncio.sleep(self._delay)
        if not self._lines:
            return b""  # EOF
        return self._lines.pop(0)


class FakeProcess:
    def __init__(self, lines: list[dict[str, Any]], delay: float = 0.0) -> None:
        self.stdin = FakeStdin()
        self.stdout = FakeStdout(lines, delay=delay)
        self.killed = False

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return 0


def make_executor(
    lines: list[dict[str, Any]], *, delay: float = 0.0, **kw: Any
) -> tuple[PiExecutor, FakeProcess]:
    proc = FakeProcess(lines, delay=delay)
    ex = PiExecutor(bridge_path=BRIDGE, **kw)

    async def _spawn() -> FakeProcess:
        return proc

    ex._spawn_bridge = _spawn  # type: ignore[method-assign]
    return ex, proc


def run_sync(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# unit: helpers


def test_decision_denies_semantics() -> None:
    assert _decision_denies({}) is False
    assert (
        _decision_denies(
            {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}}
        )
        is True
    )
    assert (
        _decision_denies({"hookSpecificOutput": {"permissionDecision": "allow"}}) is False
    )
    assert _decision_denies({"something": "unrecognized"}) is True  # 保守:无法识别即拒


def test_matcher_hits() -> None:
    assert _matcher_hits(None, "Bash") is True
    assert _matcher_hits("Bash", "Bash") is True
    assert _matcher_hits("Bash", "Read") is False
    assert _matcher_hits("Write|Edit", "Edit") is True


def test_pi_build_options_snapshot() -> None:
    ex = PiExecutor(provider="deepseek", model="deepseek-chat", allowed_tools=["Bash"])
    snap = ex.build_options()
    assert snap["backend"] == "pi"
    assert snap["provider"] == "deepseek"
    assert snap["model"] == "deepseek-chat"
    assert snap["allowed_tools"] == ["Bash"]


def test_pi_constructor_validation() -> None:
    with pytest.raises(ValueError):
        PiExecutor(idle_timeout=0)
    with pytest.raises(ValueError):
        PiExecutor(total_budget=-1)


# ---------------------------------------------------------------------------
# protocol: run / done 收敛


def test_pi_run_converges_done() -> None:
    lines = [
        {"type": "text", "delta": "recon "},
        {"type": "text", "delta": "done"},
        {
            "type": "done",
            "text": "recon done",
            "usage": {"input": 10, "output": 5},
            "numTurns": 3,
            "error": None,
        },
    ]
    ex, proc = make_executor(lines)
    result = run_sync(ex.run("scan target"))
    assert isinstance(result, ExecutorResult)
    assert result.text == "recon done"
    assert result.usage == {"input": 10, "output": 5}
    assert result.num_turns == 3
    assert result.is_error is False
    assert proc.killed is True  # finally 清理
    init = proc.stdin.written[0]
    assert init["type"] == "run"
    assert init["prompt"] == "scan target"


def test_pi_run_uses_streamed_text_when_no_final() -> None:
    lines = [
        {"type": "text", "delta": "partial "},
        {"type": "text", "delta": "output"},
        {"type": "done", "text": "", "usage": None, "numTurns": 1, "error": None},
    ]
    ex, _ = make_executor(lines)
    result = run_sync(ex.run("p"))
    assert result.text == "partial output"


def test_pi_run_bridge_error_converged() -> None:
    lines = [{"type": "done", "text": "", "usage": None, "numTurns": 0, "error": "boom"}]
    ex, _ = make_executor(lines)
    result = run_sync(ex.run("p"))
    assert result.is_error is True
    assert result.error == "boom"


def test_pi_run_eof_returns_partial() -> None:
    lines = [{"type": "text", "delta": "half"}]  # 无 done,直接 EOF
    ex, _ = make_executor(lines)
    result = run_sync(ex.run("p"))
    assert result.is_error is False
    assert result.text == "half"


# ---------------------------------------------------------------------------
# scope 复用:ScopeGuardHook 原样挂载


def _scoped_executor(lines: list[dict[str, Any]]) -> tuple[PiExecutor, FakeProcess]:
    ex, proc = make_executor(lines, allowed_tools=["Bash"])
    ex.add_pre_tool_use_hook(
        ScopeGuardHook(Scope(in_scope=["example.com"], out_of_scope=[])), matcher="Bash"
    )
    return ex, proc


def test_pi_tool_request_in_scope_allowed() -> None:
    lines = [
        {
            "type": "tool_request",
            "id": "t1",
            "name": "Bash",
            "input": {"command": "curl -s https://example.com/api"},
        },
        {"type": "done", "text": "ok", "usage": None, "numTurns": 1, "error": None},
    ]
    ex, proc = _scoped_executor(lines)
    result = run_sync(ex.run("p"))
    verdicts = [w for w in proc.stdin.written if w.get("type") == "verdict"]
    assert verdicts == [{"type": "verdict", "id": "t1", "allow": True}]
    assert [c.name for c in result.tool_calls] == ["Bash"]
    assert result.tool_calls[0].input == {"command": "curl -s https://example.com/api"}


def test_pi_tool_request_out_of_scope_denied() -> None:
    lines = [
        {
            "type": "tool_request",
            "id": "t2",
            "name": "Bash",
            "input": {"command": "curl -s https://evil.com/x"},
        },
        {"type": "done", "text": "", "usage": None, "numTurns": 1, "error": None},
    ]
    ex, proc = _scoped_executor(lines)
    run_sync(ex.run("p"))
    verdicts = [w for w in proc.stdin.written if w.get("type") == "verdict"]
    assert verdicts[0]["allow"] is False


def test_pi_deny_records_tool_call() -> None:
    lines = [
        {
            "type": "tool_request",
            "id": "t3",
            "name": "Bash",
            "input": {"command": "curl -s https://evil.com/x"},
        },
        {"type": "done", "text": "", "usage": None, "numTurns": 1, "error": None},
    ]
    ex, proc = _scoped_executor(lines)
    result = run_sync(ex.run("p"))
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].tool_use_id == "t3"


def test_pi_matcher_skips_non_matching_tool() -> None:
    lines = [
        {"type": "tool_request", "id": "t4", "name": "Read", "input": {"path": "/etc/passwd"}},
        {"type": "done", "text": "", "usage": None, "numTurns": 1, "error": None},
    ]
    ex, proc = make_executor(lines, allowed_tools=["Read"])
    ex.add_pre_tool_use_hook(
        ScopeGuardHook(Scope(in_scope=["example.com"], out_of_scope=[])), matcher="Bash"
    )
    run_sync(ex.run("p"))
    verdicts = [w for w in proc.stdin.written if w.get("type") == "verdict"]
    # Read 不匹配 matcher → 没有任何 hook 拒绝 → allow
    assert verdicts[0]["allow"] is True


@pytest.mark.parametrize("tool_name", ["Read", "Grep", "Glob"])
def test_pi_readonly_tools_run_through_python_verdict(tool_name: str) -> None:
    lines = [
        {"type": "tool_request", "id": "ro1", "name": tool_name, "input": {"path": "."}},
        {"type": "done", "text": "", "usage": None, "numTurns": 1, "error": None},
    ]
    ex, proc = make_executor(lines, allowed_tools=[tool_name])
    ex.add_pre_tool_use_hook(
        ScopeGuardHook(Scope(in_scope=["example.com"], out_of_scope=[])),
        matcher="Read|Grep|Glob",
    )
    run_sync(ex.run("p"))
    assert {"type": "verdict", "id": "ro1", "allow": True} in proc.stdin.written


def test_pi_tool_request_outside_allowed_tools_is_denied() -> None:
    lines = [
        {"type": "tool_request", "id": "t5", "name": "Read", "input": {"file_path": "x"}},
        {"type": "done", "text": "", "usage": None, "numTurns": 1, "error": None},
    ]
    ex, proc = make_executor(lines, allowed_tools=["Bash"])
    run_sync(ex.run("p"))
    assert {"type": "verdict", "id": "t5", "allow": False} in proc.stdin.written


def test_pi_bridge_registers_full_readonly_tool_surface() -> None:
    source = BRIDGE.read_text(encoding="utf-8")
    for tool_name in ("Bash", "Read", "Grep", "Glob"):
        assert f'{tool_name}:' in source
    assert ".map((name) => withPythonVerdict(toolFactories[name]()))" in source


# ---------------------------------------------------------------------------
# 双防线


def test_pi_idle_timeout_interrupts() -> None:
    lines = [{"type": "text", "delta": "x"}]
    ex, proc = make_executor(lines, delay=0.2, idle_timeout=0.05)
    result = run_sync(ex.run("p"))
    assert result.interrupted is True
    assert result.interrupt_reason == INTERRUPT_IDLE_TIMEOUT
    assert proc.killed is True


def test_pi_total_budget_interrupts() -> None:
    lines = [{"type": "text", "delta": "x"}]
    ex, _ = make_executor(lines, delay=0.2, idle_timeout=30.0, total_budget=0.05)
    result = run_sync(ex.run("p"))
    assert result.interrupted is True
    assert result.interrupt_reason == "total_budget"


# ---------------------------------------------------------------------------
# 桥缺失防护


def test_pi_bridge_missing_returns_error(tmp_path: Path) -> None:
    ex = PiExecutor(bridge_path=tmp_path / "nope.mjs")
    result = run_sync(ex.run("p"))
    assert result.is_error is True
    assert "npm install" in (result.error or "")


# ---------------------------------------------------------------------------
# CLI 开关


def test_cli_backend_flags_parse() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["run", "--target", "example.com", "--backend", "pi", "--pi-provider", "deepseek", "--pi-model", "m1"]
    )
    assert args.backend == "pi"
    assert args.pi_provider == "deepseek"
    assert args.pi_model == "m1"
    default = parser.parse_args(["run", "--target", "example.com"])
    assert default.backend == "claude"
    assert default.pi_provider == "anthropic"
    assert default.pi_model is None


def test_cli_build_executor_selects_backend() -> None:
    parser = build_parser()
    pi_args = parser.parse_args(
        [
            "run",
            "--target",
            "example.com",
            "--backend",
            "pi",
            "--pi-provider",
            "openai",
            "--pi-model",
            "gpt-x",
        ]
    )
    ex = _build_executor(pi_args)
    assert isinstance(ex, PiExecutor)
    assert ex.provider == "openai"
    assert ex.model == "gpt-x"
    assert ex.allowed_tools == ["Bash", "Read", "Grep", "Glob"]

    claude_args = parser.parse_args(["run", "--target", "example.com"])
    from cain_agent.executor import SDKExecutor

    assert isinstance(_build_executor(claude_args), SDKExecutor)


def test_cli_validation_executor_pi_stays_zero_tools() -> None:
    parser = build_parser()
    pi_args = parser.parse_args(["run", "--target", "example.com", "--backend", "pi"])
    v = _build_validation_executor(pi_args)
    assert isinstance(v, PiExecutor)
    assert v.allowed_tools == []  # 只读校验通道:零工具
    assert v is not _build_executor(pi_args)  # 独立会话对象


def test_cli_dry_run_prints_backend(capsys: Any) -> None:
    from cain_agent.cli import cmd_run

    parser = build_parser()
    args = parser.parse_args(
        ["run", "--target", "example.com", "--backend", "pi", "--pi-provider", "deepseek", "--dry-run"]
    )
    rc = cmd_run(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "后端:     pi" in out
    assert "deepseek/默认" in out
