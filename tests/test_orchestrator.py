"""Orchestrator 单元测试 —— 全 mock:fake StageHandler + 真 executor 壳(不触网)。

覆盖派活单自测要求:
- 阶段顺序不可逆(乱序抛错钉死);
- state.json 可追溯(当前阶段 / 已完成列表 / 时间戳 / 产物清单);
- ScopeGuardHook 挂载透传到 executor(PreToolUse 钩子数 + 回调本体);
- 默认 placeholder handler 落盘占位产物;
- 未知 handler 阶段名拒绝。
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import pytest
from claude_agent_sdk.types import HookCallback, HookJSONOutput, PreToolUseHookInput

from cain_agent.executor import SDKExecutor
from cain_agent.orchestrator import (
    STAGES,
    Orchestrator,
    StageContext,
    StageHandler,
    StageOrderError,
    StageResult,
)
from cain_agent.workspace import Workspace


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "scope.yaml").write_text(
        "in_scope:\n  - example.com\nout_of_scope: []\n", encoding="utf-8"
    )
    return Workspace(root)


def _recording_handler(calls: list[str], marker: str) -> StageHandler:
    """fake handler:记录自己被调用的阶段名,并在阶段目录落一个 marker 文件。"""

    def handler(ctx: StageContext) -> StageResult:
        calls.append(ctx.stage)
        path = ctx.artifacts_dir / f"{ctx.stage}-{marker}.json"
        path.write_text(json.dumps({"stage": ctx.stage}), encoding="utf-8")
        return StageResult(
            summary=f"{ctx.stage} done",
            artifacts=[path.relative_to(ctx.workspace.root).as_posix()],
        )

    return handler


def test_hook_mounted_onto_executor(ws: Workspace) -> None:
    executor = SDKExecutor()
    orch = Orchestrator(executor, ws)
    matchers = executor.hooks.get("PreToolUse", [])
    assert len(matchers) == 1, "ScopeGuardHook 应被挂到 executor 的 PreToolUse"
    assert orch.guard_hook in matchers[0].hooks


def _pre_tool_use_input(tool_name: str, tool_input: dict[str, Any]) -> PreToolUseHookInput:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "test-session",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/tmp",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "toolu_test",
    }


def _call_hook(hook: HookCallback, input_data: PreToolUseHookInput) -> dict[str, Any]:
    async def call() -> HookJSONOutput:
        return await hook(input_data, None, {"signal": None})

    return cast(dict[str, Any], asyncio.run(call()))


def test_mounted_hook_actually_blocks_out_of_scope(ws: Workspace) -> None:
    """透传不只看注册表:跑一次 hook 本体,验证从 workspace scope 构造的拦截生效。"""
    executor = SDKExecutor()
    orch = Orchestrator(executor, ws)
    hook = executor.hooks["PreToolUse"][0].hooks[0]
    deny = _call_hook(
        hook, _pre_tool_use_input("Bash", {"command": "curl https://evil.com"})
    )
    assert deny["hookSpecificOutput"]["permissionDecision"] == "deny"
    allow = _call_hook(
        hook, _pre_tool_use_input("Bash", {"command": "curl https://a.example.com"})
    )
    assert allow == {}
    assert orch.scope_guard.scope.is_allowed("example.com")


def test_run_executes_stages_in_hardcoded_order(ws: Workspace) -> None:
    calls: list[str] = []
    orch = Orchestrator(SDKExecutor(), ws, handlers={
        stage: _recording_handler(calls, "x") for stage in STAGES
    })
    final = orch.run()
    assert calls == ["recon", "test", "report"]
    assert final["completed_stages"] == ["recon", "test", "report"]
    assert final["current_stage"] == "report"


def test_stage_out_of_order_raises(ws: Workspace) -> None:
    orch = Orchestrator(SDKExecutor(), ws)
    with pytest.raises(StageOrderError, match="下一个应为 'recon'"):
        orch.run_stage("test")


def test_stage_replay_raises(ws: Workspace) -> None:
    orch = Orchestrator(SDKExecutor(), ws)
    orch.run_stage("recon")
    with pytest.raises(StageOrderError, match="不允许重复执行"):
        orch.run_stage("recon")


def test_unknown_stage_raises(ws: Workspace) -> None:
    orch = Orchestrator(SDKExecutor(), ws)
    with pytest.raises(StageOrderError, match="未知阶段"):
        orch.run_stage("exfil")


def test_state_json_traceable(ws: Workspace) -> None:
    orch = Orchestrator(SDKExecutor(), ws)
    orch.run_stage("recon")
    state = json.loads((ws.root / "state.json").read_text(encoding="utf-8"))
    assert state["current_stage"] == "recon"
    assert state["completed_stages"] == ["recon"]
    assert "updated_at" in state
    entry = state["history"][0]
    assert entry["stage"] == "recon"
    assert entry["started_at"] and entry["finished_at"]
    assert entry["artifacts"] == ["recon/recon-placeholder.json"]


def test_state_persists_across_orchestrator_instances(ws: Workspace) -> None:
    """状态写盘即真源:换个 Orchestrator 实例,顺序纪律仍然生效。"""
    Orchestrator(SDKExecutor(), ws).run_stage("recon")
    orch2 = Orchestrator(SDKExecutor(), ws)
    with pytest.raises(StageOrderError):
        orch2.run_stage("report")
    result = orch2.run_stage("test")
    assert result.summary == "test 阶段占位产物"
    assert orch2.load_state()["completed_stages"] == ["recon", "test"]


def test_placeholder_handler_writes_artifact(ws: Workspace) -> None:
    orch = Orchestrator(SDKExecutor(), ws)
    result = orch.run_stage("recon")
    artifact = ws.root / result.artifacts[0]
    assert artifact.exists()
    assert json.loads(artifact.read_text(encoding="utf-8"))["stage"] == "recon"


def test_handler_with_unknown_stage_rejected(ws: Workspace) -> None:
    with pytest.raises(ValueError, match="未知阶段"):
        Orchestrator(SDKExecutor(), ws, handlers={"exfil": lambda ctx: StageResult()})


def test_artifacts_landed_in_stage_dirs(ws: Workspace) -> None:
    orch = Orchestrator(SDKExecutor(), ws)
    orch.run()
    for stage in STAGES:
        assert (ws.root / stage / f"{stage}-placeholder.json").exists()
