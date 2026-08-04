"""Orchestrator —— 确定性 Python 状态机(DESIGN.md §2 中枢件)。

阶段流转硬编码 ``recon → test → report``,不接受外部传入阶段序列:
用确定性工程框住自由度,战略/战术交给 LLM,流转纪律交给代码。

职责:
- 把已合入的 ``SDKExecutor`` 与 ``ScopeGuardHook`` 组装成最小闭环:
  构造时从 workspace 的 scope.yaml 建 ``ScopeGuardHook``,经
  ``add_pre_tool_use_hook`` 挂到 executor 上(只组合,不改 hook 语义)。
- 每阶段调用一个注入的 ``StageHandler``(输入 Workspace,输出阶段产物),
  产物落盘到对应阶段子目录;本期默认 handler 仅写占位产物。
- 每阶段结束写 ``state.json``(当前阶段、已完成列表、时间戳),状态可追溯;
  断点续跑本期不实现,但阶段乱序(跳阶段)会被状态机直接抛错拒绝。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from claude_agent_sdk.types import HookContext, HookInput, HookJSONOutput

from cain_agent.executor import SDKExecutor
from cain_agent.scope import ScopeGuardHook
from cain_agent.workspace import STATE_FILE, Workspace

__all__ = [
    "STAGES",
    "Orchestrator",
    "StageContext",
    "StageHandler",
    "StageOrderError",
    "StageResult",
    "placeholder_handler",
]

STAGES = ("recon", "test", "report")
"""硬编码阶段序列:侦察 → 测试 → 报告。不接受外部重排。"""


class StageOrderError(RuntimeError):
    """阶段乱序(跳阶段 / 重复跑已完成阶段)时抛出。"""


@dataclass
class StageContext:
    """传给 StageHandler 的上下文:Workspace 真源 + 阶段名 + 产物目录。"""

    workspace: Workspace
    stage: str
    artifacts_dir: Path


@dataclass
class StageResult:
    """StageHandler 的结构化产出。

    ``artifacts`` 记录本阶段落盘的产物文件(相对工作区根的路径),
    会被原样记进 state.json,供断点追溯与报告阶段引用。
    """

    summary: str = ""
    artifacts: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


class StageHandler(Protocol):
    """阶段处理器协议:可调用对象,输入 StageContext,输出 StageResult。

    由调用方注入(后续 recon/test 技能全部以这个形态挂上来);
    本期不提供任何真实侦察/测试逻辑。
    """

    def __call__(self, ctx: StageContext) -> StageResult: ...


def placeholder_handler(ctx: StageContext) -> StageResult:
    """默认占位 handler:在阶段目录写一个占位 JSON,不产生任何真实测试行为。"""
    path = ctx.artifacts_dir / f"{ctx.stage}-placeholder.json"
    payload = {"stage": ctx.stage, "note": "placeholder — 真实技能尚未接入"}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return StageResult(
        summary=f"{ctx.stage} 阶段占位产物",
        artifacts=[path.relative_to(ctx.workspace.root).as_posix()],
    )


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Orchestrator:
    """确定性编排状态机:硬编码 recon → test → report,逐阶段驱动 handler。

    参数:
        executor: 已构造的 ``SDKExecutor``;ScopeGuardHook 会挂到它上面。
        workspace: 外置记忆真源;scope.yaml 在此加载。
        handlers: 可选,阶段名 → handler 映射;缺省阶段用 ``placeholder_handler``。
    """

    def __init__(
        self,
        executor: SDKExecutor,
        workspace: Workspace,
        handlers: dict[str, StageHandler] | None = None,
    ) -> None:
        self.executor = executor
        self.workspace = workspace
        unknown = set(handlers or {}) - set(STAGES)
        if unknown:
            raise ValueError(f"handler 挂到了未知阶段: {sorted(unknown)}(合法值: {list(STAGES)})")
        self.handlers: dict[str, StageHandler] = {stage: placeholder_handler for stage in STAGES}
        self.handlers.update(handlers or {})

        # 集成点:从 workspace 真源建 ScopeGuardHook,硬拦截挂到 executor。
        # 只组合已验收的两件,不改变 ScopeGuardHook 的任何语义;
        # 外层仅是一层对齐 SDK HookCallback 签名的薄类型适配。
        self.scope_guard = ScopeGuardHook(workspace.scope)

        async def _guard_callback(
            input_data: HookInput, tool_use_id: str | None, context: HookContext
        ) -> HookJSONOutput:
            return cast(HookJSONOutput, await self.scope_guard(input_data, tool_use_id, context))

        self.guard_hook = _guard_callback
        self.executor.add_pre_tool_use_hook(self.guard_hook)

    # -- 状态读写 ----------------------------------------------------------------
    def load_state(self) -> dict[str, Any]:
        """读取 state.json;不存在返回初始态(未开始)。"""
        path = self.workspace.path(STATE_FILE)
        if not path.exists():
            return {"current_stage": None, "completed_stages": [], "history": []}
        state: dict[str, Any] = self.workspace.read_json(STATE_FILE)
        return state

    def _save_state(self, state: dict[str, Any]) -> None:
        self.workspace.write_json(STATE_FILE, state)

    # -- 阶段流转 ----------------------------------------------------------------
    def _check_order(self, stage: str, completed: list[str]) -> None:
        """流转纪律:只允许跑「下一个该跑的阶段」,跳阶段/重复一律抛错。"""
        if stage not in STAGES:
            raise StageOrderError(f"未知阶段: {stage!r}(合法值: {list(STAGES)})")
        if stage in completed:
            raise StageOrderError(f"阶段 {stage!r} 已完成,不允许重复执行")
        expected = STAGES[len(completed)]
        if stage != expected:
            raise StageOrderError(
                f"阶段乱序: 已完成 {completed},下一个应为 {expected!r},不能跳到 {stage!r}"
            )

    def run_stage(self, stage: str) -> StageResult:
        """执行单个阶段(带顺序校验);成功后更新 state.json。"""
        state = self.load_state()
        completed: list[str] = list(state["completed_stages"])
        self._check_order(stage, completed)

        ctx = StageContext(
            workspace=self.workspace,
            stage=stage,
            artifacts_dir=self.workspace.stage_dir(stage),
        )
        started_at = _utc_now_iso()
        result = self.handlers[stage](ctx)
        finished_at = _utc_now_iso()

        completed.append(stage)
        history: list[dict[str, Any]] = list(state.get("history", []))
        history.append({
            "stage": stage,
            "started_at": started_at,
            "finished_at": finished_at,
            "summary": result.summary,
            "artifacts": result.artifacts,
        })
        self._save_state({
            "current_stage": stage,
            "completed_stages": completed,
            "updated_at": finished_at,
            "history": history,
        })
        return result

    def run(self) -> dict[str, Any]:
        """顺序跑完全部阶段,返回最终 state。"""
        for stage in STAGES:
            self.run_stage(stage)
        return self.load_state()
