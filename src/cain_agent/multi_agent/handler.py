"""MultiAgentHandler —— 桥接层：将 Multi-Agent 系统注入现有 Orchestrator 状态机

设计原则（只做桥接，不变语义）：
- 现有 Orchestrator 的 StageHandler 协议不变
- MultiAgentHandler 实现 StageHandler，内部驱动 PentestManager + Solvers + Observer
- 每个阶段创建对应 Solver 任务，经 Manager 分发执行
- ToolExecutor 挂载到 Solvers，提供真实工具能力
- Observer 旁路审计每个结果

桥梁两端：
  Orchestrator.run_stage("recon") → MultiAgentHandler.__call__ → PentestManager.dispatch()
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cain_agent.multi_agent.types import SolverResult, SolverTask
from cain_agent.orchestrator import StageContext, StageHandler, StageResult

if TYPE_CHECKING:
    from cain_agent.multi_agent.blackboard import Blackboard
    from cain_agent.multi_agent.manager import PentestManager
    from cain_agent.multi_agent.observer import SafetyObserver
    from cain_agent.toolchain.executor import ToolExecutor
    from cain_agent.workspace import Workspace


@dataclass
class StagePlan:
    """每个阶段的执行计划：告诉 Manager 该派出哪些 Solver。"""

    tasks: list[SolverTask]
    """待分发的任务列表（目标从 scope 读取，策略由阶段决定）。"""


class MultiAgentHandler:
    """Multi-Agent 阶段处理器：实现 StageHandler，内部驱动 Agent 协作。

    每个阶段实例化一个 handler，内部持有 Manager/Observer/Blackboard 引用。
    """

    def __init__(
        self,
        stage: str,
        manager: PentestManager,
        blackboard: Blackboard,
        observer: SafetyObserver,
        tool_executor: ToolExecutor | None = None,
    ) -> None:
        self.stage = stage
        self.manager = manager
        self.blackboard = blackboard
        self.observer = observer
        self.tool_executor = tool_executor

    def __call__(self, ctx: StageContext) -> StageResult:
        """实现 StageHandler 协议：生成计划 → 分发 → 收集 → 审计 → 落盘。"""
        plan = self._build_plan(ctx)
        results = self.manager.dispatch(plan.tasks)

        # Observer 旁路审计每个结果
        advices = []
        for r in results:
            advices.extend(self.observer.audit_result(r))

        # 产物落盘到阶段目录
        artifacts = self._save_artifacts(ctx, results, advices)

        # 持久化黑板状态
        self._persist(ctx)

        return StageResult(
            summary=self._build_summary(results, advices),
            artifacts=artifacts,
            data={
                "tasks_total": len(plan.tasks),
                "tasks_completed": sum(1 for r in results if r.success),
                "findings_total": len(self.blackboard.read_findings()),
                "findings_confirmed": len(self.blackboard.read_confirmed_findings()),
                "observer_warnings": self.observer.get_advice_summary(),
            },
        )

    # -- 阶段计划 ----------------------------------------------------------------

    def _build_plan(self, ctx: StageContext) -> StagePlan:
        """根据阶段生成执行计划。"""
        if self.stage == "recon":
            return self._recon_plan(ctx)
        if self.stage == "test":
            return self._test_plan(ctx)
        if self.stage == "report":
            return self._report_plan(ctx)
        # 未知阶段：空计划（不应到达，Orchestrator 已校验）
        return StagePlan(tasks=[])

    def _recon_plan(self, ctx: StageContext) -> StagePlan:
        """侦察阶段：信息收集 → 子域名枚举 → 存活探测 → 指纹识别。"""
        ws = ctx.workspace
        try:
            scope = ws.scope
            targets = scope.in_plain + [
                f"*.{base}" for base in scope.in_wild
            ]
        except Exception:
            targets = []

        tasks = [
            SolverTask(
                objective="子域名枚举与资产发现",
                scope=targets,
                constraints=["readonly"],
                context={
                    "capability": "recon",
                    "tools": ["subfinder", "assetfinder", "httpx"],
                    "stage": "recon",
                },
            ),
        ]

        # 如果有 IP 范围，追加端口扫描任务
        ip_targets = [str(n) for n in scope.in_nets] if targets else []
        if ip_targets:
            tasks.append(SolverTask(
                objective="端口扫描与服务识别",
                scope=ip_targets,
                constraints=["readonly"],
                context={
                    "capability": "recon",
                    "tools": ["nmap", "rustscan"],
                    "stage": "recon",
                },
            ))

        return StagePlan(tasks=tasks)

    def _test_plan(self, ctx: StageContext) -> StagePlan:
        """测试阶段：基于黑板的 Idea 进行只读漏洞验证。"""
        open_ideas = self.blackboard.read_open_ideas(min_priority=5)

        if not open_ideas:
            # 无 Idea 时扫描已知资产
            tasks = [
                SolverTask(
                    objective="漏洞扫描（基于已发现资产）",
                    scope=[],
                    constraints=["readonly"],
                    context={
                        "capability": "exploit",
                        "tools": ["nuclei"],
                        "stage": "test",
                    },
                ),
            ]
        else:
            tasks = [
                SolverTask(
                    objective=idea.hypothesis,
                    scope=idea.plan,
                    constraints=["readonly"],
                    context={
                        "capability": "exploit",
                        "parent_idea_id": idea.idea_id,
                        "stage": "test",
                    },
                )
                for idea in open_ideas[:10]  # 每轮最多验证 10 个 Idea
            ]

        return StagePlan(tasks=tasks)

    def _report_plan(self, ctx: StageContext) -> StagePlan:
        """报告阶段：汇总确认的 Finding 生成证据链报告。"""
        confirmed = self.blackboard.read_confirmed_findings()
        return StagePlan(tasks=[
            SolverTask(
                objective=f"生成渗透测试报告（{len(confirmed)} 个已确认发现）",
                scope=[],
                constraints=["readonly"],
                context={
                    "capability": "report",
                    "finding_ids": [f.finding_id for f in confirmed],
                    "stage": "report",
                },
            ),
        ])

    # -- 产物保存 ----------------------------------------------------------------

    def _save_artifacts(
        self,
        ctx: StageContext,
        results: list[SolverResult],
        advices: list,
    ) -> list[str]:
        """阶段结果落盘到 artifacts 目录。"""
        import json

        artifacts: list[str] = []
        stage_dir = ctx.artifacts_dir

        # 保存任务结果
        results_path = stage_dir / f"{self.stage}-results.json"
        results_path.write_text(
            json.dumps(
                [{
                    "task_id": r.task_id,
                    "solver_id": r.solver_id,
                    "success": r.success,
                    "output": r.output[:500] if r.output else "",
                    "error": r.error,
                    "duration": round(r.duration, 2),
                    "findings_count": len(r.findings),
                    "ideas_count": len(r.ideas),
                } for r in results],
                ensure_ascii=False,
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        artifacts.append(results_path.relative_to(ctx.workspace.root).as_posix())

        # 保存 Observer 纠偏建议
        if advices:
            advices_path = stage_dir / f"{self.stage}-advices.json"
            advices_path.write_text(
                json.dumps(
                    [{
                        "solver_id": a.solver_id,
                        "issue": a.issue,
                        "suggestion": a.suggestion,
                        "severity": a.severity,
                        "should_block": a.should_block,
                    } for a in advices],
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
            artifacts.append(advices_path.relative_to(ctx.workspace.root).as_posix())

        # 如果是 report 阶段，保存报告文件
        if self.stage == "report":
            report_path = stage_dir / "report.md"
            report_lines = ["# 渗透测试报告", ""]
            for r in results:
                if r.output:
                    report_lines.append(r.output)
            if len(report_lines) == 2:
                report_lines.append("_无已确认的漏洞发现_")
            report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
            artifacts.append(report_path.relative_to(ctx.workspace.root).as_posix())

        return artifacts

    def _persist(self, ctx: StageContext) -> None:
        """持久化黑板状态到 Workspace。"""
        from cain_agent.workspace_ext import WorkspaceWithBoard

        if isinstance(ctx.workspace, WorkspaceWithBoard):
            ctx.workspace.save_blackboard()

    def _build_summary(
        self,
        results: list[SolverResult],
        advices: list,
    ) -> str:
        """构建阶段执行摘要。"""
        total = len(results)
        ok = sum(1 for r in results if r.success)
        findings = sum(len(r.findings) for r in results)
        ideas = sum(len(r.ideas) for r in results)
        warnings = sum(
            1 for a in advices
            if getattr(a, "severity", "info") in ("warning", "critical")
        )

        parts = [
            f"{self.stage} 阶段完成: {ok}/{total} 任务成功",
            f"产出 {findings} 个发现, {ideas} 个新方向",
        ]
        if warnings:
            parts.append(f"Observer: {warnings} 条警告")

        return " | ".join(parts)


# -- 工厂函数 ----------------------------------------------------------------

def create_multi_agent_handlers(
    workspace: Workspace,
    manager: PentestManager,
    blackboard: Blackboard,
    observer: SafetyObserver,
    tool_executor: ToolExecutor | None = None,
) -> dict[str, StageHandler]:
    """创建三阶段的 Multi-Agent handler 字典。

    直接注入 Orchestrator(handlers=...)，零侵入替换 placeholder_handler。
    """
    return {
        stage: MultiAgentHandler(
            stage=stage,
            manager=manager,
            blackboard=blackboard,
            observer=observer,
            tool_executor=tool_executor,
        )
        for stage in ("recon", "test", "report")
    }
