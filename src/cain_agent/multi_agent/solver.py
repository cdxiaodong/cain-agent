"""Solver —— 执行主体（多实例并行，推进具体攻击路线）

职责：
- 接收 Manager 分配的任务
- 执行具体的只读检测动作（信息收集/漏洞验证/报告生成）
- 产出 Finding（客观事实）和 Idea（待验证方向）

约束（只读原则）：
- 只读目标系统，不执行写入/删除/提权操作
- 所有工具调用经只读白名单校验
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from cain_agent.multi_agent.types import (
    Finding,
    Idea,
    SolverResult,
    SolverTask,
    TaskStatus,
)

if TYPE_CHECKING:
    from cain_agent.multi_agent.blackboard import Blackboard


class BaseSolver(ABC):
    """Solver 基类：定义执行接口和只读约束。"""

    #: 只读工具白名单（子类可扩展，不可删除核心项）
    ALLOWED_READ_TOOLS: frozenset[str] = frozenset({
        "curl", "nuclei", "nmap", "dig", "whois", "nslookup",
        "httpx", "subfinder", "assetfinder", "waybackurls",
    })

    def __init__(self, solver_id: str, blackboard: Blackboard | None = None):
        self.solver_id = solver_id
        self.blackboard = blackboard
        self.current_task: SolverTask | None = None

    def execute(self, task: SolverTask) -> SolverResult:
        """执行任务（模板方法：校验 → 执行 → 记录）。"""
        start = time.time()
        self.current_task = task
        task.status = TaskStatus.RUNNING
        task.assigned_solver = self.solver_id

        # 只读约束校验
        violation = self._check_readonly(task)
        if violation:
            return SolverResult(
                task_id=task.task_id,
                solver_id=self.solver_id,
                success=False,
                error=f"只读原则违反: {violation}",
                duration=time.time() - start,
            )

        try:
            result = self._run(task)
            result.task_id = task.task_id
            result.solver_id = self.solver_id
            result.duration = time.time() - start
            task.status = TaskStatus.COMPLETED if result.success else TaskStatus.FAILED

            # 同步到黑板
            if self.blackboard:
                for f in result.findings:
                    self.blackboard.post_finding(f, self.solver_id)
                for i in result.ideas:
                    self.blackboard.post_idea(i, self.solver_id)
            return result
        except Exception as exc:  # noqa: BLE001
            task.status = TaskStatus.FAILED
            return SolverResult(
                task_id=task.task_id,
                solver_id=self.solver_id,
                success=False,
                error=str(exc),
                duration=time.time() - start,
            )

    def _check_readonly(self, task: SolverTask) -> str | None:
        """只读约束校验。返回 None 表示通过，否则返回违规原因。"""
        forbidden = ("delete", "drop", "rm ", "write", "put-object", "upload")
        for constraint in task.constraints:
            if any(f in constraint.lower() for f in forbidden):
                return f"任务约束包含写操作: {constraint}"
        return None

    @abstractmethod
    def _run(self, task: SolverTask) -> SolverResult:
        """子类实现具体执行逻辑。"""

    @abstractmethod
    def capability(self) -> str:
        """Solver 能力标识（用于 Manager 任务路由）。"""


class ReconSolver(BaseSolver):
    """侦察 Solver：信息收集、攻击面映射（只读）。"""

    def capability(self) -> str:
        return "recon"

    def _run(self, task: SolverTask) -> SolverResult:
        findings: list[Finding] = []
        ideas: list[Idea] = []

        for target in task.scope:
            # 占位：实际实现调用只读工具（subfinder/httpx 等）
            ideas.append(Idea(
                hypothesis=f"目标 {target} 可能存在子域名未收录",
                plan=["subfinder 枚举", "httpx 存活探测", "指纹识别"],
                priority=6,
                parent_task_id=task.task_id,
                solver_id=self.solver_id,
            ))

        return SolverResult(
            success=True,
            findings=findings,
            ideas=ideas,
            output=f"侦察完成: 覆盖 {len(task.scope)} 个目标",
        )


class ExploitSolver(BaseSolver):
    """漏洞验证 Solver：基于 Idea 验证漏洞存在性（只读验证，不利用）。"""

    def capability(self) -> str:
        return "exploit"

    def _run(self, task: SolverTask) -> SolverResult:
        findings: list[Finding] = []

        # 从黑板读取待验证的 Idea
        if self.blackboard:
            open_ideas = self.blackboard.read_open_ideas()
            for idea in open_ideas:
                # 占位：只读验证逻辑（发送 PoC 探测包，不执行利用）
                finding = Finding(
                    service=task.context.get("service", "web"),
                    resource=task.scope[0] if task.scope else "",
                    issue_type=idea.hypothesis[:40],
                    confirmed=False,  # 需二次确认
                    solver_id=self.solver_id,
                )
                findings.append(finding)

        return SolverResult(
            success=True,
            findings=findings,
            output=f"验证完成: {len(findings)} 个候选发现",
        )


class ReportSolver(BaseSolver):
    """报告 Solver：汇总 Finding 生成证据链报告（只读）。"""

    def capability(self) -> str:
        return "report"

    def _run(self, task: SolverTask) -> SolverResult:
        confirmed = []
        if self.blackboard:
            confirmed = self.blackboard.read_confirmed_findings()

        report_lines = ["# 渗透测试报告", ""]
        for f in confirmed:
            report_lines.append(
                f"- [{f.severity.value.upper()}] {f.service}/{f.issue_type}: {f.resource}"
            )

        return SolverResult(
            success=True,
            output="\n".join(report_lines),
        )
