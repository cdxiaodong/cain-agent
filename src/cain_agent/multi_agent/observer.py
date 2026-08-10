"""SafetyObserver —— 旁路监督（轻量纠偏 + Idea/Memory 分离）

职责：
- 执行路径监督：检测 Solver 是否偏离目标/重复劳作/死循环
- 状态分层维护：区分 Idea（方向）和 Memory（事实），避免状态混杂
- 轻量纠偏：发现问题时给出建议，不阻断 Solver 执行
- 只读原则守门：确保所有 Solver 符合只读约束

关键设计（借鉴 BreachWeave）：
- Observer 独立运行，不干扰 Solver 正常流程
- 纠偏建议通过黑板发布，Solver 可选择性采纳
- 重点关注：路径偏离、状态混杂、过早结束、上下文过重
"""

from __future__ import annotations

from collections import Counter

from cain_agent.multi_agent.types import (
    CorrectionAdvice,
    Finding,
    Idea,
    SolverResult,
)


class SafetyObserver:
    """安全观察者：旁路监督，不阻断执行。"""

    def __init__(self):
        self.advice_history: list[CorrectionAdvice] = []
        self._execution_trace: dict[str, list[str]] = {}  # solver_id -> actions

    def audit_result(self, result: SolverResult) -> list[CorrectionAdvice]:
        """审计 Solver 结果，给出纠偏建议。"""
        advices: list[CorrectionAdvice] = []

        # 1. 检查是否偏离只读原则
        if not result.success and result.error:
            advices.append(CorrectionAdvice(
                solver_id=result.solver_id,
                issue="执行失败",
                suggestion=f"检查只读约束: {result.error}",
                severity="warning",
            ))

        # 2. 检查是否产生空结果（过早结束）
        if result.success and not result.findings and not result.ideas:
            advices.append(CorrectionAdvice(
                solver_id=result.solver_id,
                issue="过早结束",
                suggestion="无 Finding 也无 Idea，可能退出过早，建议扩大探测范围",
                severity="info",
            ))

        # 3. 检查 Finding 重复度（重复劳作）
        if result.findings:
            dup_count = self._check_duplicate_findings(result.findings)
            if dup_count > 0:
                advices.append(CorrectionAdvice(
                    solver_id=result.solver_id,
                    issue=f"重复发现: {dup_count} 个 Finding 已存在",
                    suggestion="建议先读取黑板已有 Finding，避免重复验证",
                    severity="info",
                ))

        self.advice_history.extend(advices)
        return advices

    def _check_duplicate_findings(self, new_findings: list[Finding]) -> int:
        """检查新发现与已知发现的重复度（简版：按 resource+issue_type 去重）。"""
        # 占位：实际需要从黑板读取已有 Finding
        seen_resources: set[tuple[str, str]] = set()
        dup_count = 0
        for f in new_findings:
            key = (f.resource, f.issue_type)
            if key in seen_resources:
                dup_count += 1
            seen_resources.add(key)
        return dup_count

    def monitor_path_drift(
        self,
        solver_id: str,
        current_action: str,
        expected_scope: list[str],
    ) -> CorrectionAdvice | None:
        """监控执行路径是否偏离目标范围。"""
        self._execution_trace.setdefault(solver_id, []).append(current_action)

        # 占位：检查当前 action 是否在 expected_scope 内
        # 实际需解析 action 中的目标（URL/域名/资源）
        return None

    def check_state_corruption(
        self,
        ideas: list[Idea],
        findings: list[Finding],
    ) -> CorrectionAdvice | None:
        """检查状态混杂（Idea 被当作事实，或 Finding 被当作假设）。"""
        # 占位：检查是否有 Finding 的 confirmed=False 但被当作依据
        unconfirmed_as_fact = [
            f for f in findings if not f.confirmed and "evidence" in f.evidence
        ]
        if unconfirmed_as_fact:
            return CorrectionAdvice(
                solver_id="system",
                issue="状态混杂: 未确认 Finding 被当作数据",
                suggestion="建议将未确认 Finding 存为 Idea，经二次验证后转为 Finding",
                severity="warning",
            )
        return None

    def get_advice_summary(self) -> dict[str, int]:
        """统计纠偏建议（用于 Manager 调整策略）。"""
        counter = Counter(a.severity for a in self.advice_history)
        return {
            "critical": counter.get("critical", 0),
            "warning": counter.get("warning", 0),
            "info": counter.get("info", 0),
            "total": len(self.advice_history),
        }
