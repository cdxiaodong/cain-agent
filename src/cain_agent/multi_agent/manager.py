"""PentestManager —— 控制面（站在任务视角全局编排）

职责：
- 任务分解：将渗透测试目标拆分为可并行的子任务
- Solver 分配：根据任务类型和能力分发给对应 Solver
- 进度编排：管理任务推进节奏，协调多 Solver 协作
- 资源回收：任务完成后回收 Solver 资源

只读约束：Manager 只做编排决策，不直接触碰目标系统。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cain_agent.multi_agent.memory import (
    MemoryKind,
    MemorySearchResult,
    finding_text,
)
from cain_agent.multi_agent.types import (
    Finding,
    Severity,
    SolverResult,
    SolverTask,
)
from cain_agent.multi_agent.verify_pool import (
    ValidationConsensus,
    VerificationPool,
    VerificationVerdict,
)

if TYPE_CHECKING:
    from cain_agent.multi_agent.blackboard import Blackboard
    from cain_agent.multi_agent.observer import SafetyObserver
    from cain_agent.multi_agent.solver import BaseSolver


@dataclass
class SolverSlot:
    """Solver 槽位（资源管理）。"""

    solver: BaseSolver
    task: SolverTask | None = None
    busy_since: float = 0.0
    completed_tasks: int = 0


@dataclass(frozen=True)
class EvidenceLink:
    """结论依据链中的一条证据。"""

    source: str
    detail: str
    score: float = 0.0


@dataclass(frozen=True)
class ManagerConclusion:
    """Manager 聚合后的最终结论，供报告阶段直接消费。

    confidence:        0~1 归一化置信度，综合验证表决与记忆旁证得出
    consensus:         验证池多数表决共识（未验证时为 None）
    evidence_chain:    依据链（solver 上报 → 验证表决 → 记忆旁证）
    memory_hits:       语义记忆检索命中的相似记录（含分数）
    """

    finding_id: str
    finding: Finding
    confidence: float
    consensus: ValidationConsensus | None
    evidence_chain: tuple[EvidenceLink, ...]
    memory_hits: tuple[MemorySearchResult, ...]

    def to_dict(self) -> dict[str, Any]:
        """序列化为报告阶段可消费的 JSON 结构。"""
        f = self.finding
        return {
            "finding_id": self.finding_id,
            "confidence": self.confidence,
            "consensus": self.consensus.value if self.consensus else None,
            "finding": {
                "cloud": f.cloud,
                "service": f.service,
                "resource": f.resource,
                "issue_type": f.issue_type,
                "severity": f.severity.value,
                "detail": f.detail,
                "evidence": f.evidence,
                "confirmed": f.confirmed,
                "solver_id": f.solver_id,
            },
            "evidence_chain": [
                {"source": link.source, "detail": link.detail, "score": link.score}
                for link in self.evidence_chain
            ],
            "memory_hits": [
                {
                    "record_id": hit.record.record_id,
                    "kind": hit.record.kind.value,
                    "key": hit.record.key,
                    "score": round(hit.score, 3),
                }
                for hit in self.memory_hits
            ],
        }


class PentestManager:
    """渗透测试 Manager：全局编排，不直接执行动作。

    编排之外承担「判断聚合」：综合各 Solver 产出、并行验证池
    多数表决与语义记忆检索，输出带置信度的最终结论。
    """

    def __init__(self, blackboard: Blackboard, observer: SafetyObserver | None = None):
        self.blackboard = blackboard
        self.observer = observer
        self.slots: dict[str, SolverSlot] = {}
        self.completed_tasks: list[SolverResult] = []

    def register_solver(self, solver_id: str, solver: BaseSolver) -> None:
        """注册 Solver（复用池，可动态扩展）。"""
        self.slots[solver_id] = SolverSlot(solver=solver)

    def dispatch(self, tasks: list[SolverTask]) -> list[SolverResult]:
        """批量分发任务（根据能力路由）。"""
        results = []

        for task in tasks:
            solver_id = self._route_solver(task)
            if not solver_id:
                results.append(SolverResult(
                    task_id=task.task_id,
                    success=False,
                    error=f"无可用 Solver（能力: {task.context.get('capability', 'unknown')}）",
                ))
                continue

            slot = self.slots[solver_id]
            slot.task = task
            slot.busy_since = time.time()

            # Observer 预检（可选，不影响分发）
            if self.observer:
                # 占位：Observer 可在这里给出前置建议
                pass

            result = slot.solver.execute(task)
            slot.completed_tasks += 1
            slot.task = None

            results.append(result)
            self.completed_tasks.append(result)

        return results

    def _route_solver(self, task: SolverTask) -> str | None:
        """根据任务能力路由到空闲 Solver（负载均衡）。"""
        capability = task.context.get("capability", "")
        idle_slots = [
            (sid, slot)
            for sid, slot in self.slots.items()
            if slot.task is None and slot.solver.capability() == capability
        ]
        if not idle_slots:
            return None

        # 选择完成任务数最少的（负载均衡）
        idle_slots.sort(key=lambda x: x[1].completed_tasks)
        return idle_slots[0][0]

    def get_progress(self) -> dict[str, int]:
        """进度统计（用于 Observer 监督）。"""
        return {
            "total_slots": len(self.slots),
            "busy_slots": sum(1 for s in self.slots.values() if s.task is not None),
            "completed_tasks": len(self.completed_tasks),
            "findings_count": len(self.blackboard.read_findings()),
            "open_ideas_count": len(self.blackboard.read_open_ideas()),
        }

    def generate_next_tasks(self, max_tasks: int = 10) -> list[SolverTask]:
        """根据当前状态生成下一批任务（从 Idea 转化为 Task）。"""
        tasks: list[SolverTask] = []

        # 从黑板读取高优先级 Idea
        open_ideas = self.blackboard.read_open_ideas(min_priority=7)

        for idea in open_ideas[:max_tasks]:
            task = SolverTask(
                objective=idea.hypothesis,
                scope=idea.plan.copy(),
                constraints=["readonly"],
                context={
                    "capability": "exploit",
                    "parent_idea_id": idea.idea_id,
                },
            )
            tasks.append(task)

        return tasks

    # -- 判断聚合 ---------------------------------------------------------------

    def aggregate_findings(
        self,
        pool: VerificationPool | None = None,
        *,
        top_k: int = 3,
        min_score: float = 0.0,
    ) -> list[ManagerConclusion]:
        """综合所有 Solver finding + 验证池表决 + 语义记忆，输出最终结论。

        返回结论已排序：已确认优先，其余按置信度降序；报告阶段按此顺序消费。

        :param pool: 并行验证池。为空时复用黑板上已存的 validation fact，
            两者皆无则该 finding 标记为「未验证」。
        :param top_k: 每个 finding 最多取几条记忆旁证。
        :param min_score: 记忆检索最低余弦相似度阈值。
        """
        if top_k < 1:
            raise ValueError("top_k must be positive")
        if not 0.0 <= min_score <= 1.0:
            raise ValueError("min_score must be between 0 and 1")

        conclusions = [
            self._aggregate_one(finding, pool, top_k=top_k, min_score=min_score)
            for finding in self.blackboard.read_findings()
        ]
        conclusions.sort(key=self._conclusion_sort_key, reverse=True)
        return conclusions

    def _aggregate_one(
        self,
        finding: Finding,
        pool: VerificationPool | None,
        *,
        top_k: int,
        min_score: float,
    ) -> ManagerConclusion:
        """聚合单个 finding：验证表决 + 记忆旁证 → 置信度 + 依据链。"""
        consensus, disagreement, verification_text = self._collect_verification(finding, pool)
        if consensus is ValidationConsensus.CONFIRMED:
            self.blackboard.confirm_finding(finding.finding_id)

        memory_hits = self._search_related_memory(finding, top_k=top_k, min_score=min_score)
        memory_support = memory_hits[0].score if memory_hits else 0.0

        evidence_chain = (
            EvidenceLink(
                source="solver",
                detail=f"solver {finding.solver_id} 上报" if finding.solver_id else "solver 上报",
                score=1.0 if finding.confirmed else 0.5,
            ),
            EvidenceLink(
                source="verification",
                detail=verification_text,
                score=self._consensus_score(consensus),
            ),
            *(
                EvidenceLink(
                    source="memory",
                    detail=f"相似记录 {hit.record.kind.value}::{hit.record.key}",
                    score=round(hit.score, 3),
                )
                for hit in memory_hits
            ),
        )

        return ManagerConclusion(
            finding_id=finding.finding_id,
            finding=finding,
            confidence=self._confidence(consensus, disagreement, memory_support),
            consensus=consensus,
            evidence_chain=evidence_chain,
            memory_hits=tuple(memory_hits),
        )

    def _collect_verification(
        self,
        finding: Finding,
        pool: VerificationPool | None,
    ) -> tuple[ValidationConsensus | None, bool, str]:
        """运行验证池多数表决；无池时复用已存 validation fact。"""
        if pool is not None:
            report = pool.verify_finding(finding)
            counts = report.vote_counts
            summary = (
                f"验证池多数表决: confirmed={counts[VerificationVerdict.CONFIRMED]} "
                f"rejected={counts[VerificationVerdict.REJECTED]} "
                f"inconclusive={counts[VerificationVerdict.INCONCLUSIVE]}"
            )
            return report.validation_consensus, report.disagreement, summary

        stored = self.blackboard.get_fact(f"validation:{finding.finding_id}")
        if isinstance(stored, dict):
            try:
                consensus = ValidationConsensus(stored["validation_consensus"])
            except (KeyError, ValueError):
                consensus = None
            counts = stored.get("vote_counts", {})
            summary = (
                f"复用已存表决: confirmed={counts.get('confirmed', 0)} "
                f"rejected={counts.get('rejected', 0)} "
                f"inconclusive={counts.get('inconclusive', 0)}"
            )
            return consensus, bool(stored.get("disagreement", False)), summary

        return None, False, "未验证（无验证池且无已存表决）"

    def _search_related_memory(
        self,
        finding: Finding,
        *,
        top_k: int,
        min_score: float,
    ) -> list[MemorySearchResult]:
        """检索语义记忆中的相似记录作为旁证，排除 finding 自身。"""
        results = self.blackboard.search(
            finding_text(finding),
            top_k=top_k + 1,
            min_score=min_score,
        )
        related = [
            result
            for result in results
            if not (
                result.record.kind is MemoryKind.FINDING
                and isinstance(result.record.payload, Finding)
                and result.record.payload.finding_id == finding.finding_id
            )
        ]
        return related[:top_k]

    @staticmethod
    def _consensus_score(consensus: ValidationConsensus | None) -> float:
        """把验证共识映射为 0~1 的数值证据分。"""
        scores = {
            ValidationConsensus.CONFIRMED: 1.0,
            ValidationConsensus.CONTESTED: 0.5,
            ValidationConsensus.REJECTED: 0.0,
        }
        return scores.get(consensus, 0.0) if consensus is not None else 0.0

    @staticmethod
    def _confidence(
        consensus: ValidationConsensus | None,
        disagreement: bool,
        memory_support: float,
    ) -> float:
        """归一化置信度：以验证共识为基，分歧扣分，记忆旁证加分。"""
        if consensus is ValidationConsensus.CONFIRMED:
            base = 0.85
        elif consensus is ValidationConsensus.CONTESTED:
            base = 0.50
        elif consensus is ValidationConsensus.REJECTED:
            base = 0.15
        else:
            base = 0.40  # consensus is None → 未验证
        confidence = base - (0.05 if disagreement else 0.0)
        confidence += max(0.0, min(memory_support, 1.0)) * 0.10
        return round(min(max(confidence, 0.05), 0.95), 3)

    @staticmethod
    def _conclusion_sort_key(conclusion: ManagerConclusion) -> tuple[object, float, int]:
        severity_rank = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return (
            conclusion.finding.confirmed,
            round(conclusion.confidence, 3),
            severity_rank.get(conclusion.finding.severity, 1),
        )
