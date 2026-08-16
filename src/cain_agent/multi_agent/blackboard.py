"""Blackboard —— Agent 通信黑板（Idea/Memory 分离 + 间接协同）

核心思想（借鉴 Cairn 黑板系统 + OpenAI-HF 事件 Stigmergy）：
- Agent 不直接通信，通过读写共享黑板间接协同
- Idea（方向/假设）与 Memory（事实/证据）分离存储
- ZZ 前缀优先级消息（高优先级优先被消费）

只读约束：黑板本身只管理状态，不触碰目标系统。
"""

from __future__ import annotations

import threading

from cain_agent.multi_agent.memory import (
    MemoryKind,
    MemorySearchResult,
    SemanticMemory,
)
from cain_agent.multi_agent.types import Finding, Idea, Memory


class Blackboard:
    """Agent 通信黑板：线程安全的共享状态。"""

    def __init__(self, semantic_memory: SemanticMemory | None = None) -> None:
        self._lock = threading.RLock()
        self._memory = Memory()  # 客观事实（只增）
        self._ideas: dict[str, Idea] = {}  # 主观方向（可更新状态）
        self._subscribers: dict[str, list[str]] = {}  # event -> solver_ids
        self.semantic_memory = semantic_memory or SemanticMemory()

    # ---- Memory（事实，只增不改） ----

    def post_finding(self, finding: Finding, solver_id: str) -> None:
        """发布已发现漏洞（客观事实）。"""
        with self._lock:
            finding.solver_id = solver_id
            self.semantic_memory.post_finding(finding, solver_id)
            self._memory.findings.append(finding)
        self._notify("finding", solver_id)

    def read_findings(self) -> list[Finding]:
        with self._lock:
            return list(self._memory.findings)

    def read_confirmed_findings(self) -> list[Finding]:
        with self._lock:
            return [f for f in self._memory.findings if f.confirmed]

    def confirm_finding(self, finding_id: str) -> bool:
        """二次确认（发现/校验分离）。"""
        with self._lock:
            for f in self._memory.findings:
                if f.finding_id == finding_id:
                    f.confirmed = True
                    return True
        return False

    def set_fact(self, key: str, value: object) -> None:
        with self._lock:
            self.semantic_memory.set_fact(key, value)
            self._memory.facts[key] = value

    def get_fact(self, key: str, default: object = None) -> object:
        with self._lock:
            return self._memory.facts.get(key, default)

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float = 0.0,
        kinds: tuple[MemoryKind, ...] | None = None,
    ) -> list[MemorySearchResult]:
        """Search retrievable findings and shared context."""

        return self.semantic_memory.search(
            query,
            top_k=top_k,
            min_score=min_score,
            kinds=kinds,
        )

    # ---- Idea（方向，状态可变） ----

    def post_idea(self, idea: Idea, solver_id: str) -> None:
        """发布待验证方向。"""
        with self._lock:
            idea.solver_id = solver_id
            self._ideas[idea.idea_id] = idea
        self._notify("idea", solver_id)

    def read_open_ideas(self, min_priority: int = 0) -> list[Idea]:
        """读取开放方向（按优先级降序）。"""
        with self._lock:
            open_ideas = [
                i for i in self._ideas.values() if i.status == "open" and i.priority >= min_priority
            ]
        return sorted(open_ideas, key=lambda x: x.priority, reverse=True)

    def resolve_idea(self, idea_id: str, verified: bool) -> bool:
        """验证方向后更新状态。"""
        with self._lock:
            if idea_id in self._ideas:
                self._ideas[idea_id].status = "verified" if verified else "rejected"
                return True
        return False

    # ---- 订阅/通知（轻量事件） ----

    def subscribe(self, event: str, solver_id: str) -> None:
        with self._lock:
            self._subscribers.setdefault(event, []).append(solver_id)

    def _notify(self, event: str, solver_id: str) -> None:
        # 仅记录事件，不主动推送（Solver 轮询读取，保持解耦）
        _ = (event, solver_id)

    # ---- 统计 ----

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "findings": len(self._memory.findings),
                "confirmed": len([f for f in self._memory.findings if f.confirmed]),
                "ideas_open": len([i for i in self._ideas.values() if i.status == "open"]),
                "ideas_total": len(self._ideas),
            }
