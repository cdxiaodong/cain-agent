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
from typing import TYPE_CHECKING

from cain_agent.multi_agent.types import (
    SolverResult,
    SolverTask,
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


class PentestManager:
    """渗透测试 Manager：全局编排，不直接执行动作。"""

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
