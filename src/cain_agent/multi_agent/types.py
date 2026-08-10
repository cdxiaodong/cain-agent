"""Multi-Agent 类型定义 —— 核心数据结构

Idea（方向）vs Memory（事实）分离：
- Idea：Solver 的假设、策略、待验证方向（可变、主观）
- Memory：已确认的事实、发现的漏洞、收集的数据（客观、不可变）
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def _uuid() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> float:
    return time.time()


# Use str+Enum for backward compatibility with Python < 3.11
# ruff: noqa: UP042
class Severity(str, Enum):
    """
漏洞严重等级。
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ruff: noqa: UP042
class TaskStatus(str, Enum):
    """
任务状态。
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class Finding:
    """已确认的漏洞发现（Memory 的一部分，客观事实）。"""

    cloud: str = ""
    service: str = ""
    resource: str = ""
    issue_type: str = ""
    severity: Severity = Severity.INFO
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    confirmed: bool = False
    finding_id: str = field(default_factory=_uuid)
    timestamp: float = field(default_factory=_now)
    solver_id: str = ""


@dataclass
class Idea:
    """待验证的方向/假设（主观，可被推翻）。"""

    hypothesis: str
    plan: list[str] = field(default_factory=list)
    priority: int = 5
    status: str = "open"
    parent_task_id: str = ""
    idea_id: str = field(default_factory=_uuid)
    timestamp: float = field(default_factory=_now)
    solver_id: str = ""


@dataclass
class Memory:
    """已确认的事实集合（客观，只增不改）。"""

    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    evidence_store: dict[str, Any] = field(default_factory=dict)


@dataclass
class SolverTask:
    """Manager 分配给 Solver 的任务。"""

    objective: str
    scope: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    task_id: str = field(default_factory=_uuid)
    created_at: float = field(default_factory=_now)
    status: TaskStatus = TaskStatus.PENDING
    assigned_solver: str = ""


@dataclass
class SolverResult:
    """Solver 执行结果。"""

    task_id: str = ""
    solver_id: str = ""
    success: bool = False
    findings: list[Finding] = field(default_factory=list)
    ideas: list[Idea] = field(default_factory=list)
    output: str = ""
    error: str = ""
    duration: float = 0.0
    completed_at: float = field(default_factory=_now)


@dataclass
class CorrectionAdvice:
    """Observer 纠偏建议。"""

    solver_id: str
    issue: str
    suggestion: str
    severity: str = "info"
    should_block: bool = False
    advice_id: str = field(default_factory=_uuid)
    timestamp: float = field(default_factory=_now)
