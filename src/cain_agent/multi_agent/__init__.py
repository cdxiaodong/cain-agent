"""Multi-Agent 架构 —— 基于 BreachWeave 的三层解耦设计

Manager（控制平面）+ Solver（执行主体）+ Observer（旁路监督）

设计原则：
- 只读原则：所有 Agent 只读目标系统，不执行写入/破坏操作
- 确定性工程：阶段流转由 Orchestrator 硬编码，Agent 协作灵活
- 旁路监督：Observer 独立运行，不干扰 Solver 执行，仅纠偏
"""

from cain_agent.multi_agent.handler import (
    MultiAgentHandler,
    create_multi_agent_handlers,
)
from cain_agent.multi_agent.manager import PentestManager
from cain_agent.multi_agent.observer import SafetyObserver
from cain_agent.multi_agent.solver import (
    BaseSolver,
    ExploitSolver,
    ReconSolver,
    ReportSolver,
)
from cain_agent.multi_agent.types import (
    Finding,
    Idea,
    Memory,
    SolverResult,
    SolverTask,
)
from cain_agent.multi_agent.verify_pool import (
    ValidationConsensus,
    VerificationPool,
    VerificationReport,
    VerificationSession,
    VerificationVerdict,
    VerificationVote,
)

__all__ = [
    "BaseSolver",
    "ExploitSolver",
    "Finding",
    "Idea",
    "Memory",
    "MultiAgentHandler",
    "PentestManager",
    "ReconSolver",
    "ReportSolver",
    "SafetyObserver",
    "SolverResult",
    "SolverTask",
    "ValidationConsensus",
    "VerificationPool",
    "VerificationReport",
    "VerificationSession",
    "VerificationVerdict",
    "VerificationVote",
    "create_multi_agent_handlers",
]
