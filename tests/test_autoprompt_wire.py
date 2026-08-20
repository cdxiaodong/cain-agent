"""Auto-prompt recovery wiring tests — all fakes/mocks, zero network/target execution."""

from __future__ import annotations

from cain_agent.executor import SDKExecutor
from cain_agent.multi_agent.auto_prompt import (
    AutoPromptEngine,
    BlackboardAutoPromptMonitor,
    RecoveryPolicy,
    RepromptAction,
)
from cain_agent.multi_agent.blackboard import Blackboard
from cain_agent.multi_agent.manager import PentestManager
from cain_agent.multi_agent.orchestration import build_orchestration
from cain_agent.multi_agent.solver import BaseSolver
from cain_agent.multi_agent.types import SolverResult, SolverTask


class FakeFailingSolver(BaseSolver):
    """Deterministic solver that returns a programmed sequence of results."""

    def __init__(self, solver_id: str, responses: list[tuple[bool, str, str]]) -> None:
        super().__init__(solver_id, Blackboard())
        self.responses = responses
        self.calls = 0
        self.tasks: list[SolverTask] = []

    def capability(self) -> str:
        return "test"

    def _run(self, task: SolverTask) -> SolverResult:
        self.tasks.append(task)
        success, output, error = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return SolverResult(success=success, output=output, error=error)


def _make_manager(
    responses: list[tuple[bool, str, str]],
    policy: RecoveryPolicy | None = None,
) -> tuple[PentestManager, FakeFailingSolver]:
    blackboard = Blackboard()
    monitor = BlackboardAutoPromptMonitor(
        blackboard,
        AutoPromptEngine(
            policy=policy
            or RecoveryPolicy(
                sequence=(
                    RepromptAction.RETRY,
                    RepromptAction.DECOMPOSE,
                    RepromptAction.SKIP,
                ),
                failure_threshold=1,
                max_attempts=3,
            ),
        ),
    )
    solver = FakeFailingSolver("s1", responses)
    manager = PentestManager(blackboard, recovery=monitor)
    manager.register_solver("s1", solver)
    return manager, solver


def _task(objective: str = "scan endpoint") -> SolverTask:
    return SolverTask(
        objective=objective,
        scope=["example.com"],
        constraints=["readonly"],
        context={"capability": "test"},
    )


def test_recovery_default_sequence_retry_decompose_skip() -> None:
    manager, solver = _make_manager([
        (False, "", "execution timeout"),
        (False, "", "execution timeout"),
        (False, "", "execution timeout"),
    ])

    result = manager.dispatch([_task()])[0]

    assert not result.success
    assert solver.calls == 3
    assert "重试目标" in solver.tasks[1].objective
    assert "拆分为两个更小的只读检测步骤" in solver.tasks[2].objective


def test_recovery_stops_on_success() -> None:
    manager, solver = _make_manager([
        (False, "", "execution timeout"),
        (True, "found endpoint", ""),
    ])

    result = manager.dispatch([_task()])[0]

    assert result.success
    assert solver.calls == 2
    assert "重试目标" in solver.tasks[1].objective


def test_recovery_ignores_non_recoverable_success() -> None:
    manager, solver = _make_manager([
        (True, "valid result", ""),
    ])

    result = manager.dispatch([_task()])[0]

    assert result.success
    assert solver.calls == 1


def test_recovery_skip_decision_does_not_redispatch() -> None:
    manager, solver = _make_manager([
        (False, "", "execution timeout"),
        (False, "", "execution timeout"),
        (False, "", "execution timeout"),
    ])

    result = manager.dispatch([_task()])[0]

    assert not result.success
    assert solver.calls == 3
    # The final recorded decision on the blackboard should be SKIP.
    assert manager.recovery is not None
    history = manager.recovery.read_history()
    decision = manager.recovery.engine.evaluate_history(history, objective=_task().objective)
    assert decision is not None
    assert decision.action is RepromptAction.SKIP
    assert not decision.should_redispatch


def test_recovery_policy_is_configurable() -> None:
    policy = RecoveryPolicy(
        sequence=(RepromptAction.DECOMPOSE, RepromptAction.SKIP),
        failure_threshold=1,
        max_attempts=2,
    )
    manager, solver = _make_manager([
        (False, "", "execution timeout"),
        (False, "", "execution timeout"),
    ], policy=policy)

    result = manager.dispatch([_task()])[0]

    assert not result.success
    assert solver.calls == 2
    assert "拆分为两个更小的只读检测步骤" in solver.tasks[1].objective


def test_recovery_preserves_scope_constraints_and_context() -> None:
    manager, solver = _make_manager([
        (False, "", "execution timeout"),
        (True, "ok", ""),
    ])

    manager.dispatch([_task()])

    for task in solver.tasks:
        assert task.scope == ["example.com"]
        assert task.constraints == ["readonly"]
        assert task.context["capability"] == "test"


def test_no_recovery_without_monitor() -> None:
    solver = FakeFailingSolver("s1", [
        (False, "", "execution timeout"),
        (True, "ok", ""),
    ])
    manager = PentestManager(Blackboard())
    manager.register_solver("s1", solver)

    result = manager.dispatch([_task()])[0]

    assert not result.success
    assert solver.calls == 1


def test_build_orchestration_injects_recovery_monitor() -> None:
    orchestration = build_orchestration(SDKExecutor())

    assert orchestration.manager.recovery is not None
    assert orchestration.manager.recovery.engine.policy is not None
    assert orchestration.manager.recovery.engine.policy.sequence == (
        RepromptAction.RETRY,
        RepromptAction.DECOMPOSE,
        RepromptAction.SKIP,
    )


def test_recovery_records_failure_history_on_blackboard() -> None:
    manager, solver = _make_manager([
        (False, "", "execution timeout"),
        (False, "", "execution timeout"),
        (False, "", "execution timeout"),
    ])

    manager.dispatch([_task()])

    assert manager.recovery is not None
    history = manager.recovery.read_history()
    assert len(history) == 3
    assert all(record.failed for record in history)
    assert all(record.solver_id == "s1" for record in history)


def test_recovery_parse_failure_uses_strict_json_retry() -> None:
    manager, solver = _make_manager([
        (False, "", "JSON decode error"),
        (False, "", "JSON decode error"),
    ])

    manager.dispatch([_task()])

    assert "只输出一个 JSON 对象" in solver.tasks[1].objective
    assert "不要 Markdown" in solver.tasks[1].objective
