from cain_agent.multi_agent.auto_prompt import (
    AutoPromptEngine,
    BlackboardAutoPromptMonitor,
    FailureMode,
    RepromptAction,
)
from cain_agent.multi_agent.blackboard import Blackboard
from cain_agent.multi_agent.types import SolverResult


def _result(
    solver_id: str = "solver-1",
    *,
    success: bool = False,
    error: str = "",
    output: str = "",
    duration: float = 0.0,
) -> SolverResult:
    return SolverResult(
        task_id="task-1",
        solver_id=solver_id,
        success=success,
        error=error,
        output=output,
        duration=duration,
    )


def test_empty_success_streak_requests_decomposition() -> None:
    engine = AutoPromptEngine()
    first = engine.observe(_result(success=True, output="no result"), "检查暴露面")
    second = engine.observe(_result(success=True), "检查暴露面")

    assert first is None
    assert second is not None
    assert second.action is RepromptAction.DECOMPOSE
    assert second.failure_mode is FailureMode.EMPTY
    assert second.attempts == 2
    assert "最多 3 个更小的可观察对象" in second.prompt
    assert second.should_redispatch


def test_parse_failure_retries_with_strict_json_contract() -> None:
    decision = AutoPromptEngine().evaluate_history(
        [
            _result(error="JSON decode error"),
            _result(error="cannot parse model output"),
        ],
        objective="验证配置暴露",
    )

    assert decision is not None
    assert decision.action is RepromptAction.RETRY
    assert decision.failure_mode is FailureMode.PARSE
    assert "只输出一个 JSON 对象" in decision.prompt
    assert "不要 Markdown" in decision.prompt


def test_timeout_requests_smaller_steps() -> None:
    decision = AutoPromptEngine().evaluate_history(
        [
            _result(error="execution timeout", duration=30),
            _result(error="deadline exceeded", duration=31),
        ],
        objective="检查一组端点",
    )

    assert decision is not None
    assert decision.action is RepromptAction.DECOMPOSE
    assert decision.failure_mode is FailureMode.TIMEOUT
    assert "两个更小的只读检测步骤" in decision.prompt
    assert decision.attempts == 2


def test_interleaved_solver_result_breaks_streak() -> None:
    decision = AutoPromptEngine().evaluate_history(
        [
            _result(error="JSON parse failed"),
            _result(error="JSON parse failed", solver_id="solver-2"),
            _result(error="JSON parse failed"),
        ],
    )

    assert decision is None


def test_success_with_output_breaks_failure_streak() -> None:
    decision = AutoPromptEngine().evaluate_history(
        [
            _result(error="JSON parse failed"),
            _result(success=True, output="valid result"),
            _result(error="JSON parse failed"),
        ],
    )

    assert decision is None


def test_repeated_failure_is_skipped_after_attempt_limit() -> None:
    history = [_result(error="timeout") for _ in range(3)]
    decision = AutoPromptEngine().evaluate_history(history, objective="检查端点")

    assert decision is not None
    assert decision.action is RepromptAction.SKIP
    assert decision.attempts == 3
    assert not decision.should_redispatch
    assert decision.prompt == "检查端点"


def test_monitor_uses_blackboard_history_and_latest_objective() -> None:
    blackboard = Blackboard()
    monitor = BlackboardAutoPromptMonitor(blackboard)

    assert monitor.record(_result(error="response schema invalid")) is None
    decision = monitor.record(_result(error="invalid JSON"), objective="检查配置")

    assert decision is not None
    assert decision.action is RepromptAction.RETRY
    assert decision.prompt.startswith("重试目标：检查配置")
    assert len(monitor.read_history()) == 2
