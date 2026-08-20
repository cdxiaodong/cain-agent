"""Failure-driven prompt recovery for the multi-agent orchestrator."""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from cain_agent.multi_agent.types import SolverResult

if TYPE_CHECKING:
    from cain_agent.multi_agent.blackboard import Blackboard


class FailureMode(StrEnum):
    """Recoverable solver failure patterns."""

    EMPTY = "empty"
    TIMEOUT = "timeout"
    PARSE = "parse"
    UNKNOWN = "unknown"


class RepromptAction(StrEnum):
    """Next dispatch action selected by the recovery engine."""

    RETRY = "retry"
    DECOMPOSE = "decompose"
    SKIP = "skip"


@dataclass(frozen=True)
class FailureRecord:
    """A normalized execution record used for streak detection."""

    task_id: str
    solver_id: str
    mode: FailureMode
    failed: bool
    objective: str = ""
    error: str = ""
    output: str = ""
    duration: float = 0.0
    completed_at: float = field(default=0.0)

    @classmethod
    def from_result(
        cls,
        result: SolverResult,
        objective: str = "",
    ) -> FailureRecord:
        return cls(
            task_id=result.task_id,
            solver_id=result.solver_id,
            mode=classify_failure(result),
            failed=is_recoverable_failure(result),
            objective=objective,
            error=result.error,
            output=result.output,
            duration=result.duration,
            completed_at=result.completed_at,
        )


@dataclass(frozen=True)
class RepromptDecision:
    """The rewritten prompt and dispatch decision for a failing solver."""

    action: RepromptAction
    failure_mode: FailureMode
    prompt: str
    reason: str
    attempts: int
    solver_id: str
    task_id: str

    @property
    def should_redispatch(self) -> bool:
        return self.action is not RepromptAction.SKIP


@dataclass(frozen=True)
class RecoveryPolicy:
    """Configurable recovery action sequence for solver execution failures.

    After classifying a failure mode, the engine walks through ``sequence``
    starting at index ``attempts - failure_threshold``. Once ``max_attempts``
    is reached the final action is always ``SKIP`` regardless of sequence.
    """

    sequence: tuple[RepromptAction, ...] = (
        RepromptAction.RETRY,
        RepromptAction.DECOMPOSE,
        RepromptAction.SKIP,
    )
    failure_threshold: int = 1
    max_attempts: int = 3


def is_recoverable_failure(result: SolverResult) -> bool:
    """Return whether a result should participate in failure recovery."""

    output = result.output.strip().lower()
    has_artifact = bool(result.findings or result.ideas or output)
    explicitly_empty = any(
        marker in output
        for marker in ("no result", "no findings", "empty", "无结果", "未发现")
    )
    return not result.success or not has_artifact or explicitly_empty


def classify_failure(result: SolverResult) -> FailureMode:
    """Classify a result without treating an empty success as a hard error."""

    text = f"{result.error} {result.output}".lower()
    if not result.success and any(token in text for token in ("timeout", "time-out", "deadline")):
        return FailureMode.TIMEOUT
    if not result.success and any(
        token in text
        for token in ("parse", "json", "schema", "syntax", "decode", "unexpected format")
    ):
        return FailureMode.PARSE
    if result.success and is_recoverable_failure(result):
        return FailureMode.EMPTY
    return FailureMode.UNKNOWN


class AutoPromptEngine:
    """Detect repeated failure patterns and produce deterministic reprompts."""

    def __init__(
        self,
        base_prompt: str = "完成当前只读检测任务，并给出可验证结果。",
        failure_threshold: int = 2,
        max_attempts: int = 3,
        policy: RecoveryPolicy | None = None,
    ) -> None:
        self.policy = policy
        if policy is not None:
            failure_threshold = policy.failure_threshold
            max_attempts = policy.max_attempts

        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if max_attempts < failure_threshold:
            raise ValueError("max_attempts must be greater than or equal to failure_threshold")

        self.base_prompt = base_prompt
        self.failure_threshold = failure_threshold
        self.max_attempts = max_attempts
        self._history: list[FailureRecord] = []
        self._lock = threading.RLock()

    def observe(self, result: SolverResult, objective: str = "") -> RepromptDecision | None:
        """Append one result to the in-memory history and evaluate its streak."""

        record = FailureRecord.from_result(result, objective)
        with self._lock:
            self._history.append(record)
            return self._decide(self._history, objective)

    def evaluate_history(
        self,
        history: Sequence[SolverResult | FailureRecord],
        *,
        solver_id: str | None = None,
        objective: str = "",
    ) -> RepromptDecision | None:
        """Evaluate an externally supplied history without mutating it."""

        records = [self._normalize(item) for item in history]
        if solver_id is not None:
            records = [record for record in records if record.solver_id == solver_id]
        return self._decide(records, objective)

    def _normalize(self, item: SolverResult | FailureRecord) -> FailureRecord:
        if isinstance(item, FailureRecord):
            return item
        return FailureRecord.from_result(item)

    def _decide(
        self,
        records: Sequence[FailureRecord],
        objective: str,
    ) -> RepromptDecision | None:
        if not records:
            return None

        latest = records[-1]
        if not latest.failed:
            return None

        streak = 0
        for record in reversed(records):
            if record.solver_id != latest.solver_id:
                break
            if not record.failed or record.mode is not latest.mode:
                break
            streak += 1

        if streak < self.failure_threshold:
            return None

        target = objective or latest.objective or self.base_prompt
        if streak >= self.max_attempts:
            action = RepromptAction.SKIP
            prompt = target
            reason = f"连续 {streak} 次 {latest.mode.value} 失败，已达到重试上限"
        elif self.policy is not None:
            action, prompt, reason = self._policy_action(latest.mode, target, streak)
        elif latest.mode is FailureMode.PARSE:
            action = RepromptAction.RETRY
            prompt = (
                f"重试目标：{target}\\n"
                "只输出一个 JSON 对象，不要 Markdown、解释或额外文本。"
                'Schema: {"success": boolean, "findings": array, "ideas": array, "error": string}。'
                " findings/ideas 内每项必须包含类型、证据和可复核位置。"
            )
            reason = "输出契约不足导致解析失败，使用严格 JSON 格式重试"
        elif latest.mode is FailureMode.TIMEOUT:
            action = RepromptAction.DECOMPOSE
            prompt = (
                f"将目标拆分为两个更小的只读检测步骤：{target}\\n"
                "每步只验证一个输入或一个端点，给出硬性时间预算。"
                "先输出可执行步骤，再输出每步的最小可观察结果。"
            )
            reason = "执行范围或时间预算过大，先分解再重派"
        else:
            action = RepromptAction.DECOMPOSE
            prompt = (
                f"当前目标连续 {streak} 次没有产生 findings 或 ideas：{target}\\n"
                "请先拆出最多 3 个更小的可观察对象，再为每个对象设计一条只读验证路径。"
                "每条路径必须定义成功判据、失败判据和可保存的输出字段。"
            )
            reason = "原提示词过宽且没有可观察边界，需要分解任务"

        return RepromptDecision(
            action=action,
            failure_mode=latest.mode,
            prompt=prompt,
            reason=reason,
            attempts=streak,
            solver_id=latest.solver_id,
            task_id=latest.task_id,
        )

    def _policy_action(
        self,
        mode: FailureMode,
        target: str,
        streak: int,
    ) -> tuple[RepromptAction, str, str]:
        """Select the next action from the configured recovery sequence."""

        assert self.policy is not None
        index = min(streak - self.failure_threshold, len(self.policy.sequence) - 1)
        action = self.policy.sequence[index]

        if action is RepromptAction.SKIP:
            return action, target, f"连续 {streak} 次 {mode.value} 失败，已达到重试上限"

        if action is RepromptAction.RETRY:
            if mode is FailureMode.PARSE:
                prompt = (
                    f"重试目标：{target}\\n"
                    "只输出一个 JSON 对象，不要 Markdown、解释或额外文本。"
                    'Schema: {"success": boolean, "findings": array, "ideas": array, "error": string}。'
                    " findings/ideas 内每项必须包含类型、证据和可复核位置。"
                )
                reason = "输出契约不足导致解析失败，使用严格 JSON 格式重试"
            else:
                prompt = (
                    f"重试目标：{target}\\n"
                    f"前一次执行触发 {mode.value} 失败，请重新执行并给出明确可验证结果。"
                )
                reason = f"{mode.value} 失败，按策略直接重试"
            return action, prompt, reason

        # DECOMPOSE
        if mode is FailureMode.TIMEOUT:
            prompt = (
                f"将目标拆分为两个更小的只读检测步骤：{target}\\n"
                "每步只验证一个输入或一个端点，给出硬性时间预算。"
                "先输出可执行步骤，再输出每步的最小可观察结果。"
            )
            reason = "执行范围或时间预算过大，先分解再重派"
        else:
            prompt = (
                f"当前目标连续 {streak} 次没有产生 findings 或 ideas：{target}\\n"
                "请先拆出最多 3 个更小的可观察对象，再为每个对象设计一条只读验证路径。"
                "每条路径必须定义成功判据、失败判据和可保存的输出字段。"
            )
            reason = "原提示词过宽且没有可观察边界，需要分解任务"
        return action, prompt, reason


class BlackboardAutoPromptMonitor:
    """Persist execution history on a Blackboard fact and return reprompt decisions."""

    HISTORY_FACT_KEY = "auto_prompt.failure_history"

    def __init__(self, blackboard: Blackboard, engine: AutoPromptEngine | None = None) -> None:
        self.blackboard = blackboard
        self.engine = engine or AutoPromptEngine()
        self._lock = threading.RLock()

    def record(self, result: SolverResult, objective: str = "") -> RepromptDecision | None:
        """Record one result on the blackboard and evaluate the full history."""

        record = FailureRecord.from_result(result, objective)
        with self._lock:
            history = self.read_history()
            history.append(record)
            self.blackboard.set_fact(self.HISTORY_FACT_KEY, history)
            return self.engine.evaluate_history(history, objective=objective)

    def read_history(self) -> list[FailureRecord]:
        value = self.blackboard.get_fact(self.HISTORY_FACT_KEY, [])
        if not isinstance(value, list):
            raise TypeError("auto-prompt blackboard history must be a list")

        history: list[FailureRecord] = []
        for item in value:
            if isinstance(item, FailureRecord):
                history.append(item)
            elif isinstance(item, SolverResult):
                history.append(FailureRecord.from_result(item))
            else:
                raise TypeError("auto-prompt history entries must be FailureRecord or SolverResult")
        return history
