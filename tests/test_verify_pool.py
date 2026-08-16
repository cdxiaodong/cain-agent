"""VerificationPool unit tests: parallel sessions, voting, and Blackboard state."""

from __future__ import annotations

import threading

import pytest

from cain_agent.multi_agent.blackboard import Blackboard
from cain_agent.multi_agent.types import Finding, SolverResult, SolverTask
from cain_agent.multi_agent.verify_pool import (
    ValidationConsensus,
    VerificationPool,
    VerificationSession,
    VerificationVerdict,
)


class StaticVerificationSession(VerificationSession):
    """Deterministic session used to exercise pool behavior without network access."""

    def __init__(
        self,
        solver_id: str,
        verdict: VerificationVerdict,
        *,
        barrier: threading.Barrier | None = None,
        error: Exception | None = None,
    ) -> None:
        super().__init__(solver_id)
        self.verdict = verdict
        self.barrier = barrier
        self.error = error
        self.received_findings: list[Finding] = []

    def verify(self, finding: Finding) -> VerificationVerdict:
        self.received_findings.append(finding)
        if self.barrier:
            self.barrier.wait(timeout=3)
        if self.error:
            raise self.error
        return self.verdict


class InvalidOutputSession(VerificationSession):
    """Returns an output that cannot be mapped to a verification verdict."""

    def verify(self, finding: Finding) -> VerificationVerdict:
        return VerificationVerdict.CONFIRMED

    def _run(self, task: SolverTask) -> SolverResult:
        return SolverResult(success=True, output="maybe")


class WrongFindingSession(VerificationSession):
    """Returns a valid verdict but associates it with another finding."""

    def verify(self, finding: Finding) -> VerificationVerdict:
        return VerificationVerdict.CONFIRMED

    def _run(self, task: SolverTask) -> SolverResult:
        return SolverResult(
            success=True,
            output='{"finding_id": "other-finding", "verdict": "confirmed"}',
        )


def _finding() -> Finding:
    return Finding(
        cloud="web",
        service="http",
        resource="http://example.com/api",
        issue_type="sqli",
        confirmed=False,
    )


def test_confirmed_majority_marks_finding_confirmed() -> None:
    blackboard = Blackboard()
    finding = _finding()
    blackboard.post_finding(finding, "discoverer")

    sessions = [
        StaticVerificationSession("verify-1", VerificationVerdict.CONFIRMED),
        StaticVerificationSession("verify-2", VerificationVerdict.CONFIRMED),
        StaticVerificationSession("verify-3", VerificationVerdict.REJECTED),
    ]
    report = VerificationPool(blackboard, sessions).verify_finding(finding)

    assert report.validation_consensus is ValidationConsensus.CONFIRMED
    assert report.confirmed is True
    assert report.disagreement is True
    assert report.vote_counts == {
        VerificationVerdict.CONFIRMED: 2,
        VerificationVerdict.REJECTED: 1,
        VerificationVerdict.INCONCLUSIVE: 0,
    }
    assert blackboard.read_findings() == [finding]
    assert finding.confirmed is True

    stored = blackboard.get_fact(f"validation:{finding.finding_id}")
    assert isinstance(stored, dict)
    assert stored["validation_consensus"] == "confirmed"
    assert stored["confirmed"] is True
    assert stored["disagreement"] is True


def test_rejected_majority_does_not_confirm_finding() -> None:
    blackboard = Blackboard()
    finding = _finding()
    blackboard.post_finding(finding, "discoverer")

    sessions = [
        StaticVerificationSession("verify-1", VerificationVerdict.REJECTED),
        StaticVerificationSession("verify-2", VerificationVerdict.REJECTED),
        StaticVerificationSession("verify-3", VerificationVerdict.INCONCLUSIVE),
    ]
    report = VerificationPool(blackboard, sessions).verify_finding(finding)

    assert report.validation_consensus is ValidationConsensus.REJECTED
    assert report.confirmed is False
    assert report.disagreement is False
    assert finding.confirmed is False


def test_tie_and_conflicting_votes_are_contested() -> None:
    sessions = [
        StaticVerificationSession("verify-1", VerificationVerdict.CONFIRMED),
        StaticVerificationSession("verify-2", VerificationVerdict.REJECTED),
    ]
    report = VerificationPool(Blackboard(), sessions).verify_finding(_finding())

    assert report.validation_consensus is ValidationConsensus.CONTESTED
    assert report.confirmed is False
    assert report.disagreement is True


def test_failed_sessions_are_inconclusive_not_rejections() -> None:
    sessions = [
        StaticVerificationSession("verify-1", VerificationVerdict.CONFIRMED),
        StaticVerificationSession("verify-2", VerificationVerdict.CONFIRMED),
        StaticVerificationSession(
            "verify-3", VerificationVerdict.REJECTED, error=RuntimeError("session failed")
        ),
    ]
    report = VerificationPool(None, sessions).verify_finding(_finding())

    assert report.validation_consensus is ValidationConsensus.CONFIRMED
    assert report.vote_counts[VerificationVerdict.INCONCLUSIVE] == 1
    assert report.votes[2].error == "session failed"


def test_invalid_session_output_is_inconclusive() -> None:
    sessions = [
        InvalidOutputSession("verify-1"),
        StaticVerificationSession("verify-2", VerificationVerdict.CONFIRMED),
    ]
    report = VerificationPool(None, sessions).verify_finding(_finding())

    assert report.validation_consensus is ValidationConsensus.CONTESTED
    assert report.votes[0].verdict is VerificationVerdict.INCONCLUSIVE
    assert report.votes[0].error == "invalid verdict output"


def test_verdict_for_wrong_finding_is_inconclusive() -> None:
    sessions = [
        WrongFindingSession("verify-1"),
        StaticVerificationSession("verify-2", VerificationVerdict.CONFIRMED),
    ]
    report = VerificationPool(None, sessions).verify_finding(_finding())

    assert report.votes[0].verdict is VerificationVerdict.INCONCLUSIVE
    assert report.validation_consensus is ValidationConsensus.CONTESTED


def test_sessions_run_concurrently_with_separate_tasks() -> None:
    barrier = threading.Barrier(3)
    finding = _finding()
    sessions = [
        StaticVerificationSession(
            f"verify-{index}", VerificationVerdict.CONFIRMED, barrier=barrier
        )
        for index in range(3)
    ]
    report = VerificationPool(None, sessions, max_workers=3).verify_finding(finding)

    assert report.validation_consensus is ValidationConsensus.CONFIRMED
    assert [session.received_findings for session in sessions] == [[finding]] * 3
    assert len({id(session.current_task) for session in sessions}) == 3


def test_pool_requires_distinct_independent_sessions() -> None:
    session = StaticVerificationSession("verify-1", VerificationVerdict.CONFIRMED)
    with pytest.raises(ValueError, match="separate Solver instances"):
        VerificationPool(None, [session, session])

    with pytest.raises(ValueError, match="at least two"):
        VerificationPool(None, [session])
