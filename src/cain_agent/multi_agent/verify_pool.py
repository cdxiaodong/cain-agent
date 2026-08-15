"""Parallel finding verification pool.

The pool dispatches one independent verification session per solver instance and
reduces their structured votes to a consensus. It is intentionally logic-only:
sessions decide how to inspect evidence, while this module never touches a target.
"""

from __future__ import annotations

import json
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from cain_agent.multi_agent.solver import BaseSolver
from cain_agent.multi_agent.types import Finding, SolverResult, SolverTask

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cain_agent.multi_agent.blackboard import Blackboard


class VerificationVerdict(StrEnum):
    """Verdict returned by one independent verification session."""

    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class ValidationConsensus(StrEnum):
    """Consensus derived from all verification sessions."""

    CONFIRMED = "confirmed"
    CONTESTED = "contested"
    REJECTED = "rejected"


@dataclass(frozen=True)
class VerificationVote:
    """One session's parsed verdict."""

    session_id: str
    task_id: str
    verdict: VerificationVerdict
    error: str = ""


@dataclass(frozen=True)
class VerificationReport:
    """Aggregated result for one candidate finding."""

    finding_id: str
    validation_consensus: ValidationConsensus
    votes: tuple[VerificationVote, ...]
    vote_counts: dict[VerificationVerdict, int]
    disagreement: bool

    @property
    def confirmed(self) -> bool:
        return self.validation_consensus is ValidationConsensus.CONFIRMED

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "validation_consensus": self.validation_consensus.value,
            "confirmed": self.confirmed,
            "disagreement": self.disagreement,
            "vote_counts": {
                verdict.value: self.vote_counts[verdict]
                for verdict in VerificationVerdict
            },
            "votes": [
                {
                    "session_id": vote.session_id,
                    "task_id": vote.task_id,
                    "verdict": vote.verdict.value,
                    "error": vote.error,
                }
                for vote in self.votes
            ],
        }


class VerificationSession(BaseSolver):
    """A verification-only Solver that emits one structured verdict.

    Subclasses implement ``verify``. The returned verdict is serialized in
    ``SolverResult.output`` so a verification vote is never mistaken for a new
    Finding and never pollutes the Blackboard's finding list.
    """

    def capability(self) -> str:
        return "verification"

    def _run(self, task: SolverTask) -> SolverResult:
        finding = task.context.get("finding")
        if not isinstance(finding, Finding):
            raise TypeError("verification task context must contain the candidate Finding")

        verdict = self.verify(finding)
        return SolverResult(
            success=True,
            output=json.dumps(
                {
                    "finding_id": finding.finding_id,
                    "verdict": verdict.value,
                },
                ensure_ascii=False,
            ),
        )

    @abstractmethod
    def verify(self, finding: Finding) -> VerificationVerdict:
        """Return one independent verdict for ``finding``."""


class VerificationPool:
    """Run independent verification sessions concurrently and vote on a finding."""

    def __init__(
        self,
        blackboard: Blackboard | None,
        sessions: Sequence[VerificationSession],
        *,
        max_workers: int | None = None,
    ) -> None:
        if len(sessions) < 2:
            raise ValueError("at least two independent verification sessions are required")
        if len({id(session) for session in sessions}) != len(sessions):
            raise ValueError("verification sessions must be separate Solver instances")
        if len({session.solver_id for session in sessions}) != len(sessions):
            raise ValueError("verification session ids must be unique")

        self.blackboard = blackboard
        self.sessions = tuple(sessions)
        if max_workers is not None and max_workers < 1:
            raise ValueError("max_workers must be positive")
        self.max_workers = min(max_workers or len(self.sessions), len(self.sessions))
        if self.max_workers < 1:
            raise ValueError("max_workers must be positive")

    def verify_finding(self, finding: Finding) -> VerificationReport:
        """Verify one finding and publish the aggregate result to the Blackboard."""
        futures = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for index, session in enumerate(self.sessions):
                task = self._build_task(finding, index)
                futures[executor.submit(session.execute, task)] = (index, task)

            raw_results: list[SolverResult | None] = [None] * len(self.sessions)
            for future in as_completed(futures):
                index, task = futures[future]
                try:
                    raw_results[index] = future.result()
                except Exception as exc:  # noqa: BLE001
                    raw_results[index] = SolverResult(
                        task_id=task.task_id,
                        solver_id=self.sessions[index].solver_id,
                        success=False,
                        error=str(exc),
                    )

        votes = tuple(
            self._vote_from_result(self.sessions[index], result, finding.finding_id)
            for index, result in enumerate(raw_results)
        )
        report = self._build_report(finding.finding_id, votes)
        if self.blackboard:
            self.blackboard.set_fact(f"validation:{finding.finding_id}", report.to_dict())
            if report.confirmed:
                self.blackboard.confirm_finding(finding.finding_id)
        return report

    def _build_task(self, finding: Finding, session_index: int) -> SolverTask:
        return SolverTask(
            objective=f"independently verify finding {finding.finding_id}",
            scope=[finding.resource] if finding.resource else [],
            constraints=["readonly"],
            context={
                "capability": "verification",
                "finding": finding,
                "finding_id": finding.finding_id,
                "session_index": session_index,
            },
        )

    def _vote_from_result(
        self,
        session: VerificationSession,
        result: SolverResult | None,
        finding_id: str,
    ) -> VerificationVote:
        if result is None:
            return VerificationVote(
                session_id=session.solver_id,
                task_id="",
                verdict=VerificationVerdict.INCONCLUSIVE,
                error="verification session returned no result",
            )

        if not result.success or result.error:
            return VerificationVote(
                session_id=result.solver_id or session.solver_id,
                task_id=result.task_id,
                verdict=VerificationVerdict.INCONCLUSIVE,
                error=result.error or "verification session failed",
            )

        verdict = self._parse_verdict(result.output, finding_id)
        return VerificationVote(
            session_id=result.solver_id or session.solver_id,
            task_id=result.task_id,
            verdict=verdict,
            error="" if verdict is not VerificationVerdict.INCONCLUSIVE else "invalid verdict output",
        )

    @staticmethod
    def _parse_verdict(output: str, finding_id: str) -> VerificationVerdict:
        try:
            payload = json.loads(output)
        except (TypeError, json.JSONDecodeError):
            payload = output.strip().lower()

        if isinstance(payload, dict):
            if payload.get("finding_id") != finding_id:
                return VerificationVerdict.INCONCLUSIVE
            value = payload.get("verdict")
        else:
            value = payload
        if isinstance(value, str):
            try:
                return VerificationVerdict(value.strip().lower())
            except ValueError:
                return VerificationVerdict.INCONCLUSIVE
        return VerificationVerdict.INCONCLUSIVE

    @staticmethod
    def _build_report(finding_id: str, votes: tuple[VerificationVote, ...]) -> VerificationReport:
        counts = {verdict: 0 for verdict in VerificationVerdict}
        for vote in votes:
            counts[vote.verdict] += 1

        # A majority is over half of all sessions, not merely over decisive votes.
        # Failed sessions therefore cannot accidentally turn rejection into consensus.
        total = len(votes)
        if counts[VerificationVerdict.CONFIRMED] * 2 > total:
            consensus = ValidationConsensus.CONFIRMED
        elif counts[VerificationVerdict.REJECTED] * 2 > total:
            consensus = ValidationConsensus.REJECTED
        else:
            consensus = ValidationConsensus.CONTESTED

        disagreement = (
            counts[VerificationVerdict.CONFIRMED] > 0
            and counts[VerificationVerdict.REJECTED] > 0
        )
        return VerificationReport(
            finding_id=finding_id,
            validation_consensus=consensus,
            votes=votes,
            vote_counts=counts,
            disagreement=disagreement,
        )


# Short alias for call sites that prefer the feature name over the domain noun.
VerifyPool = VerificationPool
