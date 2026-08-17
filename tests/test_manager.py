"""PentestManager 判断聚合测试：Solver finding + 验证池表决 + 语义记忆 → 置信度结论。

覆盖：共识映射、置信度区间、依据链内容、记忆旁证排序、序列化与排序规则。
"""

from __future__ import annotations

import pytest

from cain_agent.multi_agent.blackboard import Blackboard
from cain_agent.multi_agent.manager import PentestManager
from cain_agent.multi_agent.types import Finding, Severity
from cain_agent.multi_agent.verify_pool import (
    ValidationConsensus,
    VerificationPool,
    VerificationSession,
    VerificationVerdict,
)


class StaticVerificationSession(VerificationSession):
    """确定性验证会话：固定返回指定表决。"""

    def __init__(self, solver_id: str, verdict: VerificationVerdict) -> None:
        super().__init__(solver_id)
        self.verdict = verdict

    def verify(self, finding: Finding) -> VerificationVerdict:
        return self.verdict


def _finding(**overrides: object) -> Finding:
    kwargs: dict[str, object] = {
        "cloud": "web",
        "service": "http",
        "resource": "https://example.com/login",
        "issue_type": "sqli",
        "severity": Severity.HIGH,
        "detail": "SQL injection in login parameter",
    }
    kwargs.update(overrides)
    return Finding(**kwargs)  # type: ignore[arg-type]


def _pool(*verdicts: VerificationVerdict) -> VerificationPool:
    sessions = [
        StaticVerificationSession(f"verify-{index}", verdict)
        for index, verdict in enumerate(verdicts)
    ]
    return VerificationPool(None, sessions)


def test_aggregate_no_findings_returns_empty() -> None:
    manager = PentestManager(Blackboard())

    assert manager.aggregate_findings() == []


def test_aggregate_confirmed_finding_high_confidence() -> None:
    blackboard = Blackboard()
    finding = _finding()
    blackboard.post_finding(finding, "solver-a")
    manager = PentestManager(blackboard)

    conclusions = manager.aggregate_findings(
        _pool(
            VerificationVerdict.CONFIRMED,
            VerificationVerdict.CONFIRMED,
            VerificationVerdict.REJECTED,
        )
    )

    assert len(conclusions) == 1
    conclusion = conclusions[0]
    assert conclusion.consensus is ValidationConsensus.CONFIRMED
    assert conclusion.confidence >= 0.8
    assert finding.confirmed is True

    sources = [link.source for link in conclusion.evidence_chain]
    assert "solver" in sources
    assert "verification" in sources

    verdict_links = [
        link for link in conclusion.evidence_chain if link.source == "verification"
    ]
    assert "confirmed=2" in verdict_links[0].detail


def test_aggregate_rejected_finding_low_confidence() -> None:
    blackboard = Blackboard()
    finding = _finding()
    blackboard.post_finding(finding, "solver-a")
    manager = PentestManager(blackboard)

    conclusion = manager.aggregate_findings(
        _pool(
            VerificationVerdict.REJECTED,
            VerificationVerdict.REJECTED,
            VerificationVerdict.INCONCLUSIVE,
        )
    )[0]

    assert conclusion.consensus is ValidationConsensus.REJECTED
    assert conclusion.confidence <= 0.25
    assert finding.confirmed is False


def test_aggregate_contested_finding_mid_confidence() -> None:
    blackboard = Blackboard()
    finding = _finding()
    blackboard.post_finding(finding, "solver-a")
    manager = PentestManager(blackboard)

    conclusion = manager.aggregate_findings(
        _pool(
            VerificationVerdict.CONFIRMED,
            VerificationVerdict.REJECTED,
        )
    )[0]

    assert conclusion.consensus is ValidationConsensus.CONTESTED
    assert 0.35 <= conclusion.confidence <= 0.60
    assert finding.confirmed is False


def test_unverified_finding_gets_moderate_confidence() -> None:
    blackboard = Blackboard()
    blackboard.post_finding(_finding(), "solver-a")
    manager = PentestManager(blackboard)

    conclusion = manager.aggregate_findings()[0]

    assert conclusion.consensus is None
    assert conclusion.confidence == 0.40
    assert any(link.source == "verification" for link in conclusion.evidence_chain)


def test_confidence_capped_at_upper_bound_with_memory_support() -> None:
    blackboard = Blackboard()
    # 两个完全一致的 finding → 记忆相似度恒为 1.0
    blackboard.post_finding(_finding(), "solver-a")
    blackboard.post_finding(_finding(), "solver-b")
    manager = PentestManager(blackboard)

    conclusions = manager.aggregate_findings(
        _pool(
            VerificationVerdict.CONFIRMED,
            VerificationVerdict.CONFIRMED,
            VerificationVerdict.CONFIRMED,
        )
    )

    assert len(conclusions) == 2
    for conclusion in conclusions:
        assert conclusion.confidence == 0.95
        assert conclusion.confidence <= 0.95


def test_aggregate_memory_similarity_ranks_related_finding_first() -> None:
    blackboard = Blackboard()
    target = _finding(resource="https://example.com/login")
    similar = _finding(resource="https://example.com/api/login")
    unrelated = _finding(
        resource="https://example.com/upload",
        issue_type="file-upload",
        severity=Severity.CRITICAL,
        detail="Unrestricted file upload",
    )
    blackboard.post_finding(target, "solver-a")
    blackboard.post_finding(similar, "solver-b")
    blackboard.post_finding(unrelated, "solver-c")
    manager = PentestManager(blackboard)

    conclusions = manager.aggregate_findings()
    by_id = {conclusion.finding_id: conclusion for conclusion in conclusions}

    target_conclusion = by_id[target.finding_id]
    assert len(target_conclusion.memory_hits) == 2
    assert target_conclusion.memory_hits[0].record.payload is similar
    assert target_conclusion.memory_hits[0].score > target_conclusion.memory_hits[1].score

    memory_links = [
        link for link in target_conclusion.evidence_chain if link.source == "memory"
    ]
    assert memory_links, "结论依据链应包含语义记忆旁证"
    assert "similar" in memory_links[0].detail or "finding" in memory_links[0].detail

    # 语义支撑强的结论置信度高于支撑弱的
    unrelated_conclusion = by_id[unrelated.finding_id]
    assert target_conclusion.confidence > unrelated_conclusion.confidence


def test_aggregate_excludes_finding_itself_from_memory_hits() -> None:
    blackboard = Blackboard()
    finding = _finding()
    blackboard.post_finding(finding, "solver-a")
    manager = PentestManager(blackboard)

    conclusion = manager.aggregate_findings()[0]

    assert conclusion.memory_hits == ()
    assert all(hit.record.payload is not finding for hit in conclusion.memory_hits)


def test_aggregate_reuses_stored_validation_fact() -> None:
    blackboard = Blackboard()
    finding = _finding()
    blackboard.post_finding(finding, "solver-a")
    blackboard.set_fact(
        f"validation:{finding.finding_id}",
        {
            "validation_consensus": "confirmed",
            "confirmed": True,
            "disagreement": False,
            "vote_counts": {"confirmed": 2, "rejected": 0, "inconclusive": 0},
        },
    )
    manager = PentestManager(blackboard)

    conclusion = manager.aggregate_findings()[0]

    assert conclusion.consensus is ValidationConsensus.CONFIRMED
    assert conclusion.confidence >= 0.8
    assert finding.confirmed is True
    verification_links = [
        link for link in conclusion.evidence_chain if link.source == "verification"
    ]
    assert "复用已存表决" in verification_links[0].detail


def test_aggregate_sorts_confirmed_findings_first() -> None:
    blackboard = Blackboard()
    confirmed = _finding(resource="https://example.com/a", issue_type="sqli")
    confirmed.confirmed = True
    unconfirmed = _finding(resource="https://example.com/b", issue_type="rce")
    blackboard.post_finding(confirmed, "solver-a")
    blackboard.post_finding(unconfirmed, "solver-b")
    manager = PentestManager(blackboard)

    conclusions = manager.aggregate_findings()

    assert [conclusion.finding_id for conclusion in conclusions] == [
        confirmed.finding_id,
        unconfirmed.finding_id,
    ]


def test_to_dict_serializes_for_report() -> None:
    blackboard = Blackboard()
    finding = _finding()
    blackboard.post_finding(finding, "solver-a")
    blackboard.set_fact("recon:example.com", {"stack": "nginx"})
    manager = PentestManager(blackboard)

    data = manager.aggregate_findings()[0].to_dict()

    assert data["finding_id"] == finding.finding_id
    assert 0.35 <= data["confidence"] <= 0.60
    assert data["consensus"] is None
    assert data["finding"]["severity"] == "high"
    assert data["finding"]["issue_type"] == "sqli"
    assert data["finding"]["confirmed"] is False
    assert isinstance(data["evidence_chain"], list)
    assert all(link["source"] for link in data["evidence_chain"])
    assert isinstance(data["memory_hits"], list)


def test_aggregate_validates_arguments() -> None:
    manager = PentestManager(Blackboard())

    with pytest.raises(ValueError, match="top_k"):
        manager.aggregate_findings(top_k=0)
    with pytest.raises(ValueError, match="min_score"):
        manager.aggregate_findings(min_score=1.1)


def test_conclusion_types_are_exported() -> None:
    from cain_agent.multi_agent import EvidenceLink, ManagerConclusion

    assert issubclass(ManagerConclusion, object)
    assert issubclass(EvidenceLink, object)