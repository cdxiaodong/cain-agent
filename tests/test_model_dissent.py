"""Phase 5-A4 分歧呈现测试 — 少数派理由收集/redact/报告渲染(零触网)。"""

from __future__ import annotations

from cain_agent.executor import ExecutorResult, SDKExecutor
from cain_agent.multi_agent.verify_pool import (
    ValidationConsensus,
    VerificationVerdict,
    VerificationVote,
)
from cain_agent.report_markdown import render_report_markdown

# 既有报告测试的构造器复用
from tests.test_report_trust_boundary import _META, _conclusion, _report

_CANARY = "Bearer AKIDISSENTCANARY88XYZQ"


def _vote(sid: str, verdict: VerificationVerdict, reason: str = "") -> VerificationVote:
    return VerificationVote(session_id=sid, task_id="t", verdict=verdict, reason=reason)


# -- dissent 计算(用 VerificationReport) ------------------------------------------


def _report_obj(votes, consensus):
    from cain_agent.multi_agent.verify_pool import VerificationReport

    counts = {v: 0 for v in VerificationVerdict}
    for vote in votes:
        counts[vote.verdict] += 1
    return VerificationReport(
        finding_id="f1",
        validation_consensus=consensus,
        votes=votes,
        vote_counts=counts,
        disagreement=any(v.verdict is not votes[0].verdict for v in votes),
    )


def test_minority_votes_collected_with_reason() -> None:
    r = _report_obj(
        [
            _vote("v1", VerificationVerdict.CONFIRMED),
            _vote("v2", VerificationVerdict.REJECTED, "哈希与资源不符"),
            _vote("v3", VerificationVerdict.CONFIRMED),
        ],
        ValidationConsensus.CONFIRMED,
    )
    d = r.dissent()
    assert d == [{"voter": "v2", "verdict": "rejected", "reason": "哈希与资源不符"}]
    assert r.to_dict()["dissent"] == d


def test_unanimous_has_no_dissent() -> None:
    r = _report_obj(
        [_vote("v1", VerificationVerdict.CONFIRMED), _vote("v2", VerificationVerdict.CONFIRMED)],
        ValidationConsensus.CONFIRMED,
    )
    assert r.dissent() == []


def test_contested_all_votes_are_dissent() -> None:
    r = _report_obj(
        [_vote("v1", VerificationVerdict.CONFIRMED), _vote("v2", VerificationVerdict.REJECTED)],
        ValidationConsensus.CONTESTED,
    )
    assert len(r.dissent()) == 2


def test_votes_to_dict_includes_reason() -> None:
    r = _report_obj([_vote("v1", VerificationVerdict.REJECTED, "证据不足")],
                    ValidationConsensus.REJECTED)
    assert r.to_dict()["votes"][0]["reason"] == "证据不足"


# -- 会话 reason 解析与 redact --------------------------------------------------------


class FakeVerifyExecutor(SDKExecutor):
    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text

    async def run(self, prompt: str) -> ExecutorResult:
        return ExecutorResult(text=self._text)


def test_session_reason_parsed_and_redacted() -> None:
    import json

    from cain_agent.multi_agent.orchestration import ExecutorVerificationSession
    from cain_agent.multi_agent.types import Finding, Severity

    f = Finding(
        cloud="web", service="http", resource="http://e.com/x", issue_type="sqli",
        severity=Severity.HIGH, detail="d",
        evidence={"evidence_hash": "sha256:" + "a" * 64}, confirmed=False,
        finding_id="f1",
    )
    payload = json.dumps(
        {"verdict": "rejected", "reason": f"令牌 {_CANARY} 与哈希不符"}
    )
    session = ExecutorVerificationSession("v1", FakeVerifyExecutor(payload))
    verdict = session.verify(f)
    assert verdict is VerificationVerdict.REJECTED
    assert _CANARY not in session.last_reason  # redact 生效
    assert "<REDACTED" in session.last_reason or session.last_reason == ""


def test_session_no_reason_leaves_empty() -> None:
    import json

    from cain_agent.multi_agent.orchestration import ExecutorVerificationSession
    from cain_agent.multi_agent.types import Finding, Severity

    f = Finding(
        cloud="web", service="http", resource="u", issue_type="sqli",
        severity=Severity.LOW, detail="d", evidence={}, confirmed=False, finding_id="f2",
    )
    session = ExecutorVerificationSession(
        "v1", FakeVerifyExecutor(json.dumps({"verdict": "confirmed"}))
    )
    session.verify(f)
    assert session.last_reason == ""


# -- 报告渲染 ------------------------------------------------------------------------


def test_report_renders_dissent_block() -> None:
    md = render_report_markdown(
        _report([
            _conclusion(model_dissent=[
                {"voter": "verify-2", "verdict": "rejected", "reason": "证据哈希不匹配"}
            ])
        ]),
        _META,
    )
    assert "分歧意见" in md and "verify-2" in md and "证据哈希不匹配" in md


def test_report_no_dissent_block_when_empty() -> None:
    md = render_report_markdown(_report([_conclusion()]), _META)
    assert "分歧意见" not in md


def test_old_conclusions_without_field_compatible() -> None:
    md = render_report_markdown(_report([_conclusion()]), _META)
    assert "## 法律声明" in md  # 兼容:无字段不炸
