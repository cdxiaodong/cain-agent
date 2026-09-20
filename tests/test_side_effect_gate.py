"""Phase 5-A3 confirm 副作用门测试 — 第五状态/降档/兼容(零触网)。"""

from __future__ import annotations

import pytest

from cain_agent.findings import Finding, FindingError, FindingResult, Severity, hash_evidence


def _finding(**over: object) -> Finding:
    kwargs: dict[str, object] = {
        "finding_id": "f-a3",
        "result": FindingResult.VALIDATION_INCONCLUSIVE,
        "severity": Severity.HIGH,
        "evidence_hash": hash_evidence("ev"),
        "reason": "r",
        "cloud": "web",
        "service": "http",
        "resource": "http://e.com/x",
        "issue_type": "sqli",
    }
    kwargs.update(over)
    return Finding(**kwargs)  # type: ignore[arg-type]


# -- 枚举与字段 ----------------------------------------------------------------------


def test_fifth_state_exists_and_serializes() -> None:
    assert FindingResult.LIKELY.value == "likely"
    f = _finding(result=FindingResult.LIKELY)
    assert f.to_dict()["result"] == "likely"
    assert Finding.from_dict(f.to_dict()).result is FindingResult.LIKELY


def test_side_effect_evidence_roundtrip_and_none_default() -> None:
    f = _finding(side_effect_evidence="只读探测,响应 200 无状态变化")
    d = f.to_dict()
    assert d["side_effect_evidence"].startswith("只读")
    assert Finding.from_dict(d).side_effect_evidence == "只读探测,响应 200 无状态变化"
    assert "side_effect_evidence" not in _finding().to_dict()  # 缺省不输出


def test_old_dict_without_field_loads() -> None:
    d = _finding().to_dict()
    assert Finding.from_dict(d).side_effect_evidence is None


def test_blank_side_effect_evidence_rejected() -> None:
    with pytest.raises(FindingError):
        _finding(side_effect_evidence="   ")


def test_non_string_side_effect_rejected() -> None:
    with pytest.raises(FindingError):
        _finding(side_effect_evidence=1)  # type: ignore[arg-type]


# -- 降档(纯函数层,复用 pipeline 内部) ----------------------------------------------


def _pool_report(consensus, votes):  # type: ignore[no-untyped-def]
    from cain_agent.multi_agent.verify_pool import VerificationReport, VerificationVerdict

    counts = {v: 0 for v in VerificationVerdict}
    for vote in votes:
        counts[vote.verdict] += 1
    return VerificationReport(
        finding_id="f-a3",
        validation_consensus=consensus,
        votes=votes,
        vote_counts=counts,
        disagreement=False,
    )


def _votes(n: int, verdict) -> list:  # type: ignore[no-untyped-def]
    from cain_agent.multi_agent.verify_pool import VerificationVote

    return [
        VerificationVote(session_id=f"v{i}", task_id="t", verdict=verdict)
        for i in range(n)
    ]


def test_gate_off_keeps_confirmed_for_old_data() -> None:
    """缺省关:无副作用证据的多数 confirmed 保持 confirmed(零变化)。"""
    from cain_agent.multi_agent.verify_pool import ValidationConsensus, VerificationVerdict
    from cain_agent.pipeline import _apply_pool_report

    out = _apply_pool_report(
        _finding(),  # 无 side_effect_evidence
        _pool_report(ValidationConsensus.CONFIRMED,
                     _votes(3, VerificationVerdict.CONFIRMED)),
    )
    assert out.result is FindingResult.CONFIRMED


def test_gate_on_demotes_without_side_effect() -> None:
    from cain_agent.multi_agent.verify_pool import ValidationConsensus, VerificationVerdict
    from cain_agent.pipeline import _apply_pool_report

    out = _apply_pool_report(
        _finding(),
        _pool_report(ValidationConsensus.CONFIRMED,
                     _votes(3, VerificationVerdict.CONFIRMED)),
        side_effect_gate=True,
    )
    assert out.result is FindingResult.LIKELY
    assert "副作用" in out.reason


def test_gate_on_keeps_confirmed_with_side_effect() -> None:
    from cain_agent.multi_agent.verify_pool import ValidationConsensus, VerificationVerdict
    from cain_agent.pipeline import _apply_pool_report

    out = _apply_pool_report(
        _finding(side_effect_evidence="sha256:" + "b" * 64),
        _pool_report(ValidationConsensus.CONFIRMED,
                     _votes(3, VerificationVerdict.CONFIRMED)),
        side_effect_gate=True,
    )
    assert out.result is FindingResult.CONFIRMED


def test_gate_never_touches_rejected_or_inconclusive() -> None:
    from cain_agent.multi_agent.verify_pool import (
        ValidationConsensus,
        VerificationVerdict,
    )
    from cain_agent.pipeline import _apply_pool_report

    out = _apply_pool_report(
        _finding(),
        _pool_report(ValidationConsensus.REJECTED, _votes(3, VerificationVerdict.REJECTED)),
        side_effect_gate=True,
    )
    assert out.result is FindingResult.FALSE_POSITIVE
    out2 = _apply_pool_report(
        _finding(),
        _pool_report(ValidationConsensus.CONTESTED,
                     _votes(1, VerificationVerdict.CONFIRMED)),
        side_effect_gate=True,
    )
    assert out2.result is FindingResult.VALIDATION_INCONCLUSIVE


# -- 报告呈现 ------------------------------------------------------------------------


def test_report_renders_likely_label() -> None:
    from cain_agent.report_markdown import render_report_markdown
    from tests.test_report_trust_boundary import _META, _report

    md = render_report_markdown(
        _report([{"finding_id": "f-x", "result": "likely", "severity": "high",
                  "evidence_hash": hash_evidence("h"), "resource": "u",
                  "issue_type": "sqli"}]),
        _META,
    )
    assert "很可能" in md and "副作用" in md
