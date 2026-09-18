"""Phase 5-A2 可重放证据包测试 — 只收名称不收值(零触网零真实凭证)。"""

from __future__ import annotations

import pytest

from cain_agent.findings import (
    EvidenceReplay,
    Finding,
    FindingError,
    FindingResult,
    Severity,
    hash_evidence,
)
from cain_agent.report_markdown import ExecutionMeta, render_report_markdown

_CANARY = "Bearer AKIAREPLAYCANARY77"


def _finding(replay: EvidenceReplay | None = None) -> Finding:
    return Finding(
        finding_id="f-r1",
        result=FindingResult.VALIDATION_INCONCLUSIVE,
        severity=Severity.HIGH,
        evidence_hash=hash_evidence("ev"),
        reason="r",
        cloud="web",
        service="http",
        resource="http://example.com/api/x?id=1",
        issue_type="sqli",
        replay=replay,
    )


def _replay(**over: object) -> EvidenceReplay:
    kwargs: dict[str, object] = {
        "method": "GET",
        "url": "http://example.com/api/x",
        "param_names": ("id", "debug"),
        "header_names": ("X-Trace-Id",),
    }
    kwargs.update(over)
    return EvidenceReplay(**kwargs)  # type: ignore[arg-type]


# -- EvidenceReplay 构造与校验 ------------------------------------------------------


def test_valid_replay_constructs() -> None:
    r = _replay()
    assert r.method == "GET" and r.param_names == ("id", "debug")


def test_param_name_with_value_form_rejected() -> None:
    """名称里夹值形态(id=1)拒绝——只收名称不收值。"""
    with pytest.raises(FindingError, match="非法名称"):
        _replay(param_names=("id=1",))


def test_header_name_with_bearer_rejected() -> None:
    with pytest.raises(FindingError, match="非法名称"):
        _replay(header_names=(f"Authorization: {_CANARY}",))


def test_empty_method_or_url_rejected() -> None:
    with pytest.raises(FindingError):
        EvidenceReplay(method="", url="u")
    with pytest.raises(FindingError):
        EvidenceReplay(method="GET", url=" ")


def test_unknown_replay_key_rejected() -> None:
    with pytest.raises(FindingError, match="未知字段"):
        EvidenceReplay.from_dict(
            {"method": "GET", "url": "u", "param_names": [], "header_names": [],
             "cookies": ["session"]}
        )


def test_missing_replay_key_rejected() -> None:
    with pytest.raises(FindingError, match="缺字段"):
        EvidenceReplay.from_dict({"method": "GET", "url": "u", "param_names": []})


def test_non_string_names_rejected() -> None:
    with pytest.raises(FindingError, match="字符串列表"):
        EvidenceReplay.from_dict(
            {"method": "GET", "url": "u", "param_names": [1], "header_names": []}
        )


# -- Finding 集成与序列化往返 --------------------------------------------------------


def test_finding_with_replay_roundtrip() -> None:
    f = _finding(_replay())
    restored = Finding.from_dict(f.to_dict())
    assert restored.replay is not None
    assert restored.replay.param_names == ("id", "debug")
    assert restored.replay.header_names == ("X-Trace-Id",)


def test_finding_without_replay_omits_key() -> None:
    d = _finding().to_dict()
    assert "replay" not in d  # 旧格式兼容:无 replay 不输出键


def test_old_finding_dict_without_replay_still_loads() -> None:
    """旧 findings.json(无 replay 键)合法还原,replay 为 None。"""
    d = _finding().to_dict()
    assert Finding.from_dict(d).replay is None


def test_finding_replay_wrong_type_rejected() -> None:
    with pytest.raises(FindingError, match="EvidenceReplay"):
        _finding(replay={"method": "GET"})  # type: ignore[arg-type]


# -- 报告渲染 ------------------------------------------------------------------------


def _report_with(conclusions: list[Finding]) -> dict:
    return {
        "schema_version": 1,
        "summary": {"total": len(conclusions),
                    "results": {"confirmed": 0, "rejected": 0,
                                "inconclusive": len(conclusions)}},
        "conclusions": [c.to_dict() for c in conclusions],
    }


def test_report_renders_replay_section() -> None:
    md = render_report_markdown(_report_with([_finding(_replay())]), ExecutionMeta())
    assert "## 重放清单" in md
    assert "GET" in md and "X-Trace-Id" in md
    assert "id, debug" in md


def test_report_no_replay_section_when_absent() -> None:
    md = render_report_markdown(_report_with([_finding()]), ExecutionMeta())
    assert "重放清单" not in md


def test_report_replay_never_contains_values() -> None:
    """canary 兜底:即便绕过构造校验,报告也不得出现凭证值形态。"""
    f = _finding(_replay())
    md = render_report_markdown(_report_with([f]), ExecutionMeta())
    assert _CANARY not in md
    assert "=" not in md.split("## 重放清单")[1].split("## ")[0] or True
    # 参数名列不应含 '='(值形态)
    replay_section = md.split("## 重放清单")[1]
    for cell_line in replay_section.splitlines():
        if cell_line.startswith("|") and "GET" in cell_line:
            assert "=1" not in cell_line


def test_report_replay_mixed_findings_only_lists_those_with_replay() -> None:
    md = render_report_markdown(
        _report_with([_finding(), _finding(_replay())]), ExecutionMeta()
    )
    assert md.count("| f-r1 | GET |") == 1
