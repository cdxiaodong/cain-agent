"""tests for cain_agent.findings —— 纯逻辑零触网。

覆盖派活单自测清单:四状态枚举非法值拒绝、reason 超长拒绝、四元组归一化
去重(大小写/空白变体判同)、规则表优先级、无命中时降级取低、JSON
round-trip(含与 Workspace findings.json 的读写兼容)。
"""

from __future__ import annotations

import json

import pytest

from cain_agent.findings import (
    SEVERITY_RULES,
    Finding,
    FindingError,
    FindingResult,
    Severity,
    classify,
    dedup,
    fingerprint,
    hash_evidence,
)
from cain_agent.workspace import Workspace

_HASH = hash_evidence("GET /bucket/ 200 OK")


def make_finding(**overrides: object) -> Finding:
    """构造一条合法 Finding,按需覆盖字段。"""
    base: dict[str, object] = {
        "finding_id": "aliyun-oss-public-bucket-001",
        "result": "confirmed",
        "severity": "high",
        "evidence_hash": _HASH,
        "reason": "匿名列举对象成功",
        "cloud": "aliyun",
        "service": "oss",
        "resource": "bucket-001",
        "issue_type": "public-read",
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


# -- Finding 数据类校验 --------------------------------------------------------
class TestFindingValidation:
    def test_result_accepts_all_four_states(self) -> None:
        for state in (
            "confirmed",
            "false_positive",
            "validation_system_error",
            "validation_inconclusive",
        ):
            assert make_finding(result=state).result is FindingResult(state)

    def test_result_rejects_illegal_value(self) -> None:
        with pytest.raises(FindingError, match="result 非法值"):
            make_finding(result="maybe")

    def test_severity_rejects_illegal_value(self) -> None:
        with pytest.raises(FindingError, match="severity 非法值"):
            make_finding(severity="fatal")

    def test_reason_over_limit_rejected(self) -> None:
        with pytest.raises(FindingError, match="reason 超长"):
            make_finding(reason="超" * 31)

    def test_reason_at_limit_accepted(self) -> None:
        assert len(make_finding(reason="满" * 30).reason) == 30

    def test_reason_empty_rejected(self) -> None:
        with pytest.raises(FindingError, match="reason"):
            make_finding(reason="")

    @pytest.mark.parametrize(
        "bad_hash",
        [
            "deadbeef" * 8,  # 缺 sha256: 前缀
            "sha256:XYZ",  # 非法字符
            "sha256:" + "a" * 63,  # 长度不足
            "sha256:" + "A" * 64,  # 大写 hex 不收
        ],
    )
    def test_evidence_hash_format_enforced(self, bad_hash: str) -> None:
        with pytest.raises(FindingError, match="evidence_hash"):
            make_finding(evidence_hash=bad_hash)

    @pytest.mark.parametrize("field", ["finding_id", "cloud", "service", "resource", "issue_type"])
    def test_required_text_fields_reject_blank(self, field: str) -> None:
        with pytest.raises(FindingError, match=field):
            make_finding(**{field: "  "})


# -- 证据哈希 ------------------------------------------------------------------
class TestHashEvidence:
    def test_format_and_deterministic(self) -> None:
        digest = hash_evidence("凭证样式字符串 AKIA***")
        assert digest.startswith("sha256:")
        assert len(digest) == len("sha256:") + 64
        assert digest == hash_evidence("凭证样式字符串 AKIA***")

    def test_distinct_evidence_distinct_hash(self) -> None:
        assert hash_evidence("evidence-a") != hash_evidence("evidence-b")

    def test_non_string_rejected(self) -> None:
        with pytest.raises(FindingError):
            hash_evidence(b"bytes-not-allowed")  # type: ignore[arg-type]


# -- 指纹去重 ------------------------------------------------------------------
class TestFingerprintDedup:
    def test_case_and_whitespace_variants_share_fingerprint(self) -> None:
        a = make_finding()
        b = make_finding(
            finding_id="other-id",
            cloud=" AliYun ",
            service="OSS",
            resource=" Bucket-001 ",
            issue_type="PUBLIC-READ",
        )
        assert fingerprint(a) == fingerprint(b)

    def test_tuple_difference_changes_fingerprint(self) -> None:
        assert fingerprint(make_finding()) != fingerprint(make_finding(resource="bucket-002"))

    def test_dedup_order_preserving(self) -> None:
        a = make_finding(finding_id="a", resource="bucket-001")
        dup_of_a = make_finding(finding_id="a-dup", cloud="ALIYUN", resource=" bucket-001 ")
        b = make_finding(finding_id="b", resource="bucket-002")
        result = dedup([a, dup_of_a, b])
        assert [f.finding_id for f in result] == ["a", "b"]

    def test_dedup_keeps_first_occurrence(self) -> None:
        first = make_finding(finding_id="first", reason="第一条")
        second = make_finding(finding_id="second", reason="重复")
        assert dedup([first, second])[0].finding_id == "first"


# -- 定级规则表 ----------------------------------------------------------------
class TestClassify:
    def test_rule_hit_overrides_model_suggestion(self) -> None:
        # 公开可写存储:规则钉死 critical,模型建议 low 直接作废
        finding = make_finding(issue_type="public-write-storage")
        assert classify(finding, suggested=Severity.LOW) is Severity.CRITICAL

    def test_public_read_is_high(self) -> None:
        assert classify(make_finding(issue_type="public-read")) is Severity.HIGH

    def test_metadata_endpoint_is_high(self) -> None:
        finding = make_finding(service="ecs", issue_type="metadata-endpoint-reachable")
        assert classify(finding) is Severity.HIGH

    def test_rule_table_priority_first_match_wins(self) -> None:
        # SEVERITY_RULES 按优先级排列:public-read 先于 misconfiguration,
        # 一条 Finding 只可能命中首个匹配规则,定级为 high 而非 medium
        assert SEVERITY_RULES[0].severity is Severity.CRITICAL
        finding = make_finding(issue_type="public-read")
        assert classify(finding, suggested="medium") is Severity.HIGH

    def test_rule_matching_is_normalized(self) -> None:
        finding = make_finding(issue_type=" Public-Read ")
        assert classify(finding) is Severity.HIGH

    def test_no_hit_degrades_to_lower_of_suggested_and_info(self) -> None:
        # 无命中:取模型建议与 info 的较低者,模型报 critical 也只能拿 info
        finding = make_finding(issue_type="something-unlisted")
        assert classify(finding, suggested=Severity.CRITICAL) is Severity.INFO
        assert classify(finding, suggested="high") is Severity.INFO

    def test_no_hit_without_suggestion_is_info(self) -> None:
        assert classify(make_finding(issue_type="something-unlisted")) is Severity.INFO

    def test_illegal_suggestion_rejected(self) -> None:
        with pytest.raises(FindingError, match="suggested 非法值"):
            classify(make_finding(issue_type="something-unlisted"), suggested="fatal")


# -- findings.json round-trip ---------------------------------------------------
class TestJsonRoundTrip:
    def test_to_dict_from_dict_lossless(self) -> None:
        finding = make_finding()
        assert Finding.from_dict(json.loads(json.dumps(finding.to_dict()))) == finding

    def test_dict_values_are_plain_strings(self) -> None:
        data = make_finding().to_dict()
        assert set(data) == {
            "finding_id",
            "result",
            "severity",
            "evidence_hash",
            "reason",
            "cloud",
            "service",
            "resource",
            "issue_type",
        }
        assert all(isinstance(v, str) for v in data.values())

    def test_from_dict_rejects_missing_field(self) -> None:
        data = make_finding().to_dict()
        del data["reason"]
        with pytest.raises(FindingError, match="缺字段"):
            Finding.from_dict(data)

    def test_from_dict_rejects_unknown_field(self) -> None:
        data = make_finding().to_dict()
        data["evidence_plaintext"] = "绝不落明文"
        with pytest.raises(FindingError, match="未知字段"):
            Finding.from_dict(data)

    def test_from_dict_rejects_non_dict(self) -> None:
        with pytest.raises(FindingError):
            Finding.from_dict(["not", "a", "dict"])  # type: ignore[arg-type]

    def test_workspace_findings_json_compatible(self, tmp_path: object) -> None:
        # 与 Workspace.findings.json 读写兼容:save -> load -> from_dict 无损
        ws = Workspace(str(tmp_path))
        findings = [make_finding(), make_finding(finding_id="f-002", resource="bucket-002")]
        ws.save_findings([f.to_dict() for f in dedup(findings)])
        loaded = [Finding.from_dict(item) for item in ws.load_findings()]
        assert loaded == findings
