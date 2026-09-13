"""BAC 证据包输入验证测试(09-09 任务 2)— 全 mock,零触网零真实凭证。

覆盖:合法构造 / 缺字段 / 类型违规(bool 冒充 int 等)/ 非法枚举与状态码 /
未知与敏感字段拒绝 / 错误消息不泄露输入内容。
"""

from __future__ import annotations

import math

import pytest

from cain_agent.web.bac_core import RequestPair, ResponseDiff, VictimSideChange
from cain_agent.web.bac_evidence import load_evidence

# 假凭证 canary:断言其绝不出现在任何错误消息里
_FAKE_TOKEN = "Bearer AKIAFAKECANARY0000"


def _valid_payload(**extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "request": {
            "method_a": "GET",
            "url_a": "https://app.example.com/api/orders/1001",
            "method_b": "GET",
            "url_b": "https://app.example.com/api/orders/1001",
            "object_owner": "alice",
            "replay_as": "bob",
        },
        "response": {
            "status_a": 200,
            "status_b": 200,
            "owner_fields_match": True,
            "content_similarity": 0.9,
        },
    }
    for section, values in extra.items():  # pragma: no cover - 测试辅助分支
        payload[section] = {**payload[section], **values}  # type: ignore[arg-type]
    return payload


def test_valid_payload_builds_pair_and_diff() -> None:
    pair, diff = load_evidence(_valid_payload())
    assert isinstance(pair, RequestPair) and isinstance(diff, ResponseDiff)
    assert pair.object_owner == "alice" and pair.replay_as == "bob"
    assert diff.victim_side_change is VictimSideChange.NONE
    assert pair.is_privileged_action is False and pair.replay_role_lower is False


def test_valid_payload_with_optionals_and_change() -> None:
    payload = _valid_payload(
        request={"is_privileged_action": True, "replay_role_lower": True},
        response={"victim_side_change": "insert"},
    )
    pair, diff = load_evidence(payload)
    assert pair.is_privileged_action and pair.replay_role_lower
    assert diff.victim_side_change is VictimSideChange.NEW_TOKEN


@pytest.mark.parametrize("section,key", [
    ("request", "method_a"), ("request", "url_a"), ("request", "method_b"),
    ("request", "url_b"), ("request", "object_owner"), ("request", "replay_as"),
    ("response", "status_a"), ("response", "status_b"),
    ("response", "owner_fields_match"), ("response", "content_similarity"),
])
def test_missing_required_field_rejected(section: str, key: str) -> None:
    payload = _valid_payload()
    del payload[section][key]  # type: ignore[arg-type,union-attr]
    with pytest.raises(ValueError, match=key):
        load_evidence(payload)


def test_missing_top_section_rejected() -> None:
    payload = _valid_payload()
    del payload["response"]
    with pytest.raises(ValueError, match="response"):
        load_evidence(payload)


def test_bool_disguised_as_int_status_rejected() -> None:
    payload = _valid_payload(response={"status_b": True})
    with pytest.raises(ValueError, match="status_b"):
        load_evidence(payload)


def test_int_disguised_as_bool_rejected() -> None:
    payload = _valid_payload(response={"owner_fields_match": 1})
    with pytest.raises(ValueError, match="owner_fields_match"):
        load_evidence(payload)


def test_string_similarity_rejected() -> None:
    payload = _valid_payload(response={"content_similarity": "0.9"})
    with pytest.raises(ValueError, match="content_similarity"):
        load_evidence(payload)


def test_status_out_of_range_rejected() -> None:
    for bad in (99, 600, 0, -1):
        payload = _valid_payload(response={"status_b": bad})
        with pytest.raises(ValueError, match="status_b"):
            load_evidence(payload)


def test_similarity_out_of_range_or_non_finite_rejected() -> None:
    for bad in (-0.01, 1.01, math.inf, math.nan):
        payload = _valid_payload(response={"content_similarity": bad})
        with pytest.raises(ValueError, match="content_similarity"):
            load_evidence(payload)


def test_invalid_change_enum_rejected() -> None:
    payload = _valid_payload(response={"victim_side_change": "destroy"})
    with pytest.raises(ValueError, match="victim_side_change"):
        load_evidence(payload)


@pytest.mark.parametrize("sensitive", [
    {"headers": {"Authorization": _FAKE_TOKEN}},
    {"cookies": "session=abc"},
    {"token": _FAKE_TOKEN},
    {"request_body": "raw"},
    {"authorization": _FAKE_TOKEN},
    {"api_secret": "x"},
])
def test_sensitive_fields_rejected(sensitive: dict[str, object]) -> None:
    payload = _valid_payload(request=dict(sensitive))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="敏感字段"):
        load_evidence(payload)


def test_unknown_plain_field_rejected() -> None:
    payload = _valid_payload(response={"extra_note": "hi"})
    with pytest.raises(ValueError, match="未知字段"):
        load_evidence(payload)


def test_unknown_top_key_rejected() -> None:
    payload = _valid_payload()
    payload["metadata"] = {"anything": 1}
    with pytest.raises(ValueError, match="metadata"):
        load_evidence(payload)


def test_error_messages_never_leak_input_values() -> None:
    """错误信息只含字段名:携带假凭证的 URL 不得回流到报错文本。"""
    payload = _valid_payload()
    payload["request"]["url_b"] = f"https://app.example.com/x?token={_FAKE_TOKEN}"  # type: ignore[index,union-attr]
    payload["request"]["password_field"] = _FAKE_TOKEN  # type: ignore[index,union-attr]
    try:
        load_evidence(payload)
    except ValueError as exc:
        assert _FAKE_TOKEN not in str(exc), "错误消息不得包含输入值"
        assert "app.example.com" not in str(exc)
    else:
        raise AssertionError("含未知字段/敏感键的输入必须被拒绝")


def test_valid_input_is_not_a_finding_assertion() -> None:
    """合法构造只代表可解析:返回对象类型即证据对,不含任何「已确认」语义。"""
    pair, diff = load_evidence(_valid_payload())
    assert not hasattr(pair, "confirmed") and not hasattr(diff, "confirmed")
