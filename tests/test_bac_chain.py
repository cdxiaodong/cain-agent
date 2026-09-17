"""BAC 全链组合测试(09-14 任务 3)— load_evidence → judge_bac 组合边界。

纯函数链端到端(零触网零真实凭证),不改 src;两层语义差异与异常传播
钉死:

- 输入层(load_evidence)只保证「证据包可解析」,判定层(judge_bac)
  再做身份/数值/冲突证据裁决——两层拒绝语义不同是设计内行为;
- 输入层拒绝 = 异常传播,不产生任何判定对象;
- 失败用例只记录不修(按 09-09 任务 3 先例,本文件未发现需记录的实现缺陷)。
"""

from __future__ import annotations

import math

import pytest

from cain_agent.web.bac_core import Kind, judge_bac
from cain_agent.web.bac_evidence import load_evidence


def _payload(**over: object) -> dict:
    base: dict = {
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
    for k, v in over.items():
        sec, key = k.split("__")
        base[sec][key] = v  # type: ignore[index]
    return base


def _judge(payload: dict):
    pair, diff = load_evidence(payload)
    return judge_bac(pair, diff)


# -- 贯通:合法证据 × 判定 --------------------------------------------------------


def test_valid_cross_account_read_chain_horizontal() -> None:
    """跨账号 + 200 + 归属匹配 + 高相似 → 输入层通过,判定层 horizontal。"""
    v = _judge(_payload())
    assert v.kind is Kind.HORIZONTAL and v.confidence >= 0.8


def test_valid_gray_zone_chain_lowers_confidence() -> None:
    v = _judge(_payload(response__content_similarity=0.6))
    assert v.kind is Kind.HORIZONTAL and v.confidence < 0.7


def test_valid_denied_chain_protection_in_place() -> None:
    v = _judge(_payload(response__status_b=403, response__owner_fields_match=False,
                        response__content_similarity=0.0))
    assert v.kind is Kind.NONE and "防护在位" in v.rationale


def test_vertical_chain_through_both_layers() -> None:
    v = _judge(_payload(
        request__method_a="POST", request__method_b="POST",
        request__url_a="/admin/users", request__url_b="/admin/users",
        request__object_owner="system",
        request__is_privileged_action=True, request__replay_role_lower=True,
        response__owner_fields_match=False, response__content_similarity=0.5,
    ))
    assert v.kind is Kind.VERTICAL


# -- 组合场景:403 + 依赖页变化(09-09 任务1 修复③的组合验证) --------------------


def test_denied_with_victim_change_mbac_wins_with_capped_confidence() -> None:
    v = _judge(_payload(
        request__method_a="POST", request__method_b="POST",
        response__status_b=403, response__owner_fields_match=False,
        response__content_similarity=0.0,
        response__victim_side_change="insert",
    ))
    assert v.mbac and v.kind is Kind.HORIZONTAL
    assert v.confidence <= 0.55
    assert "冲突证据" in v.rationale


def test_success_with_victim_change_mbac_high_confidence() -> None:
    v = _judge(_payload(
        request__method_a="POST", request__method_b="POST",
        response__owner_fields_match=False, response__content_similarity=0.0,
        response__victim_side_change="update",
    ))
    assert v.mbac and v.confidence == 0.75


# -- 输入层拒绝:异常传播,不产生判定对象 ------------------------------------------


def test_sensitive_key_rejected_before_judgement() -> None:
    payload = _payload()
    payload["request"]["headers"] = {"Authorization": "Bearer X"}  # type: ignore[index]
    with pytest.raises(ValueError, match="敏感字段"):
        _judge(payload)


def test_type_disguise_rejected_before_judgement() -> None:
    with pytest.raises(ValueError, match="status_b"):
        _judge(_payload(response__status_b=True))


def test_out_of_range_similarity_rejected_before_judgement() -> None:
    with pytest.raises(ValueError, match="content_similarity"):
        _judge(_payload(response__content_similarity=1.5))


def test_invalid_change_enum_rejected_before_judgement() -> None:
    with pytest.raises(ValueError, match="victim_side_change"):
        _judge(_payload(response__victim_side_change="destroy"))


# -- 两层语义差异:输入合法但判定层排除 --------------------------------------------


def test_same_account_passes_input_but_excluded_at_judgement() -> None:
    """同账号在输入层合法(结构完整),判定层排除为 none——两层语义差异钉死。"""
    v = _judge(_payload(request__replay_as="alice"))
    assert v.kind is Kind.NONE
    assert "相同" in v.rationale or "同账号" in v.rationale


def test_missing_owner_passes_input_but_none_at_judgement() -> None:
    """object_owner 非空字符串是输入层硬约束;空串在输入层即被拒。
    这里用归属=重放者(非空)表达「归属不明」在判定层的排除路径。"""
    v = _judge(_payload(request__object_owner="bob"))
    assert v.kind is Kind.NONE


def test_chain_no_verdict_object_leaks_on_reject() -> None:
    """输入层拒绝时 judge_bac 根本不被调用(异常在 load_evidence 抛出),
    不存在「半判定」中间对象——以 pytest.raises 钉死传播路径。"""
    bad = _payload(response__content_similarity=math.nan)
    with pytest.raises(ValueError):
        pair, diff = load_evidence(bad)  # noqa: F841 — 证明异常先于 judge 抛出
        judge_bac(pair, diff)
