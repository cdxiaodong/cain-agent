"""BAC 判定核心测试(2026-09-07 任务 1)— 全 mock 纯函数,零触网零凭证。

用例对齐方法论:同资源归属一致=none / 200 vs 403 防护在位 / 200+他人数据
=horizontal / 相似度灰区=低置信+人工核验 / MBAC 三态写标记。
"""

from __future__ import annotations

from cain_agent.web.bac_core import (
    BACConfig,
    Kind,
    RequestPair,
    ResponseDiff,
    VictimSideChange,
    judge_bac,
)


def _read_pair() -> RequestPair:
    """典型读越权请求对:受害者 alice 的资源,攻击者 bob 重放。"""
    return RequestPair(
        method_a="GET",
        url_a="https://app.example.com/api/orders/1001",
        method_b="GET",
        url_b="https://app.example.com/api/orders/1001",
        object_owner="alice",
        replay_as="bob",
    )


def _write_pair(method: str = "PUT") -> RequestPair:
    return RequestPair(
        method_a=method,
        url_a="https://app.example.com/api/orders/1001",
        method_b=method,
        url_b="https://app.example.com/api/orders/1001",
        object_owner="alice",
        replay_as="bob",
    )


def test_read_denied_means_protection_in_place() -> None:
    """B 重放被 403 拒 → none(防护在位)。"""
    v = judge_bac(_read_pair(), ResponseDiff(200, 403, False, 0.0))
    assert v.kind is Kind.NONE
    assert "防护在位" in v.rationale


def test_read_own_or_shared_resource_is_none() -> None:
    """同资源归属一致(B 读到自己/共享资源)→ none。"""
    v = judge_bac(_read_pair(), ResponseDiff(200, 200, False, 0.92))
    assert v.kind is Kind.NONE
    assert "共享资源" in v.rationale


def test_horizontal_read_with_high_similarity() -> None:
    """200 + 他人数据 + 相似度超阈 → horizontal 高置信。"""
    v = judge_bac(_read_pair(), ResponseDiff(200, 200, True, 0.93))
    assert v.kind is Kind.HORIZONTAL
    assert v.confidence >= 0.8
    assert "alice" in v.rationale
    assert not v.mbac


def test_similarity_gray_zone_lowers_confidence() -> None:
    """相似度灰区(0.5~0.7)→ 仍 horizontal 但置信降档并要求人工核验。"""
    v = judge_bac(_read_pair(), ResponseDiff(200, 200, True, 0.6))
    assert v.kind is Kind.HORIZONTAL
    assert v.confidence < 0.7
    assert "人工核验" in v.rationale


def test_low_similarity_suspicious_page() -> None:
    """相似度低于灰区下沿 → 低置信 + 人工复核提示(疑似拒页)。"""
    v = judge_bac(_read_pair(), ResponseDiff(200, 200, True, 0.3))
    assert v.confidence <= 0.5
    assert "人工复核" in v.rationale


def test_custom_threshold_respected() -> None:
    """阈值可配置:0.85 阈值下 0.8 相似度进灰区。"""
    cfg = BACConfig(similarity_threshold=0.85)
    v = judge_bac(_read_pair(), ResponseDiff(200, 200, True, 0.8), cfg)
    assert v.confidence < 0.7
    assert "灰区" in v.rationale


def test_vertical_privileged_action_by_lower_role() -> None:
    """特权动作 + 低权角色 + B 200 → vertical。"""
    pair = RequestPair(
        method_a="POST",
        url_a="https://app.example.com/admin/users",
        method_b="POST",
        url_b="https://app.example.com/admin/users",
        object_owner="system",
        replay_as="bob",
        is_privileged_action=True,
        replay_role_lower=True,
    )
    v = judge_bac(pair, ResponseDiff(200, 200, False, 0.5))
    assert v.kind is Kind.VERTICAL
    assert "低权角色" in v.rationale


def test_vertical_requires_role_lower_flag() -> None:
    """未声明角色差 → 不判 vertical(证据不足回落 none)。"""
    pair = RequestPair(
        method_a="POST",
        url_a="https://app.example.com/admin/users",
        method_b="POST",
        url_b="https://app.example.com/admin/users",
        object_owner="system",
        replay_as="bob",
        is_privileged_action=True,
    )
    v = judge_bac(pair, ResponseDiff(200, 200, False, 0.5))
    assert v.kind is not Kind.VERTICAL


def test_mbac_insert_marked() -> None:
    """POST + Victim 依赖页新 token → horizontal+mbac(INSERT)。"""
    v = judge_bac(
        _write_pair("POST"), ResponseDiff(200, 200, False, 0.0, VictimSideChange.NEW_TOKEN)
    )
    assert v.kind is Kind.HORIZONTAL and v.mbac
    assert v.victim_side_change is VictimSideChange.NEW_TOKEN
    assert "insert" in v.rationale


def test_mbac_update_and_delete_marked() -> None:
    for change in (VictimSideChange.TOKEN_REPLACED, VictimSideChange.TOKEN_GONE):
        v = judge_bac(_write_pair("DELETE"), ResponseDiff(200, 200, False, 0.0, change))
        assert v.mbac, change
        assert v.victim_side_change is change


def test_write_without_victim_change_not_mbac() -> None:
    """写操作但 Victim 依赖页无变化 → 不判 MBAC(依赖页反馈缺失)。"""
    v = judge_bac(_write_pair(), ResponseDiff(200, 200, False, 0.9))
    assert not v.mbac


def test_get_triggered_write_demoted() -> None:
    """GET 触发修改属异常场景 → 置信降档 + 人工复核。"""
    pair = RequestPair(
        method_a="GET",
        url_a="https://app.example.com/api/orders/1001?force=1",
        method_b="GET",
        url_b="https://app.example.com/api/orders/1001?force=1",
        object_owner="alice",
        replay_as="bob",
    )
    v = judge_bac(pair, ResponseDiff(200, 200, False, 0.0, VictimSideChange.TOKEN_GONE))
    assert v.mbac
    assert v.confidence <= 0.5
    assert "人工复核" in v.rationale


def test_error_status_not_treated_as_success() -> None:
    """5xx 非成功状态 → 不进读越权分支。"""
    v = judge_bac(_read_pair(), ResponseDiff(200, 500, True, 0.9))
    assert v.kind is Kind.NONE
    assert "非成功状态" in v.rationale


def test_denied_status_configurable() -> None:
    """403 从拒绝集豁免后不再短路成「防护在位」,走内容证据分支。"""
    cfg = BACConfig(forbidden_status=frozenset({401}))
    v = judge_bac(_read_pair(), ResponseDiff(200, 403, True, 0.9), cfg)
    assert v.kind is Kind.NONE  # 403 非 2xx,不构成成功读
    assert "防护在位" not in v.rationale  # 配置生效:不再按拒绝短路
    assert "非成功状态" in v.rationale
