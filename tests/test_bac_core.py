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


# -- 09-09 任务1:BAC 判定核心证据前置检查(钉死三缺陷复现) --------------------


def _same_account_pair() -> RequestPair:
    """同账号重放:object_owner == replay_as,不构成跨账号前提。"""
    return RequestPair(
        method_a="GET",
        url_a="https://app.example.com/api/orders/1001",
        method_b="GET",
        url_b="https://app.example.com/api/orders/1001",
        object_owner="alice",
        replay_as="alice",
    )


def test_same_account_replay_not_horizontal() -> None:
    """缺陷钉死:同账号 200+归属匹配不得判已成立水平越权(此前 0.85 误报)。"""
    v = judge_bac(_same_account_pair(), ResponseDiff(200, 200, True, 0.93))
    assert v.kind is Kind.NONE
    assert "同账号" in v.rationale or "相同" in v.rationale


def test_missing_owner_identity_not_horizontal() -> None:
    """归属身份缺失:读越权前提不成立。"""
    pair = RequestPair("GET", "u", "GET", "u", "", "bob")
    v = judge_bac(pair, ResponseDiff(200, 200, True, 0.9))
    assert v.kind is Kind.NONE
    assert "缺失" in v.rationale


def test_missing_replay_identity_rejected_before_anything() -> None:
    """重放者身份缺失:最先拒绝,任何越权结论失去前提。"""
    pair = RequestPair("GET", "u", "GET", "u", "alice", "")
    v = judge_bac(pair, ResponseDiff(200, 200, True, 0.9))
    assert v.kind is Kind.NONE
    assert "replay_as 为空" in v.rationale


def test_nan_similarity_rejected_explicitly() -> None:
    """NaN 相似度:显式 ValueError,不得产出任何置信结论(此前出 0.5 结论)。"""
    pair = RequestPair("GET", "u", "GET", "u", "alice", "bob")
    try:
        judge_bac(pair, ResponseDiff(200, 200, True, float("nan")))
    except ValueError as e:
        assert "content_similarity" in str(e)
    else:
        raise AssertionError("NaN 相似度必须显式拒绝")


def test_inf_and_out_of_range_rejected() -> None:
    import math
    pair = RequestPair("GET", "u", "GET", "u", "alice", "bob")
    for bad in (math.inf, -math.inf, -0.1, 1.5):
        try:
            judge_bac(pair, ResponseDiff(200, 200, True, bad))
        except ValueError:
            continue
        raise AssertionError(f"非法相似度 {bad} 必须显式拒绝")


def test_invalid_threshold_rejected() -> None:
    import math
    pair = RequestPair("GET", "u", "GET", "u", "alice", "bob")
    for bad in (float("nan"), math.inf, 0.0, 1.5, -0.2):
        try:
            judge_bac(pair, ResponseDiff(200, 200, True, 0.8), BACConfig(similarity_threshold=bad))
        except ValueError:
            continue
        raise AssertionError(f"非法阈值 {bad} 必须显式拒绝")


def test_denied_but_victim_changed_is_conflict_not_protection() -> None:
    """403 + 依赖页 INSERT:冲突证据,不得短路为「防护在位」none(此前被吞)。"""
    pair = RequestPair("POST", "u", "POST", "u", "alice", "bob")
    v = judge_bac(pair, ResponseDiff(200, 403, False, 0.0, VictimSideChange.NEW_TOKEN))
    assert v.mbac and v.kind is Kind.HORIZONTAL
    assert "冲突证据" in v.rationale
    assert "人工复核" in v.rationale
    assert v.confidence <= 0.55


def test_mbac_same_account_excluded() -> None:
    """同账号 + 依赖页变化:不构成跨账号越权写。"""
    pair = RequestPair("POST", "u", "POST", "u", "alice", "alice")
    v = judge_bac(pair, ResponseDiff(200, 200, False, 0.0, VictimSideChange.TOKEN_GONE))
    assert v.kind is Kind.NONE and not v.mbac
    assert "人工核验归属" in v.rationale


def test_cross_account_still_detected_regression() -> None:
    """回归:正常跨账号对照判定不受前置检查影响。"""
    pair = RequestPair("GET", "u", "GET", "u", "alice", "bob")
    v = judge_bac(pair, ResponseDiff(200, 200, True, 0.93))
    assert v.kind is Kind.HORIZONTAL and v.confidence >= 0.8
    denied = judge_bac(pair, ResponseDiff(200, 403, False, 0.0))
    assert denied.kind is Kind.NONE and "防护在位" in denied.rationale
