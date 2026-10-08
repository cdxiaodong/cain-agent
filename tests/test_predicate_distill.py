"""C2 根因谓词蒸馏测试(prompt 模板 + 防幻觉校验,零 LLM 零触网)。"""

from __future__ import annotations

import pytest

from cain_agent.patchdiff import (
    ChangeSet,
    Hunk,
    PredicateError,
    build_distill_prompt,
    validate_predicate,
)


def _cs() -> ChangeSet:
    h = Hunk(
        file_path="auth.py",
        old_start=10,
        new_start=10,
        signature_changes=("validate_token",),
        added_checks=("if not is_expired(token):",),
        removed_paths=(),
    )
    return ChangeSet(hunks=(h,))


def _pred(**over: object) -> dict[str, object]:
    p: dict[str, object] = {
        "target_kind": "令牌校验接口",
        "invariant": "validate_token 必须先检查过期",
        "violation": "validate_token 跳过 is_expired",
        "verify_method": "构造过期 token 对照请求",
        "confidence_prior": 0.8,
    }
    p.update(over)
    return p


# -- prompt 模板 --------------------------------------------------------------------


def test_prompt_contains_five_field_instruction() -> None:
    prompt = build_distill_prompt(_cs())
    for field in ("target_kind", "invariant", "violation", "verify_method",
                  "confidence_prior"):
        assert field in prompt, field
    assert "JSON" in prompt


def test_prompt_lists_symbol_whitelist() -> None:
    prompt = build_distill_prompt(_cs())
    assert "变更集符号表" in prompt
    assert "validate_token" in prompt and "is_expired" in prompt


def test_prompt_includes_hunk_summary() -> None:
    prompt = build_distill_prompt(_cs())
    assert "auth.py" in prompt and "签名变化: validate_token" in prompt
    assert "is_expired" in prompt  # 新增校验行进摘要


def test_empty_changeset_returns_empty_prompt() -> None:
    assert build_distill_prompt(ChangeSet()) == ""


def test_prompt_has_no__llm_side_effect_contract() -> None:
    """模板是纯字符串:两次构建结果一致(确定性)。"""
    assert build_distill_prompt(_cs()) == build_distill_prompt(_cs())


# -- validate_predicate:结构 ----------------------------------------------------------


def test_valid_predicate_passes() -> None:
    assert validate_predicate(_pred(), _cs()) == _pred()


def test_non_dict_rejected() -> None:
    with pytest.raises(PredicateError, match="dict"):
        validate_predicate("x", _cs())


@pytest.mark.parametrize("key", ["target_kind", "invariant", "violation", "verify_method"])
def test_missing_field_rejected(key: str) -> None:
    p = _pred()
    del p[key]
    with pytest.raises(PredicateError, match=key):
        validate_predicate(p, _cs())


def test_blank_field_rejected() -> None:
    with pytest.raises(PredicateError, match="invariant"):
        validate_predicate(_pred(invariant="  "), _cs())


@pytest.mark.parametrize("bad", [0.0, 1.5, True, "0.8", None])
def test_bad_confidence_rejected(bad: object) -> None:
    with pytest.raises(PredicateError, match="confidence_prior"):
        validate_predicate(_pred(confidence_prior=bad), _cs())


# -- validate_predicate:防幻觉 --------------------------------------------------------


def test_hallucinated_symbol_rejected() -> None:
    """invariant/violation 均不引变更集符号 → 幻觉拒绝。"""
    with pytest.raises(PredicateError, match="幻觉拒绝"):
        validate_predicate(
            _pred(invariant="完全无关的描述", violation="另一个无关描述"), _cs()
        )


def test_symbol_in_invariant_passes() -> None:
    assert validate_predicate(_pred(violation="另一个描述无符号"), _cs())


def test_symbol_in_violation_passes() -> None:
    assert validate_predicate(_pred(invariant="无符号描述", violation="is_expired 被跳过"), _cs())


def test_word_boundary_not_substring() -> None:
    """符号是词边界匹配:is_expired 不得被 'isis_expiredx' 骗过。"""
    with pytest.raises(PredicateError, match="幻觉拒绝"):
        validate_predicate(
            _pred(invariant="xisis_expiredx", violation="无符号"), _cs()
        )


def test_empty_changeset_skips_symbol_check() -> None:
    """空变更集无白名单——只走结构校验(防误杀空场景)。"""
    assert validate_predicate(_pred(invariant="任意", violation="任意"), ChangeSet())
