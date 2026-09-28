"""Phase 5-B1 patterns 校验器测试(零触网;含 20 条全过入口)。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cain_agent.patternlib import (
    PatternError,
    iter_patterns,
    load_patterns,
    validate_pattern,
)

REPO = Path(__file__).resolve().parent.parent
PATTERNS = REPO / "skills" / "patterns.jsonl"


def _valid() -> dict[str, object]:
    return {
        "target_kind": "接口",
        "invariant": "输入不进拼接",
        "violation": "拼接发生",
        "verify_method": "对照请求",
        "confidence_prior": 0.7,
    }


# -- 单条校验 ------------------------------------------------------------------------


def test_valid_pattern_passes() -> None:
    assert validate_pattern(_valid()) == _valid()


def test_non_dict_rejected() -> None:
    with pytest.raises(PatternError, match="对象"):
        validate_pattern(["not", "a", "dict"])


@pytest.mark.parametrize("key", ["target_kind", "invariant", "violation", "verify_method"])
def test_missing_required_field_rejected(key: str) -> None:
    p = _valid()
    del p[key]
    with pytest.raises(PatternError, match=key):
        validate_pattern(p)


def test_blank_string_field_rejected() -> None:
    p = _valid()
    p["invariant"] = "   "
    with pytest.raises(PatternError, match="invariant"):
        validate_pattern(p)


@pytest.mark.parametrize("bad", [0.0, 1.5, -0.1, True, "0.7", None])
def test_invalid_confidence_prior_rejected(bad: object) -> None:
    p = _valid()
    p["confidence_prior"] = bad
    with pytest.raises(PatternError, match="confidence_prior"):
        validate_pattern(p)


def test_confidence_one_is_valid_boundary() -> None:
    p = _valid()
    p["confidence_prior"] = 1.0
    validate_pattern(p)


# -- JSONL 加载 -----------------------------------------------------------------------


def test_iter_skips_blank_lines() -> None:
    text = "\n".join([
        json.dumps(_valid(), ensure_ascii=False),
        "",
        "   ",
        json.dumps(_valid(), ensure_ascii=False),
    ])
    assert len(list(iter_patterns(text))) == 2


def test_bad_json_line_reports_lineno() -> None:
    text = json.dumps(_valid()) + "\n{broken"
    with pytest.raises(PatternError, match="line 2"):
        list(iter_patterns(text))


def test_bad_field_reports_lineno() -> None:
    p = _valid()
    p["confidence_prior"] = 0.0
    text = json.dumps(_valid()) + "\n" + json.dumps(p)
    with pytest.raises(PatternError, match="line 2"):
        list(iter_patterns(text))


def test_empty_file_loads_zero() -> None:
    assert list(iter_patterns("")) == []


def test_load_missing_file_raises() -> None:
    with pytest.raises(OSError):
        load_patterns(REPO / "no-such-patterns.jsonl")


# -- 仓库首批 ≥20 条 -------------------------------------------------------------------


def test_repo_patterns_all_valid_and_count() -> None:
    patterns = load_patterns(PATTERNS)
    assert len(patterns) >= 20
    kinds = {str(p["target_kind"]) for p in patterns}
    assert any("SQL" in k or "拼接" in k for k in kinds)
    assert all(
        isinstance(p["confidence_prior"], (int, float))
        and not isinstance(p["confidence_prior"], bool)
        and 0.0 < float(p["confidence_prior"]) <= 1.0  # type: ignore[arg-type]
        for p in patterns
    )
