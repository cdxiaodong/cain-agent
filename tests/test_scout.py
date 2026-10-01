"""Phase 5-B2 Scout 假设生成测试(零 token,零触网)。"""

from __future__ import annotations

from pathlib import Path

import pytest

from cain_agent.handlers import make_test_handler
from cain_agent.patternlib import PatternError
from cain_agent.scout import Hypothesis, generate_hypotheses, render_hypotheses
from cain_agent.workspace import Workspace
from tests.test_handlers import SKILLS_ROOT, FakeExecutor, SkillLoader, _ctx, _seed_recon_endpoints

_PATTERNS = [
    {"target_kind": "动态SQL拼接接口", "invariant": "i1", "violation": "v1",
     "verify_method": "m1", "confidence_prior": 0.8, "id": "p-sqli"},
    {"target_kind": "用户内容回显点", "invariant": "i2", "violation": "v2",
     "verify_method": "m2", "confidence_prior": 0.6, "id": "p-xss"},
    {"target_kind": "服务端取数参数", "invariant": "i3", "violation": "v3",
     "verify_method": "m3", "confidence_prior": 0.9, "id": "p-ssrf"},
]


def _ep(url: str, params: list[str] | None = None, method: str = "GET") -> dict:
    return {"url": url, "params": params or [], "method": method}


# -- 匹配 -------------------------------------------------------------------------


def test_sql_pattern_matches_query_endpoint() -> None:
    hyps = generate_hypotheses([_ep("http://e.com/search", ["q"])], _PATTERNS)
    assert any(h.pattern_id == "p-sqli" for h in hyps)


def test_ssrf_matches_url_param() -> None:
    hyps = generate_hypotheses([_ep("http://e.com/fetch", ["url"])], _PATTERNS)
    assert any(h.pattern_id == "p-ssrf" for h in hyps)


def test_no_signal_no_hypothesis() -> None:
    hyps = generate_hypotheses([_ep("http://e.com/static/logo")], _PATTERNS)
    assert hyps == []


def test_empty_endpoints_yield_empty() -> None:
    assert generate_hypotheses([], _PATTERNS) == []


def test_endpoint_without_url_skipped() -> None:
    assert generate_hypotheses([{"params": ["q"]}], _PATTERNS) == []


def test_priority_orders_output() -> None:
    ep = _ep("http://e.com/proxy", ["url"])
    hyps = generate_hypotheses([_ep("http://e.com/search", ["q"]), ep], _PATTERNS)
    assert hyps == sorted(hyps, key=lambda h: (-h.priority, h.endpoint_url, h.pattern_id))
    assert hyps[0].priority >= hyps[-1].priority


def test_post_method_boosts_csrf_like_signal() -> None:
    """POST 方法自身进 haystack——状态变更类接口获得特征。"""
    hyps = generate_hypotheses([_ep("http://e.com/api/update", method="POST")], _PATTERNS)
    # update 是 CSRF 组信号词,但 _PATTERNS 无 CSRF pattern——不产假设(保守)
    assert hyps == []


def test_hypothesis_is_frozen_with_signal() -> None:
    hyps = generate_hypotheses([_ep("http://e.com/search", ["q"])], _PATTERNS)
    h = hyps[0]
    assert isinstance(h, Hypothesis) and h.signal == "search"
    with pytest.raises(AttributeError):
        h.priority = 0.1  # type: ignore[misc]


# -- 渲染 -------------------------------------------------------------------------


def test_render_empty_returns_empty_string() -> None:
    assert render_hypotheses([]) == ""


def test_render_contains_endpoint_and_caveat() -> None:
    hyps = generate_hypotheses([_ep("http://e.com/search", ["q"])], _PATTERNS)
    text = render_hypotheses(hyps)
    assert "Scout 定点假设" in text and "http://e.com/search" in text
    assert "不是结论" in text  # 防把预筛当结论的免责口径


def test_render_respects_limit() -> None:
    many = [Hypothesis("u", "p", 0.5, "s")] * 50
    text = render_hypotheses(many, limit=5)
    assert text.count("- `u`") == 5


# -- 坏库与接线 --------------------------------------------------------------------


def test_bad_patterns_file_rejected_not_silently_degraded(tmp_path: Path) -> None:
    bad = tmp_path / "patterns.jsonl"
    bad.write_text('{"target_kind": "x"}\n', encoding="utf-8")  # 缺字段
    with pytest.raises(PatternError):
        generate_hypotheses([_ep("u")], patterns_path=str(bad))


def test_repo_patterns_load_and_generate(tmp_path: Path) -> None:
    hyps = generate_hypotheses(
        [_ep("http://e.com/api/users", ["id"])], patterns_path=str(SKILLS_ROOT / "patterns.jsonl")
    )
    assert len(hyps) >= 1  # 仓库 22 条库至少 SQL 类命中 id 参数


def test_handler_scout_off_default_zero_change(tmp_path: Path) -> None:
    """缺省 off:prompt 与旧行为一致(不含 Scout 段)。"""
    ws = Workspace(tmp_path / "ws")
    _seed_recon_endpoints(ws)
    executor = FakeExecutor("[]")
    make_test_handler(executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert len(executor.prompts) == 1
    assert "Scout" not in executor.prompts[0]


def test_handler_scout_on_injects_hypotheses(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    _seed_recon_endpoints(ws)  # 含 login(username/password)与 api/users?id=1
    executor = FakeExecutor("[]")
    make_test_handler(
        executor, SkillLoader(SKILLS_ROOT), scout=True,
        patterns_path=str(SKILLS_ROOT / "patterns.jsonl"),
    )(_ctx(ws, "test"))
    assert "Scout 定点假设" in executor.prompts[0]
    assert "http://example.com/api/users" in executor.prompts[0]
