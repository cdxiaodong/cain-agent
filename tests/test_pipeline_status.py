"""产线健康画像格式测试 — 章节齐全、事实口径与当前状态一致。"""

from __future__ import annotations

from pathlib import Path

DOC = Path(__file__).resolve().parent.parent / "docs" / "pipeline-status.md"


def _text() -> str:
    return DOC.read_text(encoding="utf-8")


def test_doc_exists_with_core_sections() -> None:
    text = _text()
    for section in ("通道现状", "近 7 日交付节奏", "风险清单", "建议"):
        assert section in text, f"missing section: {section}"


def test_roles_table_covers_all_channels() -> None:
    text = _text()
    for role in ("Lead", "Claude 主力", "Codex-A", "Codex-B", "监工"):
        assert role in text, f"missing role: {role}"


def test_risk_calls_out_single_point() -> None:
    text = _text()
    assert "单点依赖监工" in text
    assert "cron 触发吞没" in text


def test_recommendations_are_user_actions() -> None:
    text = _text()
    assert "重建三工程师会话" in text
    assert "v0.2.1" in text and "拍板" in text


def test_issue_guard_status_reflected() -> None:
    """#4-#8 修复状态与守卫口径在文档中可追溯。"""
    text = _text()
    assert "#4-#8" in text


def test_date_stamp_present() -> None:
    text = _text()
    assert "2026-09-05" in text
