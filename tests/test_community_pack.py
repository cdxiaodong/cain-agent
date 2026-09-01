"""社区冷启动包静态文件测试 — 模板齐全、内容口径钉死,零外发动作。"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_community_doc_exists_with_required_sections() -> None:
    text = (REPO / "docs" / "community.md").read_text(encoding="utf-8")
    for section in ("提 Issue", "提 PR", "安全报告", "开发约定"):
        assert section in text
    # 三型 Issue 模板引用(中文标签,对应 bug/feature/security 模板)
    for label in ("Bug 报告", "功能建议", "安全问题"):
        assert label in text
    # 安全问题不开公开 Issue 的边界声明
    assert "不要开公开 Issue" in text or "不要在公开 Issue" in text
    # 增长记录含目标口径
    assert "fork ≥ 200" in text


def test_issue_templates_three_kinds() -> None:
    base = REPO / ".github" / "ISSUE_TEMPLATE"
    names = {p.name for p in base.iterdir() if p.suffix in (".yml", ".yaml", ".md")}
    joined = " ".join(names).lower()
    for kind in ("bug", "feature", "security"):
        assert kind in joined, f"missing issue template for {kind}"


def test_pr_template_exists() -> None:
    pr = REPO / ".github" / "pull_request_template.md"
    assert pr.exists()
    text = pr.read_text(encoding="utf-8")
    assert "测试" in text or "test" in text.lower()


def test_contributing_exists_or_community_covers() -> None:
    """CONTRIBUTING.md 存在,或 community.md 已覆盖贡献指引(单一真源)。"""
    contributing = REPO / "CONTRIBUTING.md"
    if not contributing.exists():
        text = (REPO / "docs" / "community.md").read_text(encoding="utf-8")
        assert "提 PR" in text and "开发约定" in text
