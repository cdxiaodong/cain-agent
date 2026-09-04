"""ROADMAP 发版守卫测试 — v0.2.1 未拍板前,待办不得被勾选、预案不得被删。

背景:2026-09-04 终备的 v0.2.1 发布预案明确「不执行,留用户拍板」。本测试
把这一约束固化:若有人(或自动化)在用户拍板前勾掉待办、删除预案、或把
预案里的不执行声明改掉,CI 变红拦截。
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROADMAP = REPO / "ROADMAP.md"
PLAN = REPO / "docs" / "release" / "v0.2.1-release-plan.md"


def test_v021_todo_exists_unchecked() -> None:
    text = ROADMAP.read_text(encoding="utf-8")
    assert "v0.2.1 发版" in text, "ROADMAP 缺 v0.2.1 发版待办"
    lines = text.splitlines()
    idx = next(i for i, ln in enumerate(lines) if "v0.2.1 发版" in ln)
    block = "\n".join(lines[idx : idx + 3])  # 条目可跨行,取 3 行块
    assert lines[idx].strip().startswith("- [ ]"), (
        f"v0.2.1 待办被勾选了,但发版需用户拍板:{lines[idx]!r}"
    )
    assert "待用户拍板" in block


def test_release_plan_file_exists_with_not_executed_clause() -> None:
    assert PLAN.exists(), "v0.2.1 发布预案文件被删,请恢复或说明原因"
    text = PLAN.read_text(encoding="utf-8")
    assert "不执行声明" in text
    assert "未执行" in text
    assert "拍板" in text


def test_release_plan_has_no_bumped_version() -> None:
    """预案本身只是文档;若 pyproject 已是 0.2.1 说明发版动作已开始,需同步调整守卫。"""
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "0.2.0"' in pyproject, (
        "pyproject 版本已离开 0.2.0 —— 发版是否已获用户拍板?若是,请同步更新本守卫"
    )
