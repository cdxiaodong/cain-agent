"""v0.2.1 发布预案格式测试 — 预案完整可执行、且明确标注未执行。"""

from __future__ import annotations

import re
from pathlib import Path

PLAN = Path(__file__).resolve().parent.parent / "docs" / "release" / "v0.2.1-release-plan.md"
CHECKLIST = (
    Path(__file__).resolve().parent.parent / "docs" / "release" / "v0.2.0-checklist.md"
)


def _plan() -> str:
    return PLAN.read_text(encoding="utf-8")


def test_plan_exists_with_core_sections() -> None:
    text = _plan()
    for section in ("为什么是 v0.2.1", "用户可见变更摘要", "终检数据",
                    "发布步骤", "回滚预案", "不执行声明"):
        assert section in text, f"missing section: {section}"


def test_plan_cites_security_fix_commits() -> None:
    text = _plan()
    assert "4096e00" in text          # 社区安全修复 merge
    assert "#4" in text and "#8" in text


def test_plan_release_commands_complete() -> None:
    text = _plan()
    assert "git tag -a v0.2.1" in text
    assert "gh release create v0.2.1" in text
    assert "--verify-tag" in text
    assert "version" in text and "0.2.1" in text  # 版本 bump 步骤


def test_plan_declares_not_executed() -> None:
    text = _plan()
    assert "未执行" in text
    assert "拍板" in text  # 留用户决策


def test_plan_rollback_covers_tag_and_release() -> None:
    text = _plan()
    rollback = text.split("回滚预案")[1].split("## 6")[0]
    assert "git tag -d" in rollback
    assert "gh release delete" in rollback


def test_v020_checklist_archived_with_publish_fact() -> None:
    text = CHECKLIST.read_text(encoding="utf-8")
    assert "已归档" in text
    assert "2026-08-25" in text          # 发布日期事实
    assert "4b2026cf" in text            # tag 指向


def test_plan_baseline_numbers_match_reality() -> None:
    text = _plan()
    assert "1069 passed" in text         # 与当前全量基线一致
    assert re.search(r"v0\.2\.1\s+不存在", text)  # tag 前提检查
