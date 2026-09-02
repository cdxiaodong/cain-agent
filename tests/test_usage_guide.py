"""用户指南格式测试 — 章节齐全、命令可解析、口径与 README 一致。"""

from __future__ import annotations

import re
from pathlib import Path

GUIDE = Path(__file__).resolve().parent.parent / "docs" / "usage.md"


def _text() -> str:
    return GUIDE.read_text(encoding="utf-8")


def test_guide_exists_with_core_sections() -> None:
    text = _text()
    for section in ("安装", "第一次运行", "读懂输出产物", "选择执行后端",
                    "按阶段混搭模型", "常见问题"):
        assert section in text, f"missing section: {section}"


def test_install_commands_use_editable_mode() -> None:
    text = _text()
    assert "pip install -e ." in text
    assert '".[cloud]"' in text


def test_scope_yaml_example_documented() -> None:
    text = _text()
    assert "in_scope:" in text and "out_of_scope:" in text
    assert "deny 优先" in text  # 语义说明
    # scope 工程强制口径
    assert "PreToolUse" in text


def test_backend_flags_match_cli() -> None:
    text = _text()
    for flag in ("--backend pi", "--pi-provider", "--pi-model",
                 "--recon-backend", "--test-backend", "--pi-validation-provider"):
        assert flag in text, f"missing flag doc: {flag}"


def test_run_flags_documented() -> None:
    text = _text()
    for flag in ("--target", "--workspace", "--total-budget", "--idle-timeout",
                 "--dry-run"):
        assert flag in text, f"missing flag doc: {flag}"


def test_output_artifacts_table() -> None:
    text = _text()
    for artifact in ("report.md", "aggregated-report.json", "validation-summary.json"):
        assert artifact in text


def test_safety_disclaimer_present() -> None:
    text = _text()
    assert "已获授权" in text
    assert "授权" in text  # 前置阅读指向 README 法律声明


def test_code_blocks_are_fenced() -> None:
    text = _text()
    fenced = len(re.findall(r"^```", text, re.MULTILINE))
    assert fenced >= 10 and fenced % 2 == 0  # 成对围栏
