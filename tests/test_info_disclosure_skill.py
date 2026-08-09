"""敏感信息泄露技能文档格式校验"""
from pathlib import Path


def test_skill_file_exists():
    assert Path("skills/web/info-disclosure/SKILL.md").exists()


def test_skill_structure():
    content = Path("skills/web/info-disclosure/SKILL.md").read_text(encoding="utf-8")
    for section in ["## 原理", "## 检测方法", "## 工具", "## 输出格式"]:
        assert section in content


def test_no_sensitive_info():
    content = Path("skills/web/info-disclosure/SKILL.md").read_text(encoding="utf-8")
    assert "平安" not in content
    assert "pingan" not in content.lower()


def test_payload_examples():
    content = Path("skills/web/info-disclosure/SKILL.md").read_text(encoding="utf-8")
    assert ".git" in content
    assert ".env" in content
    assert ".bak" in content
