"""反序列化技能文档格式校验"""
from pathlib import Path


def test_skill_file_exists():
    assert Path("skills/web/deserialization/SKILL.md").exists()


def test_skill_structure():
    content = Path("skills/web/deserialization/SKILL.md").read_text(encoding="utf-8")
    required_sections = ["## 原理", "## 检测方法", "## 工具", "## 输出格式"]
    for section in required_sections:
        assert section in content


def test_no_sensitive_info():
    content = Path("skills/web/deserialization/SKILL.md").read_text(encoding="utf-8")
    assert "平安" not in content
    assert "pingan" not in content.lower()


def test_payload_examples():
    content = Path("skills/web/deserialization/SKILL.md").read_text(encoding="utf-8")
    assert "ysoserial" in content
    assert "pickle" in content
    assert "unserialize" in content
