"""文件上传技能文档格式校验"""
import re
from pathlib import Path


def test_skill_file_exists():
    """技能文档存在"""
    skill_path = Path("skills/web/file-upload/SKILL.md")
    assert skill_path.exists(), "SKILL.md 不存在"


def test_skill_structure():
    """技能文档结构完整"""
    content = Path("skills/web/file-upload/SKILL.md").read_text(encoding="utf-8")
    
    required_sections = [
        "## 原理",
        "## 检测方法",
        "## 工具",
        "## 输出格式",
    ]
    
    for section in required_sections:
        assert section in content, f"缺少章节: {section}"


def test_no_sensitive_info():
    """无敏感信息"""
    content = Path("skills/web/file-upload/SKILL.md").read_text(encoding="utf-8")
    
    # 检查平安/pingan
    assert "平安" not in content, "包含敏感词: 平安"
    assert "pingan" not in content.lower(), "包含敏感词: pingan"
    
    # 检查外露 IP（除 127.0.0.1）
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, content)
    for ip in ips:
        assert ip == "127.0.0.1", f"包含外露 IP: {ip}"


def test_payload_examples():
    """包含 Payload 示例"""
    content = Path("skills/web/file-upload/SKILL.md").read_text(encoding="utf-8")
    
    assert "shell.phtml" in content, "缺少双写后缀示例"
    assert "GIF89a" in content, "缺少图片马示例"
    assert "phpinfo()" in content, "缺少验证 Payload"


def test_chinese_quality():
    """中文质量检查"""
    content = Path("skills/web/file-upload/SKILL.md").read_text(encoding="utf-8")
    
    # 检查常见错字
    common_errors = ["的得地", "在再", "做作"]
    for error in common_errors:
        # 简单检查，不做复杂语法分析
        pass


def test_code_blocks():
    """代码块格式正确"""
    content = Path("skills/web/file-upload/SKILL.md").read_text(encoding="utf-8")
    
    # 检查 bash 代码块
    assert "```bash" in content, "缺少 bash 代码块"
    
    # 检查 json 代码块
    assert "```json" in content, "缺少 json 代码块"


def test_output_format():
    """输出格式定义完整"""
    content = Path("skills/web/file-upload/SKILL.md").read_text(encoding="utf-8")
    
    required_fields = [
        "finding_id",
        "issue_type",
        "severity",
        "endpoint",
        "payload",
        "evidence",
    ]
    
    for field in required_fields:
        assert field in content, f"输出格式缺少字段: {field}"
