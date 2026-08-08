"""README 格式校验"""
from pathlib import Path


def test_readme_exists():
    assert Path("README.md").exists()


def test_features_section():
    content = Path("README.md").read_text(encoding="utf-8")
    assert "## Features" in content


def test_cloud_coverage():
    content = Path("README.md").read_text(encoding="utf-8")
    clouds = ["AWS", "Azure", "GCP", "阿里云", "腾讯云", "华为云"]
    for cloud in clouds:
        assert cloud in content


def test_owasp_coverage():
    content = Path("README.md").read_text(encoding="utf-8")
    skills = ["SQLi", "XSS", "SSRF", "CSRF", "File Upload", "XXE", "Command Injection", "Path Traversal"]
    for skill in skills:
        assert skill in content


def test_no_sensitive_info():
    content = Path("README.md").read_text(encoding="utf-8")
    assert "平安" not in content
    assert "pingan" not in content.lower()
