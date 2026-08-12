"""README 格式校验"""
from pathlib import Path


def test_readme_exists():
    assert Path("README.md").exists()


def test_sections_present():
    content = Path("README.md").read_text(encoding="utf-8")
    assert "## Why Cain" in content
    assert "## Quick Start" in content
    assert "## Architecture" in content
    assert "## Cloud Module" in content
    assert "## Benchmark" in content
    assert "## ⚠️ Legal & Ethical Use" in content
    assert "## Status" in content
    assert "## License" in content


def test_cloud_coverage():
    content = Path("README.md").read_text(encoding="utf-8")
    clouds = ["AWS", "Azure", "GCP", "阿里云", "腾讯云", "华为云"]
    for cloud in clouds:
        assert cloud in content


def test_skills_coverage():
    content = Path("README.md").read_text(encoding="utf-8")
    assert "cloud module" in content
    assert "read-only" in content
    assert "benchmark" in content


def test_no_sensitive_info():
    content = Path("README.md").read_text(encoding="utf-8")
    assert "平安" not in content
    assert "pingan" not in content.lower()
