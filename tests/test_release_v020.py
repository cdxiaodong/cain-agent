from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent


def test_v020_metadata_is_consistent():
    package_init = (REPO_ROOT / "src/cain_agent/__init__.py").read_text(encoding="utf-8")
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    docker_docs = (REPO_ROOT / "docs/docker.md").read_text(encoding="utf-8")

    assert '__version__ = "0.2.0"' in package_init
    assert 'version = "0.2.0"' in pyproject
    assert "cain-agent 0.2.0" in docker_docs


def test_v020_release_notes_are_bilingual_and_include_benchmark():
    notes = (REPO_ROOT / "docs/release/v0.2.0.md").read_text(encoding="utf-8")

    assert "## 中文" in notes
    assert "## English" in notes
    assert "| classic | 66.7% | 4/6 | 0.012s | 538 | 0 |" in notes
    assert "| orchestrated | 66.7% | 4/6 | 0.020s | 1260 | 0 |" in notes
