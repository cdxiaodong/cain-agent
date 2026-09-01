"""CI workflow 静态测试 — 语法可解析 + 关键步骤存在,不依赖 GitHub 运行。"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOW = (
    Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
)


@pytest.fixture(scope="module")
def doc() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_workflow_file_exists_and_parses(doc: dict) -> None:
    assert doc, "ci.yml must be non-empty"
    assert doc["name"] == "CI"


def test_triggers_cover_push_and_pr(doc: dict) -> None:
    on = doc.get(True) or doc.get("on")  # YAML 1.1 会把 on 解析为 True
    assert "push" in on and "pull_request" in on
    assert "main" in on["push"]["branches"]


def test_matrix_python_versions(doc: dict) -> None:
    job = doc["jobs"].get("test") or doc["jobs"].get("quality")
    matrix = job["strategy"]["matrix"]
    assert "3.11" in matrix["python-version"]
    assert "3.12" in matrix["python-version"]


def test_install_lint_test_steps_present(doc: dict) -> None:
    job = doc["jobs"].get("test") or doc["jobs"].get("quality")
    steps = job["steps"]
    run_all = "\n".join(
        str(s.get("run", "")) for s in steps
    ) + "\n" + " | ".join(str(s.get("name", "")) for s in steps)
    assert "pip install -e" in run_all          # editable 安装
    assert "ruff check" in run_all              # lint 步骤
    assert "pytest" in run_all                  # 测试步骤


def test_badges_in_both_readmes() -> None:
    repo = Path(__file__).resolve().parent.parent
    for name in ("README.md", "README.zh-CN.md"):
        text = (repo / name).read_text(encoding="utf-8")
        assert "actions/workflows/ci.yml/badge.svg" in text, f"{name} missing CI badge"
