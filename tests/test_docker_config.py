"""Docker 配置静态校验。

不真的 build 镜像(CI 友好),只检查 Dockerfile / .dockerignore 的关键约束:
  - Dockerfile 存在且含非 root USER 指令
  - ENTRYPOINT 指向 cain-agent
  - 基础镜像为 python:3.11-slim
  - .dockerignore 排除 .git / .venv / tests / docs / skills
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def dockerfile_content() -> str:
    """读取 Dockerfile 全文;文件缺失则跳过全部测试。"""
    path = REPO_ROOT / "Dockerfile"
    if not path.exists():
        pytest.skip("Dockerfile not found")
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dockerignore_content() -> str:
    """读取 .dockerignore 全文。"""
    path = REPO_ROOT / ".dockerignore"
    if not path.exists():
        pytest.skip(".dockerignore not found")
    return path.read_text(encoding="utf-8")


# ── Dockerfile 校验 ──────────────────────────────────────────


class TestDockerfile:
    """Dockerfile 关键约束静态校验。"""

    def test_dockerfile_exists(self) -> None:
        """Dockerfile 存在于仓库根目录。"""
        assert (REPO_ROOT / "Dockerfile").exists(), "Dockerfile 缺失"

    def test_base_image_is_python_slim(self, dockerfile_content: str) -> None:
        """基础镜像为 python:3.11-slim。"""
        assert re.search(r"^FROM\s+python:3\.11-slim", dockerfile_content, re.MULTILINE), (
            "基础镜像应为 python:3.11-slim"
        )

    def test_non_root_user(self, dockerfile_content: str) -> None:
        """含非 root USER 指令(不在最后一行的 USER root)。"""
        user_lines = [
            line.strip()
            for line in dockerfile_content.splitlines()
            if line.strip().upper().startswith("USER ")
        ]
        assert len(user_lines) >= 1, "缺少 USER 指令"
        # 最后一条 USER 指令不能是 root
        final_user = user_lines[-1].removeprefix("USER ").strip()
        assert final_user != "root", "最终运行用户为 root,应使用非 root 用户"

    def test_user_is_cain(self, dockerfile_content: str) -> None:
        """非 root 用户为 cain。"""
        user_lines = [
            line.strip()
            for line in dockerfile_content.splitlines()
            if line.strip().upper().startswith("USER ")
        ]
        assert user_lines, "缺少 USER 指令"
        final_user = user_lines[-1].removeprefix("USER ").strip()
        assert final_user == "cain", f"非 root 用户应为 cain,实际为 {final_user}"

    def test_entrypoint_is_cain_agent(self, dockerfile_content: str) -> None:
        """ENTRYPOINT 指向 cain-agent。"""
        assert re.search(r'ENTRYPOINT\s+\[?\s*"?cain-agent"', dockerfile_content, re.IGNORECASE), (
            "ENTRYPOINT 应指向 cain-agent"
        )

    def test_pip_install_project(self, dockerfile_content: str) -> None:
        """通过 pip install . 安装项目。"""
        assert re.search(r"pip\s+install\s+\S*\s*\.\s*$", dockerfile_content, re.MULTILINE), (
            "应通过 pip install . 安装项目"
        )

    def test_no_hardcoded_credentials(self, dockerfile_content: str) -> None:
        """Dockerfile 中无硬编码凭证(ENV 含 KEY/SECRET/TOKEN/PASSWORD 等)。"""
        sensitive_pattern = re.compile(
            r"(?i)(ACCESS[_-]?KEY|SECRET[_-]?KEY|SECRET|TOKEN|PASSWORD|LTAI)"  # noqa: S105, S106
        )
        env_lines = [
            line
            for line in dockerfile_content.splitlines()
            if line.strip().upper().startswith("ENV ")
            or line.strip().upper().startswith("ARG ")
        ]
        for line in env_lines:
            assert not sensitive_pattern.search(line), (
                f"Dockerfile 中疑似硬编码凭证: {line.strip()}"
            )


# ── .dockerignore 校验 ───────────────────────────────────────


class TestDockerignore:
    """.dockerignore 关键排除项校验。"""

    def test_dockerignore_exists(self) -> None:
        """.dockerignore 存在于仓库根目录。"""
        assert (REPO_ROOT / ".dockerignore").exists(), ".dockerignore 缺失"

    def test_excludes_git(self, dockerignore_content: str) -> None:
        """排除 .git。"""
        assert ".git" in dockerignore_content, ".dockerignore 应排除 .git"

    def test_excludes_venv(self, dockerignore_content: str) -> None:
        """排除 .venv。"""
        assert ".venv" in dockerignore_content, ".dockerignore 应排除 .venv"

    def test_excludes_tests(self, dockerignore_content: str) -> None:
        """排除 tests/。"""
        assert "tests/" in dockerignore_content, ".dockerignore 应排除 tests/"

    def test_excludes_docs(self, dockerignore_content: str) -> None:
        """排除 docs/。"""
        assert "docs/" in dockerignore_content, ".dockerignore 应排除 docs/"

    def test_excludes_skills(self, dockerignore_content: str) -> None:
        """排除 skills/。"""
        assert "skills/" in dockerignore_content, ".dockerignore 应排除 skills/"

    def test_excludes_pycache(self, dockerignore_content: str) -> None:
        """排除 __pycache__。"""
        assert "__pycache__" in dockerignore_content, ".dockerignore 应排除 __pycache__"
