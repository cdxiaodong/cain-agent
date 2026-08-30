from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "gitee_sync.sh"


def make_repository(path: Path) -> None:
    path.mkdir()
    environment = base_environment()
    subprocess.run(
        ["git", "init", "--initial-branch", "main"],
        cwd=path,
        env=environment,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "-m",
            "initial commit",
        ],
        cwd=path,
        env=environment,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/example/cain-agent.git"],
        cwd=path,
        env=environment,
        check=True,
    )


def base_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GITEE_TOKEN": "test-gitee-token",
            "GITEE_OWNER": "mirror-owner",
            "GITEE_REPO": "cain-agent",
        }
    )
    return environment


def run_sync(repository: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPT), *arguments],
        cwd=repository,
        env=base_environment(),
        text=True,
        capture_output=True,
        check=False,
    )


def test_script_exists_and_is_executable() -> None:
    assert SCRIPT.exists()
    assert SCRIPT.stat().st_mode & 0o111


def test_dry_run_validates_configuration_and_builds_mirror_command(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    make_repository(repository)

    result = run_sync(repository, ["--dry-run"])

    assert result.returncode == 0, result.stderr
    assert "Source remote: origin" in result.stdout
    assert "Source ref: main" in result.stdout
    assert "Destination: https://gitee.com/mirror-owner/cain-agent.git" in result.stdout
    assert "[dry-run] git push --mirror https://oauth2@gitee.com/mirror-owner/cain-agent.git" in result.stdout
    assert "test-gitee-token" not in result.stdout
    assert "test-gitee-token" not in result.stderr


def test_dry_run_rejects_missing_source_remote(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    make_repository(repository)
    subprocess.run(
        ["git", "remote", "remove", "origin"],
        cwd=repository,
        env=base_environment(),
        check=True,
    )

    result = run_sync(repository, ["--dry-run", "--source-remote", "missing"])

    assert result.returncode != 0
    assert "Source remote does not exist: missing" in result.stderr
    assert "git push --mirror" not in result.stdout


def test_missing_token_is_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    make_repository(repository)
    environment = base_environment()
    environment.pop("GITEE_TOKEN")

    result = subprocess.run(
        [str(SCRIPT), "--dry-run"],
        cwd=repository,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "GITEE_TOKEN is required" in result.stderr


def test_real_push_uses_environment_credential_without_embedding_token() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "GITEE_TOKEN" in script
    assert "credential.helper" in script
    assert "push --mirror" in script
    assert "https://oauth2:" not in script
