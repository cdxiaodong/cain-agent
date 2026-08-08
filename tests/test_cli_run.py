"""CLI run 子命令单元测试。

进程内调用 ``cain_agent.cli.main``,通过 monkeypatch sys.argv 和 stdout,
覆盖:dry-run 初始化、公网 target 无授权被拒、127.0.0.1 直通、非法参数 exit 2。
**严禁真实启动 Agent 循环烧 token**——_build_executor 被 monkeypatch 替身。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from cain_agent import __version__
from cain_agent.cli import build_parser, is_local_target, main

# ── helpers ─────────────────────────────────────────────────────────────────


def _run_cli(argv: list[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> int:
    """Run main() with *argv*, capturing stdout/stderr. Returns exit code.

    If main() calls sys.exit, the SystemExit code is returned.
    """
    monkeypatch.setattr(sys, "argv", ["cain-agent"] + argv)
    try:
        main()
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1


def _run_cli_captured(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str, str]:
    """Run main() and return (exit_code, stdout, stderr)."""
    code = _run_cli(argv, monkeypatch, Path())  # tmp_path not needed for arg parsing
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ── --version still works ───────────────────────────────────────────────────


class TestVersion:
    def test_version_flag(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run_cli_captured(["--version"], monkeypatch, capsys)
        assert code == 0
        assert f"cain-agent {__version__}" in out

    def test_no_args_prints_help(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, _ = _run_cli_captured([], monkeypatch, capsys)
        assert code == 0
        assert "usage:" in out


# ── is_local_target ─────────────────────────────────────────────────────────


class TestIsLocalTarget:
    """本地/私网 target 判定。"""

    def test_loopback_ip(self) -> None:
        assert is_local_target("127.0.0.1") is True

    def test_ipv6_loopback(self) -> None:
        assert is_local_target("::1") is True

    def test_localhost(self) -> None:
        assert is_local_target("localhost") is True

    def test_local_suffix(self) -> None:
        assert is_local_target("myapp.local") is True

    def test_private_ip(self) -> None:
        assert is_local_target("10.0.0.1") is True
        assert is_local_target("192.168.1.1") is True
        assert is_local_target("172.16.0.1") is True

    def test_loopback_with_port(self) -> None:
        assert is_local_target("127.0.0.1:8080") is True

    def test_private_ip_with_port(self) -> None:
        assert is_local_target("10.0.0.1:443") is True

    def test_public_domain(self) -> None:
        assert is_local_target("example.com") is False

    def test_public_ip(self) -> None:
        assert is_local_target("8.8.8.8") is False

    def test_public_ip_with_port(self) -> None:
        assert is_local_target("8.8.8.8:80") is False


# ── dry-run ─────────────────────────────────────────────────────────────────


class TestDryRun:
    def test_dry_run_initializes_workspace(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """dry-run 初始化 workspace + scope,打印执行计划,exit 0。"""
        ws = tmp_path / "ws"
        code, out, _ = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws), "--dry-run"],
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert "dry-run" in out.lower()
        assert "127.0.0.1" in out
        assert "recon" in out
        # Workspace directory created.
        assert ws.exists()
        # scope.yaml written with target.
        scope = ws / "scope.yaml"
        assert scope.exists()
        assert "127.0.0.1" in scope.read_text()
        # Stage dirs created.
        assert (ws / "recon").exists()
        assert (ws / "test").exists()
        assert (ws / "report").exists()

    def test_dry_run_does_not_start_agent(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """dry-run 绝不调用 _build_executor。"""
        called: list[bool] = []

        def fake_build(args: Any) -> Any:
            called.append(True)
            return object()

        monkeypatch.setattr("cain_agent.cli._build_executor", fake_build)
        _run_cli_captured(
            ["run", "--target", "localhost", "--workspace", str(tmp_path / "ws"), "--dry-run"],
            monkeypatch,
            capsys,
        )
        assert called == []  # executor never built

    def test_dry_run_public_target_needs_auth(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """dry-run 对公网 target 仍需授权标志。"""
        code, out, err = _run_cli_captured(
            ["run", "--target", "example.com", "--workspace", str(tmp_path / "ws"), "--dry-run"],
            monkeypatch,
            capsys,
        )
        assert code == 2
        assert "授权" in err or "authorization" in err.lower()

    def test_dry_run_public_with_auth(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """dry-run + 公网 target + --i-have-authorization → 通过。"""
        ws = tmp_path / "ws"
        code, out, _ = _run_cli_captured(
            [
                "run", "--target", "example.com",
                "--workspace", str(ws),
                "--dry-run",
                "--i-have-authorization",
            ],
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert "授权确认" in out


# ── authorization gate ──────────────────────────────────────────────────────


class TestAuthorizationGate:
    def test_public_target_without_auth_rejected(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """公网 target 无 --i-have-authorization → exit 2。"""
        code, out, err = _run_cli_captured(
            ["run", "--target", "8.8.8.8", "--workspace", str(tmp_path / "ws")],
            monkeypatch,
            capsys,
        )
        assert code == 2
        assert "授权" in err or "authorization" in err.lower()

    def test_public_target_with_auth_proceeds(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """公网 target + --i-have-authorization → 不被授权门拦(后续走 executor 替身)。"""
        # Mock executor build to avoid real Agent.
        monkeypatch.setattr("cain_agent.cli._build_executor", lambda args: _FakeExecutor())
        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            [
                "run", "--target", "1.1.1.1",
                "--workspace", str(ws),
                "--i-have-authorization",
            ],
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert "完成" in out

    def test_loopback_no_auth_needed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """127.0.0.1 不需要授权标志。"""
        monkeypatch.setattr("cain_agent.cli._build_executor", lambda args: _FakeExecutor())
        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 0

    def test_private_ip_no_auth_needed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """10.0.0.1 私网 IP 不需要授权标志。"""
        monkeypatch.setattr("cain_agent.cli._build_executor", lambda args: _FakeExecutor())
        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            ["run", "--target", "10.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 0

    def test_local_suffix_no_auth_needed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """.local 后缀不需要授权标志。"""
        monkeypatch.setattr("cain_agent.cli._build_executor", lambda args: _FakeExecutor())
        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            ["run", "--target", "myapp.local", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 0


# ── argument errors ─────────────────────────────────────────────────────────


class TestArgumentErrors:
    def test_run_without_target(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """run 不给 --target → argparse 报错 exit 2。"""
        monkeypatch.setattr(sys, "argv", ["cain-agent", "run", "--workspace", str(tmp_path)])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2

    def test_run_empty_target(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """run --target '' → exit 2。"""
        code, out, err = _run_cli_captured(
            ["run", "--target", "", "--workspace", str(tmp_path / "ws"), "--dry-run"],
            monkeypatch,
            capsys,
        )
        assert code == 2


# ── run with mocked executor (no real Agent) ────────────────────────────────


class TestRunWithMockExecutor:
    def test_run_completes_three_stages(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """完整 run(127.0.0.1 + mock executor)→ 三阶段跑完,exit 0。"""
        monkeypatch.setattr("cain_agent.cli._build_executor", lambda args: _FakeExecutor())
        ws = tmp_path / "ws"
        code, out, _ = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 0
        # Summary should mention all three stages.
        assert "recon" in out
        assert "test" in out
        assert "report" in out
        # Artifacts should exist.
        assert (ws / "recon" / "recon-placeholder.json").exists()

    def test_run_no_credentials_printed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """stdout 不包含任何凭证环境变量值。"""
        monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "LTAI" + "Z" * 20)
        monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "SuperSecret" + "X" * 20)
        monkeypatch.setattr("cain_agent.cli._build_executor", lambda args: _FakeExecutor())
        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert "LTAI" not in out
        assert "SuperSecret" not in out
        assert "LTAI" not in err
        assert "SuperSecret" not in err


# ── fake executor ───────────────────────────────────────────────────────────


class _FakeExecutor:
    """Minimal stand-in for SDKExecutor that Orchestrator accepts.

    Provides add_pre_tool_use_hook (no-op) so ScopeGuardHook mounting succeeds.
    Never calls the real SDK — zero token spend.
    """

    def add_pre_tool_use_hook(self, callback: Any, **kwargs: Any) -> None:
        pass  # no-op: ScopeGuardHook mounts but never fires

    def build_options(self) -> dict[str, Any]:
        return {"allowed_tools": ["Bash"]}


# ── build_parser ────────────────────────────────────────────────────────────


class TestBuildParser:
    def test_parser_has_run_subcommand(self) -> None:
        parser = build_parser()
        # Subparsers are stored in _subparsers group; check run exists.
        sub_actions = [
            a for a in parser._actions
            if hasattr(a, "choices") and a.choices is not None
        ]
        assert sub_actions, "no subparsers found"
        choices: set[str] = set()
        for sa in sub_actions:
            choices.update(sa.choices)  # type: ignore[union-attr]
        assert "run" in choices

    def test_run_requires_target(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["run"])
        assert exc_info.value.code == 2

    def test_run_parses_target(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["run", "--target", "127.0.0.1"])
        assert args.target == "127.0.0.1"
        assert args.command == "run"

    def test_run_defaults(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["run", "--target", "127.0.0.1"])
        assert args.workspace == "./workspace"
        assert args.idle_timeout == 300.0
        assert args.total_budget is None
        assert args.dry_run is False
        assert args.i_have_authorization is False
