"""CLI run 子命令单元测试。

进程内调用 ``cain_agent.cli.main``,通过 monkeypatch sys.argv 和 stdout,
覆盖:dry-run 初始化、公网 target 无授权被拒、127.0.0.1 直通、非法参数 exit 2、
经典 Route A 真实 handler 注入与产物契约、双 executor 构造与构造失败兜底。
**严禁真实启动 Agent / 触网**——发现与校验两个 executor 构造器都被
``_mock_executors`` 换成假 executor(``run`` 按阶段 prompt 返回预制 JSON,
零 token 零网络)。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

import cain_agent.pipeline as pipeline_mod
from cain_agent import __version__
from cain_agent.cli import build_parser, is_local_target, main
from cain_agent.executor import ExecutorResult

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

    def test_public_domain_with_port(self) -> None:
        assert is_local_target("example.com:8080") is False


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
        """dry-run 绝不调用 executor / handler 构造器。"""
        called: list[bool] = []
        for attr in ("_build_executor", "_build_validation_executor", "_build_handlers"):
            monkeypatch.setattr(
                f"cain_agent.cli.{attr}",
                lambda *a: called.append(True),
            )
        _run_cli_captured(
            ["run", "--target", "localhost", "--workspace", str(tmp_path / "ws"), "--dry-run"],
            monkeypatch,
            capsys,
        )
        assert called == []  # 三个构造器一律不得触发

    def test_dry_run_public_target_allowed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """dry-run 对公网 target 直接放行（无授权门）。"""
        code, out, err = _run_cli_captured(
            ["run", "--target", "example.com", "--workspace", str(tmp_path / "ws"), "--dry-run"],
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert "执行计划" in out


# ── authorization gate ──────────────────────────────────────────────────────


class TestAuthorizationGate:
    def test_public_target_proceeds(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """公网 target 直接放行（无授权门），走 executor 替身。"""
        _mock_executors(monkeypatch)
        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            ["run", "--target", "public.example.com", "--workspace", str(ws)],
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
        _mock_executors(monkeypatch)
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
        _mock_executors(monkeypatch)
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
        _mock_executors(monkeypatch)
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
        """完整 run(127.0.0.1 + mock executors)→ 三阶段跑完,exit 0。"""
        _mock_executors(monkeypatch)
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
        # 真实 handler 落盘的真实产物(非 placeholder)。
        assert (ws / "recon" / "endpoints.json").exists()
        assert (ws / "findings.json").exists()
        assert (ws / "report" / "validation-summary.json").exists()

    def test_run_no_credentials_printed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """stdout 不包含任何凭证环境变量值。"""
        monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "LTAI" + "Z" * 20)
        monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "SuperSecret" + "X" * 20)
        _mock_executors(monkeypatch)
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


# ── classic Route A: 真实 handler 注入与产物契约 ───────────────────────────────


class TestClassicHandlers:
    def test_two_distinct_executor_constructions(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """发现 executor 与校验 executor 是两个独立构造,绝不共享 session。"""
        built = _mock_executors(monkeypatch)
        ws = tmp_path / "ws"
        code, out, _ = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert len(built) == 2
        assert built[0] is not built[1], "发现 executor 与校验 executor 必须是两个独立对象"

    def test_pipeline_receives_distinct_executors(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """FindingsPipeline 的 discovery/validation 参数是不同对象(防自证硬约束成立)。"""
        captured: dict[str, Any] = {}
        real_pipeline = pipeline_mod.FindingsPipeline

        def spy(workspace: Any, *, discovery_executor: Any, validation_executor: Any) -> Any:
            captured["discovery"] = discovery_executor
            captured["validation"] = validation_executor
            return real_pipeline(
                workspace,
                discovery_executor=discovery_executor,
                validation_executor=validation_executor,
            )

        monkeypatch.setattr("cain_agent.pipeline.FindingsPipeline", spy)
        _mock_executors(monkeypatch)
        ws = tmp_path / "ws"
        code, out, _ = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert captured, "FindingsPipeline 必须被构造"
        assert captured["discovery"] is not captured["validation"], "发现≠校验(§3.3)"

    def test_artifact_contract_classic_handlers(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """三阶段真实 handler 端到端落盘契约(recon→test→report 产物齐全)。"""
        _mock_executors(monkeypatch)
        ws = tmp_path / "ws"
        code, out, _ = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 0

        # recon: 端点草稿 + 原始输出(脱敏后)
        endpoints = json.loads((ws / "recon" / "endpoints.json").read_text(encoding="utf-8"))
        assert endpoints == [
            {
                "url": "http://127.0.0.1:8080/login",
                "method": "GET",
                "params": ["id"],
                "tech": "nginx/1.24",
                "notes": "登录页",
            }
        ]
        assert (ws / "recon" / "recon-output.txt").exists()

        # test: findings.json 落盘,校验流水线跑完后定级 confirmed
        findings = json.loads((ws / "findings.json").read_text(encoding="utf-8"))
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "sqli"
        assert findings[0]["resource"] == "http://127.0.0.1:8080/login?id=1"
        assert findings[0]["result"] == "confirmed"
        assert (ws / "test" / "test-output.txt").exists()

        # report: 校验汇总 + 中心编排真实聚合报告
        summary = json.loads(
            (ws / "report" / "validation-summary.json").read_text(encoding="utf-8")
        )
        assert summary["total"] == 1
        assert summary["results"]["confirmed"] == 1
        assert (ws / "report" / "aggregated-report.json").exists()
        assert (ws / "report" / "report.md").exists()

        # 状态机历史按 recon → test → report 钉死
        state = json.loads((ws / "state.json").read_text(encoding="utf-8"))
        assert [entry["stage"] for entry in state["history"]] == ["recon", "test", "report"]


# ── construction failure ─────────────────────────────────────────────────────


class TestConstructionFailure:
    def test_orchestrator_construction_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """Orchestrator 构造抛错:赋值前失败不引用未绑定局部变量,exit 2。"""
        _mock_executors(monkeypatch)

        def boom(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("boom")

        monkeypatch.setattr("cain_agent.cli.Orchestrator", boom)
        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 2
        assert "orchestrator 构造失败" in err
        assert "UnboundLocalError" not in err

    def test_handler_construction_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """FindingsPipeline 构造抛错 → handler 构造失败兜底,exit 2。"""
        _mock_executors(monkeypatch)

        def boom(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("pipeline boom")

        monkeypatch.setattr("cain_agent.pipeline.FindingsPipeline", boom)
        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 2
        assert "handler 构造失败" in err


# ── fake executor ───────────────────────────────────────────────────────────


def _canned_response(prompt: str) -> str:
    """按 prompt 中的 Agent 角色返回预制 JSON(测试专用,绝不触网)。"""
    if "侦察 Agent" in prompt:
        return json.dumps(
            {
                "endpoints": [
                    {
                        "url": "http://127.0.0.1:8080/login",
                        "method": "GET",
                        "params": ["id"],
                        "tech": "nginx/1.24",
                        "notes": "登录页",
                    }
                ]
            },
            ensure_ascii=False,
        )
    if "测试 Agent" in prompt:
        return json.dumps(
            {
                "findings": [
                    {
                        "cloud": "web",
                        "service": "http",
                        "resource": "http://127.0.0.1:8080/login?id=1",
                        "issue_type": "sqli",
                        "evidence": "响应差异: 200 vs 500",
                        "reason": "疑似注入点",
                        "suggested_severity": "high",
                    }
                ]
            },
            ensure_ascii=False,
        )
    if "校验 Agent" in prompt:
        return json.dumps(
            {"result": "confirmed", "severity": "high", "reason": "证据成立"},
            ensure_ascii=False,
        )
    return "{}"


class _FakeExecutor:
    """SDKExecutor 替身:async run 按阶段 prompt 返回预制 JSON,零网络零 token。

    Orchestrator 需要 ``add_pre_tool_use_hook``(挂 ScopeGuardHook),真实
    handler 需要 ``async run``(收 prompt 回 ExecutorResult);两者都实现,
    其余调用不触及真实 SDK。``prompts`` 记录收到的每次 prompt 供断言。
    """

    def __init__(self, session_id: str = "fake-session") -> None:
        self.session_id = session_id
        self.prompts: list[str] = []

    def add_pre_tool_use_hook(self, callback: Any, **kwargs: Any) -> None:
        pass  # no-op: ScopeGuardHook mounts but never fires

    def build_options(self) -> dict[str, Any]:
        return {"allowed_tools": ["Bash"]}

    async def run(self, prompt: str) -> ExecutorResult:
        self.prompts.append(prompt)
        return ExecutorResult(text=_canned_response(prompt), session_id=self.session_id)


def _mock_executors(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """把两个 executor 构造器都换成假 executor(零 token 零触网)。

    返回按构造顺序收集的假 executor:built[0]=发现,built[1]=校验。两者是
    独立对象,便于断言「发现 ≠ 校验」双 session 结构。
    """
    built: list[Any] = []

    def fake_build(args: Any) -> Any:
        session = _FakeExecutor(session_id=f"fake-{len(built)}")
        built.append(session)
        return session

    monkeypatch.setattr("cain_agent.cli._build_executor", fake_build)
    monkeypatch.setattr("cain_agent.cli._build_validation_executor", fake_build)
    return built


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
