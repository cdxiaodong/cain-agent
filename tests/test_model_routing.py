"""阶段模型路由(pipeline 级混搭)单元测试 —— 2026-08-29 Phase 2.7 收官项。

覆盖 ``--recon-backend/--test-backend`` 及配套 provider/model 参数:

- **配置解析与缺省回退**:单阶段参数未指定时逐级回落 ``--backend`` /
  ``--pi-provider`` / ``--pi-model``;全部缺省时 recon/test 配置相等。
- **构造层**:配置相同(含全部缺省)→ 两阶段共享**同一个** executor 对象
  (与历史行为零变化,identity 断言);配置不同 → 各构造各的,类型与
  provider/model/白名单/超时参数按各自配置生效。
- **分发层**:混搭全流程(零 token 替身)下 recon prompt 只进 recon
  executor、test prompt 只进 test executor;两个通道都挂上 ScopeGuardHook,
  授权范围硬拦截不因路由降级。
- **CLI 面**:参数解析、非法值 exit 2、dry-run 路由展示与缺省零变化。

**严禁真实启动 Agent / 触网**——所有 executor 构造器都被 monkeypatch 成
替身(``run`` 按阶段 prompt 返回预制 JSON,零 token 零网络)。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from cain_agent import cli as cli_mod
from cain_agent.cli import (
    StageBackendConfig,
    _build_stage_executors,
    _resolve_stage_config,
    _stage_routing_overridden,
    build_parser,
    main,
)
from cain_agent.executor import ExecutorResult, ToolCallRecord, complete_tool_call
from cain_agent.pi_executor import PiExecutor

sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))
from local_finding_fixture import (  # noqa: E402
    OfflineValidationExecutor,
    fixture_evidence,
    load_fixture,
    materialize_finding,
)

# ── helpers ─────────────────────────────────────────────────────────────────


def _args(argv: list[str]) -> Any:
    """Parse a ``run`` argv into an argparse Namespace (defaults filled)."""
    return build_parser().parse_args(["run", "--target", "127.0.0.1"] + argv)


def _canned_response(prompt: str) -> str:
    """按 prompt 中的 Agent 角色返回预制 JSON(测试专用,绝不触网)。"""
    if "侦察 Agent" in prompt or "reconnaissance agent" in prompt:
        return json.dumps({"endpoints": []}, ensure_ascii=False)
    if "测试 Agent" in prompt or "testing agent" in prompt:
        return json.dumps({"findings": []}, ensure_ascii=False)
    if "校验 Agent" in prompt or "validation agent" in prompt:
        return json.dumps(
            {"result": "confirmed", "severity": "high", "reason": "证据成立"},
            ensure_ascii=False,
        )
    return "{}"


class _RoutingFakeExecutor:
    """executor 替身:记录每次 prompt 与每次 hook 挂载,零网络零 token。

    与 test_cli_run 的 ``_FakeExecutor`` 相同的 canned 契约,额外把
    ``add_pre_tool_use_hook`` 从 no-op 改为记录——scope 硬拦截双挂载的
    断言依赖这份记录。
    """

    def __init__(self, session_id: str = "fake-session") -> None:
        self.session_id = session_id
        self.prompts: list[str] = []
        self.hooks: list[Any] = []

    def add_pre_tool_use_hook(self, callback: Any, **kwargs: Any) -> None:
        self.hooks.append(callback)

    def build_options(self) -> dict[str, Any]:
        return {"allowed_tools": ["Bash"]}

    async def run(self, prompt: str) -> ExecutorResult:
        self.prompts.append(prompt)
        return ExecutorResult(text=_canned_response(prompt), session_id=self.session_id)


def _run_cli_captured(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str, str]:
    """Run main() and return (exit_code, stdout, stderr)."""
    monkeypatch.setattr(sys, "argv", ["cain-agent"] + argv)
    try:
        main()
        code = 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _mock_validation_executor(monkeypatch: pytest.MonkeyPatch) -> _RoutingFakeExecutor:
    """校验 executor 构造器换成替身(零 token 零触网),返回替身供断言。"""
    fake = _RoutingFakeExecutor(session_id="fake-validation")
    monkeypatch.setattr("cain_agent.cli._build_validation_executor", lambda args: fake)
    return fake


# ── 配置解析与缺省回退 ──────────────────────────────────────────────────────


class TestStageConfigResolution:
    def test_defaults_fall_back_to_global(self) -> None:
        """全部缺省:两阶段配置都等于全局 backend 配置,且互相相等。"""
        args = _args([])
        recon = _resolve_stage_config(args, "recon")
        test = _resolve_stage_config(args, "test")
        assert recon == StageBackendConfig(backend="claude", provider="anthropic", model=None)
        assert test == recon

    def test_recon_backend_override_only_touches_recon(self) -> None:
        """--recon-backend pi 只改 recon;test 仍回落全局 claude。"""
        args = _args(["--recon-backend", "pi"])
        assert _resolve_stage_config(args, "recon").backend == "pi"
        assert _resolve_stage_config(args, "test").backend == "claude"

    def test_stage_provider_model_override_and_fallback(self) -> None:
        """--recon-provider/--recon-model 覆盖本阶段;test 阶段回落 --pi-*。"""
        args = _args(
            [
                "--backend",
                "pi",
                "--pi-provider",
                "openai",
                "--pi-model",
                "gpt-x",
                "--recon-provider",
                "deepseek",
                "--recon-model",
                "cheap-x",
            ]
        )
        recon = _resolve_stage_config(args, "recon")
        test = _resolve_stage_config(args, "test")
        assert recon == StageBackendConfig(backend="pi", provider="deepseek", model="cheap-x")
        assert test == StageBackendConfig(backend="pi", provider="openai", model="gpt-x")

    def test_claude_override_of_pi_global(self) -> None:
        """--backend pi 下 --recon-backend claude:recon 换引擎回 claude。"""
        args = _args(["--backend", "pi", "--recon-backend", "claude"])
        assert _resolve_stage_config(args, "recon").backend == "claude"
        assert _resolve_stage_config(args, "test").backend == "pi"

    def test_test_stage_full_override(self) -> None:
        """--test-* 三件套全量覆盖 test 阶段,recon 不受影响。"""
        args = _args(
            [
                "--test-backend",
                "pi",
                "--test-provider",
                "google",
                "--test-model",
                "gemini-x",
            ]
        )
        test = _resolve_stage_config(args, "test")
        assert test == StageBackendConfig(backend="pi", provider="google", model="gemini-x")
        assert _resolve_stage_config(args, "recon").backend == "claude"

    def test_explicit_same_config_resolves_equal(self) -> None:
        """显式 pi+pi 且 provider/model 相同:配置相等 → 共享 executor 的判据成立。"""
        args = _args(["--recon-backend", "pi", "--test-backend", "pi"])
        assert _resolve_stage_config(args, "recon") == _resolve_stage_config(args, "test")

    def test_routing_overridden_flag(self) -> None:
        """任意单阶段参数出现即路由生效;全缺省为 False。"""
        assert _stage_routing_overridden(_args([])) is False
        assert _stage_routing_overridden(_args(["--recon-model", "m"])) is True
        assert _stage_routing_overridden(_args(["--test-backend", "pi"])) is True


# ── 构造层:共享 vs 各走各的 ─────────────────────────────────────────────────


class TestStageExecutors:
    def test_default_shares_single_executor(self) -> None:
        """缺省:recon/test 是同一个 executor 对象(与历史行为零变化)。"""
        recon, test = _build_stage_executors(_args([]))
        assert recon is test

    def test_mixed_routing_builds_two_executors(self) -> None:
        """混搭 recon=pi/test=claude:两对象、类型与 pi 参数各自正确。"""
        args = _args(
            [
                "--recon-backend",
                "pi",
                "--recon-provider",
                "deepseek",
                "--recon-model",
                "cheap-x",
                "--idle-timeout",
                "120",
                "--total-budget",
                "600",
            ]
        )
        recon, test = _build_stage_executors(args)
        assert recon is not test
        assert isinstance(recon, PiExecutor)
        assert recon.provider == "deepseek"
        assert recon.model == "cheap-x"
        assert recon.allowed_tools == cli_mod.DEFAULT_ALLOWED_TOOLS
        assert recon.idle_timeout == 120.0
        assert recon.total_budget == 600.0
        # test 回落全局 claude → SDKExecutor
        assert type(test).__name__ == "SDKExecutor"
        assert test.allowed_tools == cli_mod.DEFAULT_ALLOWED_TOOLS

    def test_explicit_same_config_still_shares(self) -> None:
        """显式 --recon-backend pi --test-backend pi(同 provider/model):仍共享。"""
        recon, test = _build_stage_executors(_args(["--recon-backend", "pi", "--test-backend", "pi"]))
        assert recon is test
        assert isinstance(recon, PiExecutor)

    def test_provider_only_override_splits_executors(self) -> None:
        """--backend pi 下仅 --test-provider deepseek:配置不同即两 executor。"""
        args = _args(["--backend", "pi", "--test-provider", "deepseek"])
        recon, test = _build_stage_executors(args)
        assert recon is not test
        assert isinstance(recon, PiExecutor)
        assert isinstance(test, PiExecutor)
        assert recon.provider == "anthropic"
        assert test.provider == "deepseek"


# ── 分发层:全流程两阶段各走各的 executor + scope 硬拦截双挂载 ──────────────


class TestRoutedRunIntegration:
    def _mock_mixed_stage_build(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[_RoutingFakeExecutor, _RoutingFakeExecutor, list[StageBackendConfig]]:
        """把混搭路径的 ``_build_stage_executor`` 换成替身构造器。

        返回 (recon_fake, test_fake, configs):configs 记录每次构造收到的
        阶段配置,供断言"按解析后配置构造"。
        """
        recon_fake = _RoutingFakeExecutor(session_id="fake-recon")
        test_fake = _RoutingFakeExecutor(session_id="fake-test")
        configs: list[StageBackendConfig] = []

        def fake_build(args: Any, config: StageBackendConfig) -> Any:
            configs.append(config)
            return recon_fake if config.backend == "pi" else test_fake

        monkeypatch.setattr("cain_agent.cli._build_stage_executor", fake_build)
        return recon_fake, test_fake, configs

    def test_mixed_routing_dispatches_per_stage(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """混搭全流程:recon prompt 只进 recon executor,test prompt 只进 test。"""
        recon_fake, test_fake, configs = self._mock_mixed_stage_build(monkeypatch)
        validation_fake = _mock_validation_executor(monkeypatch)
        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            [
                "run",
                "--target",
                "127.0.0.1",
                "--workspace",
                str(ws),
                "--recon-backend",
                "pi",
                "--recon-provider",
                "deepseek",
                "--recon-model",
                "cheap-x",
            ],
            monkeypatch,
            capsys,
        )
        assert code == 0, f"exit={code} stderr={err}"
        # 两阶段各构造一次,配置按各自解析结果
        assert len(configs) == 2
        assert configs[0] == StageBackendConfig("pi", "deepseek", "cheap-x")
        assert configs[1].backend == "claude"
        # 分发:侦察 prompt 只进 recon 通道,测试 prompt 只进 test 通道
        assert recon_fake.prompts and all("reconnaissance agent" in p for p in recon_fake.prompts)
        assert test_fake.prompts and all("testing agent" in p for p in test_fake.prompts)
        assert not any("reconnaissance agent" in p for p in test_fake.prompts)
        assert not any("testing agent" in p for p in recon_fake.prompts)
        # 校验通道独立(防自证)
        assert not validation_fake.prompts or all("校验 Agent" in p for p in validation_fake.prompts)

    def test_scope_guard_mounted_on_both_channels(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """混搭下两个执行通道都挂上 ScopeGuardHook,无一绕过 scope 判定。"""
        recon_fake, test_fake, _ = self._mock_mixed_stage_build(monkeypatch)
        _mock_validation_executor(monkeypatch)
        ws = tmp_path / "ws"
        code, _, err = _run_cli_captured(
            [
                "run",
                "--target",
                "127.0.0.1",
                "--workspace",
                str(ws),
                "--recon-backend",
                "pi",
            ],
            monkeypatch,
            capsys,
        )
        assert code == 0, f"exit={code} stderr={err}"
        # test 通道由 Orchestrator 挂,recon 通道由 CLI 补挂——各至少一个
        assert len(test_fake.hooks) >= 1, "test 通道必须有 scope 硬拦截"
        assert len(recon_fake.hooks) >= 1, "recon 通道必须有 scope 硬拦截(混搭补挂)"

    def test_default_run_keeps_single_session(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """缺省全流程:两阶段 prompt 进同一个 executor,hook 恰 1 个(零变化)。"""
        shared = _RoutingFakeExecutor(session_id="fake-shared")
        built: list[Any] = []
        monkeypatch.setattr(
            "cain_agent.cli._build_executor",
            lambda args: (built.append(shared), shared)[1],
        )
        _mock_validation_executor(monkeypatch)
        ws = tmp_path / "ws"
        code, _, err = _run_cli_captured(
            ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
            monkeypatch,
            capsys,
        )
        assert code == 0, f"exit={code} stderr={err}"
        # 同一 executor 依次吃了侦察与测试两类 prompt
        assert any("reconnaissance agent" in p for p in shared.prompts)
        assert any("testing agent" in p for p in shared.prompts)
        # Orchestrator 挂了 1 个 guard;无混搭 → 不存在补挂
        assert len(shared.hooks) == 1


# ── CLI 参数面与 dry-run 展示 ───────────────────────────────────────────────


class TestParserAndDryRun:
    def test_new_flags_default_none(self) -> None:
        args = _args([])
        assert args.recon_backend is None
        assert args.recon_provider is None
        assert args.recon_model is None
        assert args.test_backend is None
        assert args.test_provider is None
        assert args.test_model is None

    def test_invalid_stage_backend_rejected(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["run", "--target", "127.0.0.1", "--recon-backend", "openai"])
        assert exc_info.value.code == 2

    def test_dry_run_shows_routing_when_overridden(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """dry-run 混搭:展示两阶段后端与共享会话状态。"""
        code, out, _ = _run_cli_captured(
            [
                "run",
                "--target",
                "127.0.0.1",
                "--workspace",
                str(tmp_path / "ws"),
                "--dry-run",
                "--recon-backend",
                "pi",
                "--recon-provider",
                "deepseek",
                "--recon-model",
                "cheap-x",
            ],
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert "recon 后端: pi(deepseek/cheap-x)" in out
        assert "test 后端:  claude" in out
        assert "共享发现会话: 否" in out

    def test_dry_run_silent_without_routing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """dry-run 缺省:无路由段落输出(展示面零变化)。"""
        code, out, _ = _run_cli_captured(
            [
                "run",
                "--target",
                "127.0.0.1",
                "--workspace",
                str(tmp_path / "ws"),
                "--dry-run",
            ],
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert "recon 后端" not in out
        assert "共享发现会话" not in out


# ── 混搭冒烟:local finding fixture 离线闭环 ────────────────────────────────


class _ScriptedExecutor:
    """固定应答 executor 替身:``run`` 恒返回构造时给定文本,零网络零 token。

    与 ``_RoutingFakeExecutor`` 同契约,差别在应答不按 prompt 角色现算,
    而是回放构造方(bench fixture 冒烟)预制好的整段 JSON——test 阶段的
    应答由 fixture 请求/响应对现场生成,evidence 走真实哈希链路。
    """

    def __init__(self, response_text: str, session_id: str) -> None:
        self.session_id = session_id
        self.response_text = response_text
        self.prompts: list[str] = []
        self.hooks: list[Any] = []

    def add_pre_tool_use_hook(self, callback: Any, **kwargs: Any) -> None:
        self.hooks.append(callback)

    def build_options(self) -> dict[str, Any]:
        return {"allowed_tools": ["Bash"]}

    async def run(self, prompt: str) -> ExecutorResult:
        self.prompts.append(prompt)
        result = ExecutorResult(text=self.response_text, session_id=self.session_id)
        if "testing agent" in prompt or "测试 Agent" in prompt:
            fixture = load_fixture()
            call = ToolCallRecord(
                tool_use_id="fixture-request-1",
                name="Bash",
                input={"command": f"curl -i '{fixture['request']['url']}'"},
            )
            complete_tool_call(
                call,
                f"HTTP/1.1 {fixture['response']['status']} OK\n\n{fixture['response']['body']}",
                succeeded=True,
            )
            result.tool_calls.append(call)
        return result


class TestMixedRoutingFixtureSmoke:
    """混搭路由全流程 × local finding fixture:三通道各走各的,闭环照常确认。

    场景:``--backend pi``(全局 pi 高能力 anthropic/glm-5.3)下
    ``--recon-provider deepseek``(recon 低成本)+ ``--test-backend claude``
    (test 高能力)+ ``--pi-validation-provider deepseek``(report 校验通道
    低成本)。发现通道用固定应答替身、校验通道用 fixture 的确定性
    ``OfflineValidationExecutor``(按证据哈希判 confirmed),全程零 token
    零触网;校验通道的路由解析由 ``test_cli_validation_executor_uses_
    independent_config`` 单独钉死,此处不重复构造真实 PiExecutor。
    """

    def test_mixed_routing_smoke_closes_fixture_loop(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        fixture = load_fixture()
        finding = materialize_finding(fixture)

        # recon 应答:fixture 端点草稿;test 应答:按 fixture 现场回放 finding,
        # evidence 即规范化请求/响应对——与 materialize_finding 的哈希同源。
        recon_response = json.dumps(
            {
                "endpoints": [
                    {
                        "url": fixture["request"]["url"],
                        "method": "GET",
                        "params": ["template"],
                        "tech": "nginx",
                        "notes": "模板渲染端点",
                    }
                ]
            },
            ensure_ascii=False,
        )
        test_response = json.dumps(
            {
                "findings": [
                    {
                        "cloud": "web",
                        "service": "http",
                        "resource": fixture["request"]["url"],
                        "issue_type": fixture["expected"]["issue_type"],
                        "evidence": fixture_evidence(fixture),
                        "reason": fixture["expected"]["finding_reason"],
                        "suggested_severity": "high",
                    }
                ]
            },
            ensure_ascii=False,
        )
        recon_fake = _ScriptedExecutor(recon_response, "smoke-recon-pi-deepseek")
        test_fake = _ScriptedExecutor(test_response, "smoke-test-claude")
        configs: list[StageBackendConfig] = []

        def fake_stage_build(args: Any, config: StageBackendConfig) -> Any:
            configs.append(config)
            return recon_fake if config.backend == "pi" else test_fake

        monkeypatch.setattr("cain_agent.cli._build_stage_executor", fake_stage_build)
        validation = OfflineValidationExecutor(finding.evidence_hash)
        monkeypatch.setattr("cain_agent.cli._build_validation_executor", lambda args: validation)

        ws = tmp_path / "ws"
        code, out, err = _run_cli_captured(
            [
                "run",
                "--target",
                "127.0.0.1",
                "--workspace",
                str(ws),
                "--backend",
                "pi",
                "--pi-provider",
                "anthropic",
                "--pi-model",
                "glm-5.3",
                "--recon-provider",
                "deepseek",
                "--recon-model",
                "deepseek-chat",
                "--test-backend",
                "claude",
                "--pi-validation-provider",
                "deepseek",
                "--pi-validation-model",
                "deepseek-chat",
            ],
            monkeypatch,
            capsys,
        )
        assert code == 0, f"exit={code} stderr={err}"

        # 路由解析:recon=pi(deepseek 低成本)/ test=claude(高能力),各构造一次。
        assert configs == [
            StageBackendConfig("pi", "deepseek", "deepseek-chat"),
            StageBackendConfig("claude", "anthropic", "glm-5.3"),
        ]
        assert any("reconnaissance agent" in p for p in recon_fake.prompts)
        assert any("testing agent" in p for p in test_fake.prompts)
        assert not any("testing agent" in p for p in recon_fake.prompts)

        # scope 硬拦截双挂载:两通道都过同一套 ScopeGuardHook 判定。
        assert len(test_fake.hooks) >= 1
        assert len(recon_fake.hooks) >= 1

        # fixture 闭环:发现按真实哈希链路落盘,校验池多数确认,聚合高置信。
        findings = json.loads((ws / "findings.json").read_text(encoding="utf-8"))
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "ssti"
        assert findings[0]["resource"] == fixture["request"]["url"]
        assert findings[0]["evidence_hash"] == finding.evidence_hash
        assert findings[0]["result"] == "confirmed"

        summary = json.loads((ws / "report" / "validation-summary.json").read_text(encoding="utf-8"))
        assert summary["results"]["confirmed"] == 1

        report = json.loads((ws / "report" / "aggregated-report.json").read_text(encoding="utf-8"))
        assert report["summary"]["results"]["confirmed"] == 1
        conclusion = report["conclusions"][0]
        assert conclusion["consensus"] == "confirmed"
        assert conclusion["confidence"] >= 0.85
        sources = {item["source"] for item in conclusion["basis"]}
        assert {"solver", "verification"} <= sources
        assert validation.calls >= 3  # 并行验证池 3 session 都吃过哈希判确认
