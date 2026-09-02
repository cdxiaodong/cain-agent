"""Central orchestration wiring tests, all with fake executors."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from cain_agent.executor import ExecutorResult, SDKExecutor
from cain_agent.findings import (
    Finding,
    FindingResult,
    Severity,
    hash_evidence,
)
from cain_agent.multi_agent.orchestration import (
    AGGREGATED_REPORT_FILE,
    MARKDOWN_REPORT_FILE,
    build_orchestration,
    make_multi_agent_report_handler,
)
from cain_agent.orchestrator import Orchestrator, StageContext
from cain_agent.pipeline import FindingsPipeline
from cain_agent.workspace import Workspace


class ScriptedExecutor(SDKExecutor):
    def __init__(self, payload: dict[str, Any]) -> None:
        super().__init__()
        self.payload = payload
        self.prompts: list[str] = []

    async def run(self, prompt: str) -> ExecutorResult:
        self.prompts.append(prompt)
        return ExecutorResult(text=json.dumps(self.payload, ensure_ascii=False))


def _workspace(tmp_path: Path) -> Workspace:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "scope.yaml").write_text(
        "in_scope:\n  - example.com\nout_of_scope: []\n",
        encoding="utf-8",
    )
    return Workspace(root)


def _finding() -> Finding:
    return Finding(
        finding_id="f-sqli",
        result=FindingResult.VALIDATION_INCONCLUSIVE,
        severity=Severity.HIGH,
        evidence_hash=hash_evidence("response differs"),
        reason="疑似注入点",
        cloud="web",
        service="http",
        resource="http://example.com/login?id=1",
        issue_type="sqli",
    )


def test_report_aggregates_manager_solver_pool_and_memory(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    ws.save_findings([_finding().to_dict()])
    validation = ScriptedExecutor({"verdict": "confirmed"})
    orchestration = build_orchestration(validation)
    pipeline = FindingsPipeline(
        ws,
        discovery_executor=SDKExecutor(),
        validation_executor=validation,
        verification_pool=orchestration.verification_pool,
    )
    handler = make_multi_agent_report_handler(pipeline, orchestration)
    orch = Orchestrator(SDKExecutor(), ws, handlers={"report": handler})

    state = orch.run()

    assert len(validation.prompts) == 3, "默认验证池应有三个独立表决 session"
    report_path = ws.root / AGGREGATED_REPORT_FILE
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["route"] == "multi_agent"
    assert report["summary"] == {
        "total": 1,
        "results": {
            "confirmed": 1,
            "false_positive": 0,
            "validation_system_error": 0,
            "validation_inconclusive": 0,
        },
    }
    conclusion = report["conclusions"][0]
    assert conclusion["finding_id"] == "f-sqli"
    assert conclusion["result"] == "confirmed"
    assert 0.85 <= conclusion["confidence"] <= 0.95
    assert [basis["source"] for basis in conclusion["basis"]] == [
        "solver",
        "verification",
        "memory",
    ]
    assert "confirmed=3" in conclusion["basis"][1]["detail"]
    assert conclusion["consensus"] == "confirmed"
    assert conclusion["memory_hits"], "语义记忆应检索到验证上下文旁证"
    assert report["manager"]["dispatched_tasks"] == 2
    assert report["manager"]["aggregate_count"] == 1
    assert report["manager"]["blackboard"]["confirmed"] == 1
    assert (ws.root / MARKDOWN_REPORT_FILE).exists()
    markdown = (ws.root / MARKDOWN_REPORT_FILE).read_text(encoding="utf-8")
    assert "## 执行摘要" in markdown
    assert "example.com" in markdown, "授权范围应进执行摘要"
    assert "| recon |" in markdown and "| test |" in markdown, "阶段耗时表应含此前阶段"
    assert "## Findings 一览" in markdown and "⚪ **INFO**" in markdown
    assert conclusion["evidence_hash"] in markdown, "证据哈希应可引用"
    assert "## 修复建议" in markdown and "## 法律声明" in markdown
    assert not (ws.root / "report" / "report-placeholder.json").exists()
    assert state["history"][-1]["artifacts"] == [
        "report/validation-summary.json",
        "report/aggregated-report.json",
        "report/report.md",
    ]


def _canned_response(prompt: str) -> str:
    if "侦察 Agent" in prompt:
        return json.dumps({
            "endpoints": [
                {
                    "url": "http://127.0.0.1:8080/login",
                    "method": "GET",
                    "params": ["id"],
                }
            ]
        })
    if "测试 Agent" in prompt:
        return json.dumps({
            "findings": [
                {
                    "cloud": "web",
                    "service": "http",
                    "resource": "http://127.0.0.1:8080/login?id=1",
                    "issue_type": "sqli",
                    "evidence": "response differs",
                    "reason": "疑似注入点",
                    "suggested_severity": "high",
                }
            ]
        })
    return json.dumps({"verdict": "confirmed"})


class FakeExecutor:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    def add_pre_tool_use_hook(self, callback: Any, **kwargs: Any) -> None:
        return None

    async def run(self, prompt: str) -> ExecutorResult:
        self.prompts.append(prompt)
        return ExecutorResult(text=_canned_response(prompt))


def _mock_cli_executors(monkeypatch: Any) -> list[FakeExecutor]:
    built: list[FakeExecutor] = []

    def builder(args: Any) -> FakeExecutor:
        executor = FakeExecutor()
        built.append(executor)
        return executor

    monkeypatch.setattr("cain_agent.cli._build_executor", builder)
    monkeypatch.setattr("cain_agent.cli._build_validation_executor", builder)
    return built


def _run_cli(
    monkeypatch: Any,
    capsys: Any,
    argv: list[str],
) -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "argv", ["cain-agent", *argv])
    from cain_agent.cli import main

    try:
        main()
        code = 0
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 0
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_uses_central_route_by_default(
    monkeypatch: Any,
    capsys: Any,
    tmp_path: Path,
) -> None:
    built = _mock_cli_executors(monkeypatch)
    ws = tmp_path / "cli-ws"
    code, out, _ = _run_cli(
        monkeypatch,
        capsys,
        ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
    )

    assert code == 0
    assert len(built) == 2, "中心编排复用 Route A 的发现与校验 executor"
    report = json.loads((ws / AGGREGATED_REPORT_FILE).read_text(encoding="utf-8"))
    assert report["route"] == "multi_agent"
    assert report["summary"]["total"] == 1
    assert 0.85 <= report["conclusions"][0]["confidence"] <= 0.95
    assert not (ws / "report" / "report-placeholder.json").exists()
    assert (ws / MARKDOWN_REPORT_FILE).exists()
    assert "中心编排报告完成" in out


def test_cli_falls_back_to_route_a_when_orchestration_unavailable(
    monkeypatch: Any,
    capsys: Any,
    tmp_path: Path,
) -> None:
    _mock_cli_executors(monkeypatch)

    def unavailable(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("central route unavailable")

    monkeypatch.setattr("cain_agent.cli._build_orchestration", unavailable)
    ws = tmp_path / "fallback-ws"
    code, _, _ = _run_cli(
        monkeypatch,
        capsys,
        ["run", "--target", "127.0.0.1", "--workspace", str(ws)],
    )

    assert code == 0
    assert (ws / "report" / "validation-summary.json").exists()
    assert (ws / "report" / "report-placeholder.json").exists()
    assert not (ws / AGGREGATED_REPORT_FILE).exists()


def test_runtime_manager_failure_falls_back_to_route_a(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    ws = _workspace(tmp_path)
    ws.save_findings([_finding().to_dict()])
    validation = ScriptedExecutor({"verdict": "confirmed"})
    orchestration = build_orchestration(validation)
    pipeline = FindingsPipeline(
        ws,
        discovery_executor=SDKExecutor(),
        validation_executor=validation,
        verification_pool=orchestration.verification_pool,
    )

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("aggregate unavailable")

    monkeypatch.setattr(orchestration.manager, "aggregate_findings", boom)
    handler = make_multi_agent_report_handler(pipeline, orchestration)
    result = handler(StageContext(ws, "report", ws.stage_dir("report")))

    assert result.summary.startswith("中心编排不可用")
    placeholder = ws.root / "report" / "report-placeholder.json"
    payload = json.loads(placeholder.read_text(encoding="utf-8"))
    assert "aggregate unavailable" in payload["fallback_error"]
    assert payload["validation"]["results"]["confirmed"] == 1
    assert not (ws.root / AGGREGATED_REPORT_FILE).exists()
