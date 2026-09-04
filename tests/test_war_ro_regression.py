"""Regression tests for the contaminated WAR-RO run (test-60889214)."""

from __future__ import annotations

import json
from pathlib import Path

from cain_agent.executor import ExecutorResult, SDKExecutor
from cain_agent.findings import Finding, FindingResult
from cain_agent.handlers import RECON_STATUS_FILE, SkillLoader, make_recon_handler, make_test_handler
from cain_agent.orchestrator import StageContext
from cain_agent.pipeline import FindingsPipeline
from cain_agent.workspace import Workspace


class FakeExecutor(SDKExecutor):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text
        self.calls = 0

    async def run(self, prompt: str) -> ExecutorResult:
        self.calls += 1
        return ExecutorResult(text=self.text)


def _workspace(tmp_path: Path) -> Workspace:
    root = tmp_path / "war-ro"
    root.mkdir()
    (root / "scope.yaml").write_text(
        "in_scope:\n"
        "  - war-robr.com.br\n"
        "out_of_scope: []\n"
        "allow_implicit_subdomains: false\n"
        "block_non_public_targets: true\n",
        encoding="utf-8",
    )
    return Workspace(root)


def _ctx(ws: Workspace, stage: str) -> StageContext:
    return StageContext(ws, stage, ws.stage_dir(stage))


def test_target_com_xxe_is_stored_as_invalid_out_of_scope(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    ws.path("recon/endpoints.json").write_text(
        json.dumps([{"url": "https://war-robr.com.br/api"}]), encoding="utf-8"
    )
    ws.path(RECON_STATUS_FILE).write_text(
        json.dumps({"status": "valid", "endpoint_count": 1}), encoding="utf-8"
    )
    output = json.dumps({
        "findings": [{
            "cloud": "web",
            "service": "http",
            "resource": "http://target.com/api/process",
            "issue_type": "xxe",
            "evidence": "root:x:0:0:root:/root:/bin/bash",
            "reason": "fabricated passwd disclosure",
            "suggested_severity": "high",
        }]
    })
    handler = make_test_handler(FakeExecutor(output), SkillLoader(tmp_path / "no-skills"))
    handler(_ctx(ws, "test"))

    finding = Finding.from_dict(ws.load_findings()[0])
    assert finding.result is FindingResult.FALSE_POSITIVE
    assert set(finding.invalid_reasons) == {"INVALID", "OUT_OF_SCOPE", "CONTAMINATED"}
    assert finding.provenance is None


def test_structurally_invalid_recon_stops_test_without_executor(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    recon = make_recon_handler(
        FakeExecutor("not JSON"), SkillLoader(tmp_path / "no-skills")
    )
    recon_result = recon(_ctx(ws, "recon"))
    assert recon_result.data["status"] == "recon_invalid"

    test_executor = FakeExecutor('{"findings": []}')
    test_result = make_test_handler(
        test_executor, SkillLoader(tmp_path / "no-skills")
    )(_ctx(ws, "test"))
    assert test_result.data["status"] == "recon_invalid"
    assert test_executor.calls == 0


def test_report_gate_reclassifies_legacy_confirmed_target_com(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    ws.save_findings([{
        "finding_id": "test-60889214",
        "result": "confirmed",
        "severity": "info",
        "evidence_hash": "sha256:3ea8fa5469369aae1960bd7f9257d0a8a560e26b98ea7889687346935f744cc4",
        "reason": "legacy consensus",
        "cloud": "web",
        "service": "http",
        "resource": "http://target.com/api/process",
        "issue_type": "xxe",
    }])
    pipeline = FindingsPipeline(
        ws,
        discovery_executor=SDKExecutor(),
        validation_executor=FakeExecutor('{"result":"confirmed"}'),
    )
    pipeline.run_sync()
    finding = Finding.from_dict(ws.load_findings()[0])
    assert finding.result is FindingResult.FALSE_POSITIVE
    assert set(finding.invalid_reasons) == {"INVALID", "OUT_OF_SCOPE", "CONTAMINATED"}

