"""Run a deterministic local finding through the real orchestration route."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cain_agent.executor import ExecutorResult, SDKExecutor
from cain_agent.findings import Finding as PipelineFinding
from cain_agent.findings import (
    FindingResult,
    Severity,
    hash_evidence,
)
from cain_agent.multi_agent.orchestration import (
    AGGREGATED_REPORT_FILE,
    build_orchestration,
    make_multi_agent_report_handler,
)
from cain_agent.orchestrator import StageContext
from cain_agent.pipeline import FindingsPipeline
from cain_agent.workspace import Workspace

DEFAULT_FIXTURE_PATH = Path(__file__).with_name("fixtures") / "local-ssti.json"


class OfflineValidationExecutor(SDKExecutor):
    """Deterministic validation session backed by the fixture evidence hash."""

    def __init__(self, expected_evidence_hash: str) -> None:
        super().__init__()
        self.expected_evidence_hash = expected_evidence_hash
        self.calls = 0

    async def run(self, prompt: str) -> ExecutorResult:
        self.calls += 1
        verdict = "confirmed" if self.expected_evidence_hash in prompt else "rejected"
        return ExecutorResult(text=json.dumps({"verdict": verdict}))


def load_fixture(path: Path = DEFAULT_FIXTURE_PATH) -> dict[str, Any]:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    required = {"scenario_id", "request", "response", "expected"}
    if not isinstance(fixture, dict) or not required.issubset(fixture):
        missing = sorted(required - set(fixture if isinstance(fixture, dict) else {}))
        raise ValueError(f"local finding fixture requires fields: {missing}")

    request = fixture["request"]
    response = fixture["response"]
    expected = fixture["expected"]
    if not all(isinstance(value, dict) for value in (request, response, expected)):
        raise ValueError("request, response, and expected must be objects")
    if expected.get("proof_marker") not in response.get("body", ""):
        raise ValueError("fixture response does not contain the expected proof marker")
    return fixture


def fixture_evidence(fixture: dict[str, Any]) -> str:
    """Canonicalize the request/response pair before evidence hashing."""

    return json.dumps(
        {"request": fixture["request"], "response": fixture["response"]},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def materialize_finding(fixture: dict[str, Any]) -> PipelineFinding:
    request = fixture["request"]
    expected = fixture["expected"]
    reason = str(expected.get("finding_reason", ""))
    if not reason.strip() or len(reason) > 30:
        raise ValueError("expected.finding_reason must be non-empty and at most 30 characters")

    return PipelineFinding(
        finding_id=str(fixture["scenario_id"]),
        result=FindingResult.VALIDATION_INCONCLUSIVE,
        severity=Severity.HIGH,
        evidence_hash=hash_evidence(fixture_evidence(fixture)),
        reason=reason,
        cloud="web",
        service="http",
        resource=str(request["url"]),
        issue_type=str(expected["issue_type"]),
    )


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def _require_closed_loop(report: dict[str, Any]) -> None:
    conclusions = report.get("conclusions")
    if not isinstance(conclusions, list) or not conclusions:
        raise RuntimeError("local fixture produced no findings")
    if report.get("summary", {}).get("results", {}).get("confirmed", 0) < 1:
        raise RuntimeError("local fixture finding was not confirmed")

    conclusion = conclusions[0]
    basis = conclusion.get("basis", [])
    sources = {item.get("source") for item in basis}
    required_sources = {"solver", "verification", "memory"}
    if not required_sources.issubset(sources):
        raise RuntimeError(f"local fixture evidence chain is incomplete: {sorted(sources)}")
    if conclusion.get("consensus") != "confirmed" or conclusion.get("confidence", 0) < 0.85:
        raise RuntimeError("local fixture did not produce a confirmed high-confidence conclusion")


def run_local_finding_fixture(
    output_path: Path,
    *,
    fixture_path: Path = DEFAULT_FIXTURE_PATH,
) -> dict[str, Any]:
    """Materialize one offline vulnerability and execute the central route."""

    fixture = load_fixture(fixture_path)
    candidate = materialize_finding(fixture)
    validation_executor = OfflineValidationExecutor(candidate.evidence_hash)

    with tempfile.TemporaryDirectory(prefix="cain-local-finding-") as temporary:
        workspace = Workspace(Path(temporary))
        workspace.path("scope.yaml").write_text(
            "in_scope:\n  - 127.0.0.1\nout_of_scope: []\n",
            encoding="utf-8",
        )
        workspace.save_findings([candidate.to_dict()])

        orchestration = build_orchestration(validation_executor)
        pipeline = FindingsPipeline(
            workspace,
            discovery_executor=SDKExecutor(),
            validation_executor=validation_executor,
            verification_pool=orchestration.verification_pool,
        )
        handler = make_multi_agent_report_handler(pipeline, orchestration)
        result = handler(StageContext(workspace, "report", workspace.stage_dir("report")))
        if result.data is None or not result.artifacts:
            raise RuntimeError("central report handler returned no report data")

        report_path = workspace.root / AGGREGATED_REPORT_FILE
        report = json.loads(report_path.read_text(encoding="utf-8"))
        _require_closed_loop(report)
        _write_report(output_path, report)
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local finding fixture")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE_PATH)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_local_finding_fixture(args.output, fixture_path=args.fixture)
    confirmed = report["summary"]["results"]["confirmed"]
    conclusion = report["conclusions"][0]
    print(f"本地 fixture 完成: confirmed={confirmed}, confidence={conclusion['confidence']:.1%}")


if __name__ == "__main__":
    main()
