"""Local deterministic finding fixture exercises the complete central route."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))
from local_finding_fixture import (  # noqa: E402
    DEFAULT_FIXTURE_PATH,
    fixture_evidence,
    load_fixture,
    materialize_finding,
    run_local_finding_fixture,
)

from cain_agent.findings import hash_evidence  # noqa: E402


def test_fixture_materializes_hashed_finding() -> None:
    fixture = load_fixture()
    finding = materialize_finding(fixture)

    assert finding.issue_type == "ssti"
    assert finding.evidence_hash == hash_evidence(fixture_evidence(fixture))
    assert finding.resource.startswith("http://127.0.0.1:9753/")
    serialized = finding.to_dict()
    assert fixture["response"]["body"] not in json.dumps(serialized)


def test_fixture_rejects_missing_proof_marker(tmp_path: Path) -> None:
    fixture = load_fixture()
    fixture["response"]["body"] = "render result: static text"
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")

    with pytest.raises(ValueError, match="proof marker"):
        load_fixture(path)


def test_fixture_confirms_finding_with_confidence_and_evidence_chain(
    tmp_path: Path,
) -> None:
    output = tmp_path / "aggregated-report.json"
    report = run_local_finding_fixture(output, fixture_path=DEFAULT_FIXTURE_PATH)

    assert report["route"] == "multi_agent"
    assert report["summary"]["total"] >= 1
    assert report["summary"]["results"]["confirmed"] >= 1
    conclusion = report["conclusions"][0]
    assert conclusion["consensus"] == "confirmed"
    assert conclusion["confidence"] >= 0.85
    assert [item["source"] for item in conclusion["basis"]][:2] == [
        "solver",
        "verification",
    ]
    assert "confirmed=3" in conclusion["basis"][1]["detail"]
    assert conclusion["memory_hits"]
    assert output.exists()
    assert json.loads(output.read_text(encoding="utf-8")) == report
