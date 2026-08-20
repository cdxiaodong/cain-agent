"""Classic/orchestrated benchmark comparison tests (offline and deterministic)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))
from run_benchmark import Scenario, generate_comparison_report, run_comparison  # noqa: E402


def test_same_scenarios_run_in_both_modes() -> None:
    seen: list[tuple[str, str]] = []
    scenarios = [Scenario("s-1", {}), Scenario("s-2", {})]

    def classic(scenario: Scenario) -> dict[str, object]:
        seen.append(("classic", scenario.scenario_id))
        return {"findings": 2, "confirmed_findings": 1, "usage": {"total_tokens": 12}}

    def orchestrated(scenario: Scenario) -> dict[str, object]:
        seen.append(("orchestrated", scenario.scenario_id))
        return {"findings": 2, "confirmed_findings": 2, "usage": {"input_tokens": 10, "output_tokens": 5}}

    result = run_comparison("regression", scenarios, classic, orchestrated)
    assert seen == [("classic", "s-1"), ("classic", "s-2"), ("orchestrated", "s-1"), ("orchestrated", "s-2")]
    assert result.summary("classic").confirmation_rate == 0.5
    assert result.summary("classic").token_cost == 24
    assert result.summary("orchestrated").confirmation_rate == 1.0
    assert result.summary("orchestrated").token_cost == 30


def test_duration_and_runner_errors_are_retained() -> None:
    ticks = iter([1.0, 1.25, 2.0, 2.75])

    def failed(_: Scenario) -> dict[str, object]:
        raise RuntimeError("unavailable")

    result = run_comparison(
        "regression",
        [Scenario("s-1", {})],
        lambda _: {"findings": 0, "confirmed_findings": 0},
        failed,
        clock=lambda: next(ticks),
    )
    assert result.results[0].duration_sec == 0.25
    assert result.results[1].duration_sec == 0.75
    assert result.summary("orchestrated").errors == 1
    assert result.summary("classic").confirmation_rate == 0.0


def test_invalid_confirmation_count_is_rejected() -> None:
    runner = lambda _: {"findings": 1, "confirmed_findings": 2}  # noqa: E731
    with pytest.raises(ValueError, match="confirmed_findings"):
        run_comparison("regression", [Scenario("s-1", {})], runner, runner)


def test_report_contains_required_metrics(tmp_path: Path) -> None:
    result = run_comparison(
        "regression",
        [Scenario("s-1", {})],
        lambda _: {"findings": 2, "confirmed_findings": 1, "duration_sec": 1.25, "token_cost": 100},
        lambda _: {"findings": 2, "confirmed_findings": 2, "duration_sec": 1.5, "token_cost": 130},
    )
    output = tmp_path / "comparison.md"
    generate_comparison_report(result, output)
    text = output.read_text(encoding="utf-8")
    assert "finding 确认率" in text and "总耗时" in text and "token 消耗" in text
    assert "| classic | 50.0% | 1/2 | 1.250s | 100 | 0 |" in text
    assert "| orchestrated | 100.0% | 2/2 | 1.500s | 130 | 0 |" in text
