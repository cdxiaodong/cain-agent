"""Benchmark runners and classic/orchestrated comparison reports."""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class BenchmarkResult:
    suite: str
    total_scenarios: int
    true_positives: int
    false_positives: int
    false_negatives: int
    avg_duration_sec: float
    avg_token_cost: int

    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total else 0.0

    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total else 0.0

    @property
    def f1_score(self) -> float:
        total = self.precision + self.recall
        return 2 * self.precision * self.recall / total if total else 0.0


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    mode: str
    findings: int
    confirmed_findings: int
    duration_sec: float
    token_cost: int
    error: str | None = None

    @property
    def confirmation_rate(self) -> float:
        return self.confirmed_findings / self.findings if self.findings else 0.0


@dataclass(frozen=True)
class ModeSummary:
    mode: str
    scenarios: int
    findings: int
    confirmed_findings: int
    duration_sec: float
    token_cost: int
    errors: int

    @property
    def confirmation_rate(self) -> float:
        return self.confirmed_findings / self.findings if self.findings else 0.0


@dataclass(frozen=True)
class ComparisonResult:
    suite: str
    scenarios: tuple[str, ...]
    results: tuple[ScenarioResult, ...]

    def summary(self, mode: str) -> ModeSummary:
        selected = [item for item in self.results if item.mode == mode]
        return ModeSummary(
            mode,
            len(selected),
            sum(x.findings for x in selected),
            sum(x.confirmed_findings for x in selected),
            sum(x.duration_sec for x in selected),
            sum(x.token_cost for x in selected),
            sum(x.error is not None for x in selected),
        )


ModeRunner = Callable[[Scenario], Mapping[str, Any]]


def _token_cost(usage: Mapping[str, Any] | None) -> int:
    if not usage:
        return 0
    total = usage.get("total_tokens")
    if isinstance(total, (int, float)):
        return int(total)
    keys = ("input_tokens", "output_tokens", "cache_creation_input_tokens")
    return sum(int(usage.get(key, 0) or 0) for key in keys)


def _normalize_result(
    scenario: Scenario, mode: str, raw: Mapping[str, Any], measured_duration: float
) -> ScenarioResult:
    findings = int(raw.get("findings", 0))
    confirmed = int(raw.get("confirmed_findings", 0))
    if findings < 0 or confirmed < 0 or confirmed > findings:
        raise ValueError(f"{scenario.scenario_id}/{mode}: confirmed_findings must be between 0 and findings")
    duration = raw.get("duration_sec", measured_duration)
    token_cost = raw.get("token_cost")
    usage = raw.get("usage")
    return ScenarioResult(
        scenario.scenario_id,
        mode,
        findings,
        confirmed,
        float(duration),
        int(token_cost) if token_cost is not None else _token_cost(usage),
        str(raw["error"]) if raw.get("error") else None,
    )


def run_comparison(
    suite: str,
    scenarios: Iterable[Scenario],
    classic_runner: ModeRunner,
    orchestrated_runner: ModeRunner,
    *,
    clock: Callable[[], float] = time.perf_counter,
) -> ComparisonResult:
    """Run the exact same materialized scenario set in both modes."""
    materialized = tuple(scenarios)
    identifiers = tuple(item.scenario_id for item in materialized)
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("scenario_id values must be unique")
    results: list[ScenarioResult] = []
    for mode, runner in (("classic", classic_runner), ("orchestrated", orchestrated_runner)):
        for scenario in materialized:
            started = clock()
            try:
                raw = runner(scenario)
            except Exception as exc:  # keep other scenarios comparable after a runner failure
                raw = {"error": f"{type(exc).__name__}: {exc}"}
            results.append(_normalize_result(scenario, mode, raw, max(0.0, clock() - started)))
    return ComparisonResult(suite, identifiers, tuple(results))


def generate_comparison_report(result: ComparisonResult, output_path: Path) -> None:
    lines = [
        "# Benchmark 经典与编排模式对比",
        "",
        f"- 评测套件: {result.suite}",
        f"- 同组场景数: {len(result.scenarios)}",
        "",
        "## 汇总对比",
        "",
        "| 模式 | finding 确认率 | 已确认/总 finding | 总耗时 | token 消耗 | 错误数 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for summary in (result.summary("classic"), result.summary("orchestrated")):
        lines.append(
            f"| {summary.mode} | {summary.confirmation_rate:.1%} | "
            f"{summary.confirmed_findings}/{summary.findings} | "
            f"{summary.duration_sec:.3f}s | {summary.token_cost} | {summary.errors} |"
        )
    lines += [
        "",
        "## 逐场景明细",
        "",
        "| 场景 | 模式 | finding 确认率 | 耗时 | token 消耗 | 状态 |",
        "|---|---|---:|---:|---:|---|",
    ]
    for item in result.results:
        status = item.error.replace("|", "\\|") if item.error else "ok"
        lines.append(
            f"| {item.scenario_id} | {item.mode} | {item.confirmation_rate:.1%} "
            f"({item.confirmed_findings}/{item.findings}) | {item.duration_sec:.3f}s | "
            f"{item.token_cost} | {status} |"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_comparison(path: Path) -> tuple[str, list[Scenario], ModeRunner, ModeRunner]:
    """Load recorded outputs so a comparison can be reproduced offline."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("scenarios")
    if not isinstance(rows, list):
        raise ValueError("comparison input requires a scenarios list")
    scenarios = [Scenario(str(row["id"]), dict(row.get("payload", {}))) for row in rows]
    by_id = {scenario.scenario_id: row for scenario, row in zip(scenarios, rows, strict=True)}

    def runner(mode: str) -> ModeRunner:
        def recorded(scenario: Scenario) -> Mapping[str, Any]:
            value = by_id[scenario.scenario_id].get(mode)
            if not isinstance(value, dict):
                raise ValueError(f"{scenario.scenario_id}: missing {mode} result")
            return value

        return recorded

    return str(payload.get("suite", path.stem)), scenarios, runner("classic"), runner("orchestrated")


def generate_report(result: BenchmarkResult, output_path: Path) -> None:
    report = f"""# Benchmark 评测报告

**评测套件**: {result.suite}

## 核心指标

| 指标 | 值 |
|---|---|
| 总场景数 | {result.total_scenarios} |
| 检出率（Recall） | {result.recall:.1%} |
| 精确率（Precision） | {result.precision:.1%} |
| F1 分数 | {result.f1_score:.3f} |
| 平均耗时 | {result.avg_duration_sec:.1f}s |
| 平均 token 成本 | {result.avg_token_cost} |

## 混淆矩阵

| | 预测阳性 | 预测阴性 |
|---|---|---|
| **实际阳性** | {result.true_positives} | {result.false_negatives} |
| **实际阴性** | {result.false_positives} | - |
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    print(f"报告已生成: {output_path}")


def run_xbow_benchmark(output_path: Path) -> BenchmarkResult:
    result = BenchmarkResult("xbow", 0, 0, 0, 0, 0.0, 0)
    generate_report(result, output_path)
    return result


def run_vuln_tf_benchmark(output_path: Path) -> BenchmarkResult:
    result = BenchmarkResult("vuln-tf", 0, 0, 0, 0, 0.0, 0)
    generate_report(result, output_path)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="cain-agent Benchmark 评测")
    parser.add_argument("--suite", choices=["xbow", "vuln-tf", "local-finding-fixture"])
    parser.add_argument("--compare-input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.compare_input:
        suite, scenarios, classic, orchestrated = load_comparison(args.compare_input)
        generate_comparison_report(run_comparison(suite, scenarios, classic, orchestrated), args.output)
    elif args.suite == "xbow":
        run_xbow_benchmark(args.output)
    elif args.suite == "vuln-tf":
        run_vuln_tf_benchmark(args.output)
    elif args.suite == "local-finding-fixture":
        from local_finding_fixture import run_local_finding_fixture

        run_local_finding_fixture(args.output)
    else:
        parser.error("--suite or --compare-input is required")


if __name__ == "__main__":
    main()
