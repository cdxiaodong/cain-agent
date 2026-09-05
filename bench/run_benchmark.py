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


# token 计量键:claude SDK(snake_case)与 pi 桥(camelCase)两套口径,
# total 优先,否则各分量求和;两套键名互不冲突,可安全同列。
_TOTAL_TOKEN_KEYS = ("total_tokens", "totalTokens")
_CLAUDE_TOKEN_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
)
_PI_TOKEN_KEYS = ("input", "output", "cacheRead", "cacheWrite")


def _token_cost(usage: Mapping[str, Any] | None) -> int:
    if not usage:
        return 0
    for key in _TOTAL_TOKEN_KEYS:
        total = usage.get(key)
        if isinstance(total, (int, float)):
            return int(total)
    return sum(
        int(usage.get(key, 0) or 0) for key in (*_CLAUDE_TOKEN_KEYS, *_PI_TOKEN_KEYS)
    )


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


def run_modes_comparison(
    suite: str,
    scenarios: Iterable[Scenario],
    runners: Mapping[str, ModeRunner],
    *,
    clock: Callable[[], float] = time.perf_counter,
) -> ComparisonResult:
    """Run the same scenario set under each named mode (mode order = mapping order)."""
    materialized = tuple(scenarios)
    identifiers = tuple(item.scenario_id for item in materialized)
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("scenario_id values must be unique")
    if not runners:
        raise ValueError("at least one mode runner is required")
    results: list[ScenarioResult] = []
    for mode, runner in runners.items():
        for scenario in materialized:
            started = clock()
            try:
                raw = runner(scenario)
            except Exception as exc:  # keep other scenarios comparable after a runner failure
                raw = {"error": f"{type(exc).__name__}: {exc}"}
            results.append(_normalize_result(scenario, mode, raw, max(0.0, clock() - started)))
    return ComparisonResult(suite, identifiers, tuple(results))


def run_comparison(
    suite: str,
    scenarios: Iterable[Scenario],
    classic_runner: ModeRunner,
    orchestrated_runner: ModeRunner,
    *,
    clock: Callable[[], float] = time.perf_counter,
) -> ComparisonResult:
    """Run the exact same materialized scenario set in both modes."""
    return run_modes_comparison(
        suite,
        scenarios,
        {"classic": classic_runner, "orchestrated": orchestrated_runner},
        clock=clock,
    )


def generate_modes_report(
    result: ComparisonResult,
    output_path: Path,
    *,
    title: str,
    mode_header: str = "模式",
) -> None:
    lines = [
        f"# {title}",
        "",
        f"- 评测套件: {result.suite}",
        f"- 同组场景数: {len(result.scenarios)}",
        "",
        "## 汇总对比",
        "",
        f"| {mode_header} | finding 确认率 | 已确认/总 finding | 总耗时 | token 消耗 | 错误数 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    modes = list(dict.fromkeys(item.mode for item in result.results))
    for mode in modes:
        summary = result.summary(mode)
        lines.append(
            f"| {summary.mode} | {summary.confirmation_rate:.1%} | "
            f"{summary.confirmed_findings}/{summary.findings} | "
            f"{summary.duration_sec:.3f}s | {summary.token_cost} | {summary.errors} |"
        )
    lines += [
        "",
        "## 逐场景明细",
        "",
        f"| 场景 | {mode_header} | finding 确认率 | 耗时 | token 消耗 | 状态 |",
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


def generate_comparison_report(result: ComparisonResult, output_path: Path) -> None:
    generate_modes_report(
        result,
        output_path,
        title="Benchmark 经典与编排模式对比",
        mode_header="模式",
    )


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
    """三场景离线静态跑分(见 ``bench/vuln_tf_static.py``)。

    token 恒为 0:纯静态文本分析,无 LLM 调用(如实统计,不模拟)。
    """
    if __package__:
        from .vuln_tf_static import run_all
    else:
        from vuln_tf_static import run_all

    results = run_all()
    total = len(results)
    tp = sum(len(r.detections) for r in results)
    fp = sum(len(r.false_positives) for r in results)
    fn = sum(len(r.expected_missing) for r in results)
    avg = sum(r.elapsed_s for r in results) / total if total else 0.0
    result = BenchmarkResult("vuln-tf", total, tp, fp, fn, round(avg, 6), 0)
    generate_report(result, output_path)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="cain-agent Benchmark 评测")
    parser.add_argument("--suite", choices=["xbow", "vuln-tf", "local-finding-fixture"])
    parser.add_argument("--compare-input", type=Path)
    parser.add_argument(
        "--backend-compare",
        action="store_true",
        help="run the same local fixture through the orchestrated route under "
        "each backend (claude / pi) and emit a comparison report",
    )
    parser.add_argument(
        "--backends",
        default="claude,pi",
        help="comma-separated backends for --backend-compare (default: claude,pi)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=3,
        help="rounds per backend for --backend-compare (default: 3)",
    )
    parser.add_argument("--pi-provider", default="anthropic")
    parser.add_argument("--pi-model", default="glm-5.3")
    parser.add_argument("--idle-timeout", type=float, default=180.0)
    parser.add_argument("--total-budget", type=float, default=900.0)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.backend_compare:
        from backend_bench import run_backend_benchmark

        run_backend_benchmark(
            args.output,
            fixture_path=args.fixture,
            backends=tuple(item.strip() for item in args.backends.split(",") if item.strip()),
            repeat=args.repeat,
            pi_provider=args.pi_provider,
            pi_model=args.pi_model,
            idle_timeout=args.idle_timeout,
            total_budget=args.total_budget,
        )
    elif args.compare_input:
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
        parser.error("--suite, --compare-input, or --backend-compare is required")


if __name__ == "__main__":
    main()
