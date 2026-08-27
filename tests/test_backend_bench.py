"""双后端编排链路 benchmark 测试(离线确定性,fake executor 零真实调用)。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))
from backend_bench import (  # noqa: E402
    UsageTrackingExecutor,
    build_validation_executor,
    make_backend_runner,
    run_backend_benchmark,
)
from local_finding_fixture import DEFAULT_FIXTURE_PATH  # noqa: E402
from run_benchmark import (  # noqa: E402
    Scenario,
    _token_cost,
    run_comparison,
    run_modes_comparison,
)

from cain_agent.executor import ExecutorResult  # noqa: E402


class FakeExecutor:
    """确定性表决引擎:prompt 含证据哈希即 confirmed,附可配置假 usage。"""

    def __init__(self, expected_marker: str, usage: dict | None) -> None:
        self.expected_marker = expected_marker
        self.usage = usage
        self.prompts: list[str] = []
        self.hooks: list[tuple] = []

    def add_pre_tool_use_hook(self, callback, *, matcher=None) -> None:
        self.hooks.append((callback, matcher))

    def build_options(self) -> dict:
        return {"backend": "fake"}

    async def run(self, prompt: str) -> ExecutorResult:
        import json

        self.prompts.append(prompt)
        verdict = "confirmed" if self.expected_marker in prompt else "rejected"
        return ExecutorResult(text=json.dumps({"verdict": verdict}), usage=dict(self.usage))


CLAUDE_USAGE = {
    "input_tokens": 40000,
    "output_tokens": 138,
    "cache_read_input_tokens": 704,
    "cache_creation_input_tokens": 0,
}
PI_USAGE = {
    "input": 53,
    "output": 7,
    "cacheRead": 0,
    "cacheWrite": 0,
    "totalTokens": 60,
}


def test_token_cost_normalizes_both_usage_dialects() -> None:
    # claude SDK 键:分量求和;pi 桥键:totalTokens 优先,否则分量求和。
    assert _token_cost(CLAUDE_USAGE) == 40000 + 138 + 704
    assert _token_cost(PI_USAGE) == 60
    assert _token_cost({"input": 5, "output": 7}) == 12
    assert _token_cost(None) == 0
    assert _token_cost({}) == 0


def test_usage_tracking_executor_accumulates_and_passes_hooks() -> None:
    import asyncio

    inner = FakeExecutor("hash", PI_USAGE)
    tracker = UsageTrackingExecutor(inner)
    callback = lambda *args: {}  # noqa: E731
    tracker.add_pre_tool_use_hook(callback, matcher="Bash")
    assert inner.hooks and inner.hooks[0][0] is callback
    assert inner.hooks[0][1] == "Bash"

    asyncio.run(tracker.run("prompt-a"))
    asyncio.run(tracker.run("prompt-b"))
    assert tracker.calls == 2
    assert tracker.token_cost == 120
    assert inner.prompts == ["prompt-a", "prompt-b"]


@pytest.mark.parametrize(
    ("backend", "usage"),
    [("claude", CLAUDE_USAGE), ("pi", PI_USAGE)],
)
def test_backend_runner_confirms_finding_via_orchestration(
    backend: str, usage: dict, tmp_path: Path
) -> None:
    from local_finding_fixture import load_fixture, materialize_finding

    evidence_hash = materialize_finding(load_fixture(DEFAULT_FIXTURE_PATH)).evidence_hash

    def factory() -> FakeExecutor:
        return FakeExecutor(evidence_hash, usage)

    runner = make_backend_runner(
        backend,
        executor_factory=factory,
        fixture_path=DEFAULT_FIXTURE_PATH,
    )
    raw = runner(Scenario("local-ssti-r1", {"round": 1}))
    assert raw["findings"] == 1
    assert raw["confirmed_findings"] == 1
    assert raw["token_cost"] == 3 * _token_cost(usage)
    assert raw["verdict_calls"] == 3  # 验证池 3 会话表决(有池时 Route A 校验直接走池)
    assert raw["duration_sec"] >= 0.0


def test_build_validation_executor_rejects_unknown_backend() -> None:
    with pytest.raises(ValueError, match="unknown backend"):
        build_validation_executor("gpt")


def test_run_modes_comparison_matches_run_comparison_order() -> None:
    seen: list[str] = []
    scenarios = [Scenario("s-1", {})]

    def classic(_: Scenario) -> dict:
        seen.append("classic")
        return {"findings": 1, "confirmed_findings": 1}

    def orchestrated(_: Scenario) -> dict:
        seen.append("orchestrated")
        return {"findings": 1, "confirmed_findings": 0}

    first = run_comparison("x", scenarios, classic, orchestrated)
    second = run_modes_comparison(
        "x", scenarios, {"classic": classic, "orchestrated": orchestrated}
    )
    assert seen == ["classic", "orchestrated", "classic", "orchestrated"]
    assert [r.mode for r in first.results] == [r.mode for r in second.results]


def test_run_backend_benchmark_emits_report_with_both_backends(tmp_path: Path) -> None:
    from local_finding_fixture import load_fixture, materialize_finding

    marker = materialize_finding(load_fixture(DEFAULT_FIXTURE_PATH)).evidence_hash
    output = tmp_path / "bench-backends.md"
    result = run_backend_benchmark(
        output,
        fixture_path=DEFAULT_FIXTURE_PATH,
        backends=("claude", "pi"),
        repeat=2,
        executor_factory_per_backend={
            "claude": lambda: FakeExecutor(marker, CLAUDE_USAGE),
            "pi": lambda: FakeExecutor(marker, PI_USAGE),
        },
    )
    text = output.read_text(encoding="utf-8")
    assert "Benchmark 双后端编排链路对比" in text
    assert "| 后端 |" in text
    assert result.summary("claude").confirmed_findings == 2
    assert result.summary("pi").confirmed_findings == 2
    assert result.summary("claude").token_cost == 2 * 3 * _token_cost(CLAUDE_USAGE)
    assert result.summary("pi").token_cost == 2 * 3 * 60
