"""双后端编排链路 benchmark —— claude 与 pi 执行引擎同场景对照。

同一本地 SSTI fixture(稳定产出 1 条 finding)分别交给
``SDKExecutor``(claude 后端)与 ``PiExecutor``(pi 后端,网关模型)驱动的
中心编排链路(单会话校验 + 3 会话多数表决 + 聚合报告),逐轮采集
finding 确认率 / 墙钟耗时 / token 消耗,输出对齐 bench-orchestrated
格式的对比表。两后端的 scope 语义、双会话约束、零工具校验通道完全
一致,差异只在执行引擎与模型本身。

token 口径:claude SDK(snake_case 键)与 pi 桥(camelCase 键)由
``run_benchmark._token_cost`` 统一归一化;tracker 包住真实引擎,
Route A 校验与表决池共用同一 executor 实例,全部调用都会被计入。
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from local_finding_fixture import DEFAULT_FIXTURE_PATH, load_fixture, materialize_finding
from run_benchmark import (
    ComparisonResult,
    ModeRunner,
    Scenario,
    _token_cost,
    generate_modes_report,
    run_modes_comparison,
)

from cain_agent.executor import SDKExecutor
from cain_agent.multi_agent.orchestration import (
    build_orchestration,
    make_multi_agent_report_handler,
)
from cain_agent.orchestrator import StageContext
from cain_agent.pipeline import FindingsPipeline
from cain_agent.workspace import Workspace


class UsageTrackingExecutor:
    """透传任意执行引擎(SDKExecutor / PiExecutor 同契约)并按 run 累积 token。"""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.calls = 0
        self.token_cost = 0

    def add_pre_tool_use_hook(self, callback: Any, *, matcher: str | None = None) -> None:
        self.inner.add_pre_tool_use_hook(callback, matcher=matcher)

    def build_options(self) -> Any:
        return self.inner.build_options()

    async def run(self, prompt: str) -> Any:
        result = await self.inner.run(prompt)
        self.calls += 1
        self.token_cost += _token_cost(result.usage)
        return result


def build_validation_executor(
    backend: str,
    *,
    pi_provider: str = "anthropic",
    pi_model: str | None = None,
    idle_timeout: float = 180.0,
    total_budget: float | None = 900.0,
) -> Any:
    """按后端构造零工具校验引擎(与 CLI ``_build_validation_executor`` 同语义)。"""
    if backend == "pi":
        from cain_agent.pi_executor import PiExecutor

        return PiExecutor(
            provider=pi_provider,
            model=pi_model,
            allowed_tools=[],  # 只读校验通道:零工具
            idle_timeout=idle_timeout,
            total_budget=total_budget,
        )
    if backend == "claude":
        return SDKExecutor(
            allowed_tools=[],  # 只读校验通道:零工具
            idle_timeout=idle_timeout,
            total_budget=total_budget,
        )
    raise ValueError(f"unknown backend: {backend}")


def make_backend_runner(
    backend: str,
    *,
    fixture_path: Path | None = None,
    executor_factory: Callable[[], Any] | None = None,
    pi_provider: str = "anthropic",
    pi_model: str | None = None,
    idle_timeout: float = 180.0,
    total_budget: float | None = 900.0,
) -> ModeRunner:
    """一个后端一个 runner:同一 fixture 走中心编排,采集确认率/耗时/token。

    ``executor_factory`` 供测试注入确定性 fake(零真实 LLM 调用);缺省按
    后端构造真实引擎。单轮失败(模型输出不合规等)由对比框架收敛为该轮
    error,不中断其余轮次。
    """
    resolved_fixture = fixture_path or DEFAULT_FIXTURE_PATH
    if executor_factory is None:
        executor_factory = lambda: build_validation_executor(  # noqa: E731
            backend,
            pi_provider=pi_provider,
            pi_model=pi_model,
            idle_timeout=idle_timeout,
            total_budget=total_budget,
        )

    def runner(scenario: Scenario) -> dict[str, Any]:
        fixture = load_fixture(resolved_fixture)
        candidate = materialize_finding(fixture)
        tracker = UsageTrackingExecutor(executor_factory())
        started = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix=f"cain-backend-bench-{backend}-") as temporary:
            workspace = Workspace(Path(temporary))
            workspace.path("scope.yaml").write_text(
                "in_scope:\n  - 127.0.0.1\nout_of_scope: []\n",
                encoding="utf-8",
            )
            workspace.save_findings([candidate.to_dict()])
            orchestration = build_orchestration(tracker)
            # 发现者≠校验者(DESIGN §3.3):discovery 给独立占位实例,本链路
            # findings 由 fixture 预置,discovery 不会被调用(与
            # local_finding_fixture 同款约定)。
            pipeline = FindingsPipeline(
                workspace,
                discovery_executor=SDKExecutor(),
                validation_executor=tracker,
                verification_pool=orchestration.verification_pool,
            )
            handler = make_multi_agent_report_handler(pipeline, orchestration)
            result = handler(
                StageContext(workspace, "report", workspace.stage_dir("report"))
            )
            if result.data is None:
                raise RuntimeError(f"{backend}: report handler returned no data")
            report = result.data
            if report.get("route") != "multi_agent":
                raise RuntimeError(f"{backend}: central route unavailable")
            summary = report["summary"]
            return {
                "findings": int(summary["total"]),
                "confirmed_findings": int(summary["results"].get("confirmed", 0)),
                "duration_sec": time.perf_counter() - started,
                "token_cost": tracker.token_cost,
                "verdict_calls": tracker.calls,
            }

    return runner


def run_backend_benchmark(
    output_path: Path,
    *,
    fixture_path: Path | None = None,
    backends: tuple[str, ...] = ("claude", "pi"),
    repeat: int = 3,
    pi_provider: str = "anthropic",
    pi_model: str | None = "glm-5.3",
    idle_timeout: float = 180.0,
    total_budget: float | None = 900.0,
    executor_factory_per_backend: Mapping[str, Callable[[], Any]] | None = None,
) -> ComparisonResult:
    """同一场景 × N 轮 × 每后端一 runner,产出双后端对比报告。

    ``executor_factory_per_backend`` 供测试逐后端注入确定性 fake;
    生产路径为 ``None``(真实引擎,按后端分支构造)。
    """
    if repeat < 1:
        raise ValueError("repeat must be >= 1")
    if not backends:
        raise ValueError("backends must not be empty")
    if executor_factory_per_backend is not None:
        unknown = set(executor_factory_per_backend) - set(backends)
        if unknown:
            raise ValueError(f"factories given for unknown backends: {sorted(unknown)}")
    scenarios = tuple(
        Scenario(f"local-ssti-r{index}", {"round": index})
        for index in range(1, repeat + 1)
    )
    runners = {
        backend: make_backend_runner(
            backend,
            fixture_path=fixture_path,
            pi_provider=pi_provider,
            pi_model=pi_model,
            idle_timeout=idle_timeout,
            total_budget=total_budget,
            executor_factory=(
                executor_factory_per_backend.get(backend) if executor_factory_per_backend else None
            ),
        )
        for backend in backends
    }
    result = run_modes_comparison(
        f"local-ssti-backend-compare ({', '.join(backends)})",
        scenarios,
        runners,
    )
    generate_modes_report(
        result,
        output_path,
        title="Benchmark 双后端编排链路对比",
        mode_header="后端",
    )
    print(f"报告已生成: {output_path}")
    return result
