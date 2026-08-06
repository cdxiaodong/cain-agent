"""FindingsPipeline —— 校验流水线:dedup + FindingValidator 串成 report 前置阶段。

Day 3 数据模型(findings.py)与 Day 4 校验执行层(validator.py)在此组装为
端到端校验闭环,经 ``make_report_handler`` 挂到 Orchestrator 的 StageHandler
注入点——只组装,不改 orchestrator.py(冻结文件)。

流程硬编码:读 workspace findings.json → ``dedup`` 指纹去重 → 逐条
``FindingValidator.validate`` → Workspace 原子写回 findings.json → 汇总落盘
``report/validation-summary.json``。

设计要点:

- **幂等**:``confirmed`` / ``false_positive`` 为终态,重跑直接跳过不重复
  校验;非终态(``validation_inconclusive`` / ``validation_system_error``)
  重跑时重新校验——瞬时故障恢复后给翻案机会,且去重后数量不膨胀。
- **容错**:单条校验抛 ``ValidatorError`` 以外的异常 → 该条标
  ``validation_system_error`` 并记入失败清单,流水线继续不炸;
  ``ValidatorError`` 是配置级硬约束(防自证),直接上抛不吞。
- **防自证**:发现 executor 与校验 executor 为同一对象时构造即拒绝
  (复用 FindingValidator 的硬约束,发现者 ≠ 校验者)。

本模块不生成真实报告 markdown;``make_report_handler`` 在校验流水线之后
只落占位报告产物,真实报告生成由后续任务接入。
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from cain_agent.executor import SDKExecutor
from cain_agent.findings import Finding, FindingResult, dedup
from cain_agent.orchestrator import StageContext, StageHandler, StageResult
from cain_agent.validator import FindingValidator, ValidatorError
from cain_agent.workspace import Workspace

__all__ = [
    "REPORT_PLACEHOLDER_FILE",
    "TERMINAL_RESULTS",
    "VALIDATION_SUMMARY_FILE",
    "FindingsPipeline",
    "ValidationSummary",
    "make_report_handler",
]

TERMINAL_RESULTS = frozenset({FindingResult.CONFIRMED, FindingResult.FALSE_POSITIVE})
"""终态集合:重跑跳过,不重复烧 token 校验已定论的发现。"""

VALIDATION_SUMMARY_FILE = "report/validation-summary.json"
"""校验汇总落盘路径(相对工作区根,经 Workspace 原子写)。"""

REPORT_PLACEHOLDER_FILE = "report-placeholder.json"
"""report 阶段占位产物文件名(真实报告 markdown 后续任务接入)。"""

_REASON_PIPELINE_ERROR = "校验执行异常,待复验"
"""单条校验抛出非配置异常时的兜底 reason(≤30 字,不猜结论)。"""


def _atomic_write_json(path: Path, data: Any) -> None:
    """与 Workspace 同款的「临时文件 + os.replace」原子写(用于子目录内文件)。

    ``Workspace.write_json`` 只支持根目录平铺文件名(临时文件落在根下),
    report/ 子目录内的汇总文件在此用同一模式补齐,防半写状态。
    """
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


@dataclass(frozen=True)
class ValidationSummary:
    """一次流水线跑批的校验汇总,即 ``validation-summary.json`` 的结构。

    ``results`` 固定含四状态键(无命中补零),``failures`` 为校验抛异常的
    失败清单(finding_id + 异常描述),可审计可追溯。
    """

    total: int
    dedup_removed: int
    validated: int
    skipped_terminal: int
    results: dict[str, int]
    failures: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "dedup_removed": self.dedup_removed,
            "validated": self.validated,
            "skipped_terminal": self.skipped_terminal,
            "results": dict(self.results),
            "failures": [dict(item) for item in self.failures],
        }


class FindingsPipeline:
    """Findings 校验流水线:dedup 去重 + 独立 session 校验 + 原子写回 + 汇总落盘。

    参数:
        workspace: 外置记忆真源;findings.json 在此读写,汇总落在 report/ 下。
        discovery_executor: 发现用 executor(只作防自证对照,本流水线不调用它)。
        validation_executor: **校验专用** executor(与发现方不同 session)。
        两 executor 为同一对象时构造即抛 ``ValidatorError``(防自证硬约束)。
    """

    def __init__(
        self,
        workspace: Workspace,
        *,
        discovery_executor: SDKExecutor,
        validation_executor: SDKExecutor,
    ) -> None:
        self.workspace = workspace
        # FindingValidator 构造期完成"同 session 即拒绝"的防自证检查。
        self._validator = FindingValidator(
            validation_executor, discovery_executor=discovery_executor
        )

    async def run(self) -> ValidationSummary:
        """跑一遍校验流水线,返回并落盘校验汇总。

        单条校验抛 ``ValidatorError`` 以外的异常:该条标
        ``validation_system_error``、记入失败清单,流水线继续;
        ``ValidatorError``(配置级硬约束)直接上抛。
        """
        loaded = [Finding.from_dict(item) for item in self.workspace.load_findings()]
        unique = dedup(loaded)

        out: list[Finding] = []
        failures: list[dict[str, str]] = []
        validated = 0
        skipped = 0
        for finding in unique:
            if finding.result in TERMINAL_RESULTS:
                out.append(finding)
                skipped += 1
                continue
            try:
                out.append(await self._validator.validate(finding))
            except ValidatorError:
                raise
            except Exception as exc:  # 引擎边界之外的最后防线:单条失败不炸流水线
                out.append(replace(
                    finding,
                    result=FindingResult.VALIDATION_SYSTEM_ERROR,
                    reason=_REASON_PIPELINE_ERROR,
                ))
                failures.append({
                    "finding_id": finding.finding_id,
                    "error": f"{type(exc).__name__}: {exc}",
                })
            validated += 1

        self.workspace.save_findings([finding.to_dict() for finding in out])

        results = {state.value: 0 for state in FindingResult}
        for finding in out:
            results[finding.result.value] += 1
        summary = ValidationSummary(
            total=len(out),
            dedup_removed=len(loaded) - len(unique),
            validated=validated,
            skipped_terminal=skipped,
            results=results,
            failures=failures,
        )
        summary_path = self.workspace.stage_dir("report") / Path(VALIDATION_SUMMARY_FILE).name
        _atomic_write_json(summary_path, summary.to_dict())
        return summary

    def run_sync(self) -> ValidationSummary:
        """同步上下文(Orchestrator 的 StageHandler 是同步协议)下的跑批入口。"""
        return asyncio.run(self.run())


def make_report_handler(pipeline: FindingsPipeline) -> StageHandler:
    """把校验流水线包装成符合 ``StageHandler`` 协议的 report 阶段 handler。

    可直接注入:``Orchestrator(handlers={"report": make_report_handler(pipeline)})``。
    handler 内先跑校验流水线(去重 → 校验 → 写回 → 汇总落盘),再落占位报告
    产物;真实报告生成由后续任务替换本占位实现。
    """

    def handler(ctx: StageContext) -> StageResult:
        summary = pipeline.run_sync()
        path = ctx.artifacts_dir / REPORT_PLACEHOLDER_FILE
        payload = {
            "stage": ctx.stage,
            "note": "占位报告 — 校验闭环已跑完,真实报告生成后续接入",
            "validation": summary.to_dict(),
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return StageResult(
            summary=(
                f"校验流水线完成: 共 {summary.total} 条,去重 {summary.dedup_removed} 条,"
                f"新校验 {summary.validated} 条,跳过终态 {summary.skipped_terminal} 条,"
                f"失败 {len(summary.failures)} 条"
            ),
            artifacts=[
                VALIDATION_SUMMARY_FILE,
                path.relative_to(ctx.workspace.root).as_posix(),
            ],
            data=summary.to_dict(),
        )

    return handler
