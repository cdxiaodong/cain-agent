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
  (复用 FindingValidator 的硬约束,发现者 ≠ 校验者);注入并行验证池时
  同样拒绝池 session 复用发现 executor。
- **并行验证池**:可选注入 ``VerificationPool``。提供时 finding 校验改走
  多 session 多数表决(confirmed→confirmed / rejected→false_positive /
  contested→validation_inconclusive),severity 仍过规则表;池执行异常
  自动降级回单会话校验,不让 finding 漏校验。

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
from cain_agent.findings import Finding, FindingResult, Severity, classify, dedup
from cain_agent.multi_agent import types as ma_types
from cain_agent.multi_agent.verify_pool import (
    ValidationConsensus,
    VerificationPool,
    VerificationReport,
)
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

_REASON_POOL_CONFIRMED = "并行验证池多数确认"
"""并行池多数表决 confirmed 时的校验方 reason。"""

_REASON_POOL_REJECTED = "并行验证池多数判误报"
"""并行池多数表决 rejected 时的校验方 reason。"""

_REASON_POOL_CONTESTED = "并行验证池未达多数"
"""并行池表决 contested(无多数/分歧)时的校验方 reason。"""


def _finding_to_pool_candidate(finding: Finding) -> ma_types.Finding:
    """把校验流水线的不可变 ``findings.Finding`` 适配成验证池的候选 ``types.Finding``。

    两套模型字段语义不同:流水线侧证据只存 ``evidence_hash``(§3.2 信任边界),
    验证池侧 ``evidence`` 是明文 dict。适配只搬运可公开字段,证据哈希经
    ``evidence`` 透传给校验 session 参考,绝不反推明文。
    """
    return ma_types.Finding(
        cloud=finding.cloud,
        service=finding.service,
        resource=finding.resource,
        issue_type=finding.issue_type,
        severity=ma_types.Severity(finding.severity.value),
        detail=finding.reason,
        evidence={"evidence_hash": finding.evidence_hash},
        confirmed=False,
        finding_id=finding.finding_id,
    )


def _apply_pool_report(finding: Finding, report: VerificationReport) -> Finding:
    """把验证池的多数表决结论收口回流水线 Finding(四态 + 规则表定级)。

    表决到四态的映射:confirmed→confirmed、rejected→false_positive、
    contested(无多数或分歧)→validation_inconclusive。severity 仍一律过
    ``findings.classify`` 规则表——池只表决真伪,定级权不交给表决。
    """
    consensus = report.validation_consensus
    if consensus is ValidationConsensus.CONFIRMED:
        result, reason = FindingResult.CONFIRMED, _REASON_POOL_CONFIRMED
    elif consensus is ValidationConsensus.REJECTED:
        result, reason = FindingResult.FALSE_POSITIVE, _REASON_POOL_REJECTED
    else:
        result, reason = FindingResult.VALIDATION_INCONCLUSIVE, _REASON_POOL_CONTESTED
    return replace(
        finding,
        result=result,
        severity=classify(finding, None),
        reason=reason,
    )


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
        verification_pool: 可选的并行验证池(``VerificationPool``);提供时
            finding 校验改走多数表决,池执行异常自动降级回单会话校验。
        两 executor 为同一对象时构造即抛 ``ValidatorError``(防自证硬约束)。
    """

    def __init__(
        self,
        workspace: Workspace,
        *,
        discovery_executor: SDKExecutor,
        validation_executor: SDKExecutor,
        verification_pool: VerificationPool | None = None,
    ) -> None:
        self.workspace = workspace
        # FindingValidator 构造期完成"同 session 即拒绝"的防自证检查。
        self._validator = FindingValidator(
            validation_executor, discovery_executor=discovery_executor
        )
        if verification_pool is not None:
            # 并行池同样要守住「发现≠校验」:池内任何 session 复用发现 executor
            # 都是发现者自证,构造期一并拒绝。session 复用校验 executor 则允许
            # (校验方内部多路并行,本质仍是不同 session 独立表决)。
            for session in verification_pool.sessions:
                session_executor = getattr(session, "executor", None)
                if session_executor is not None and session_executor is discovery_executor:
                    raise ValidatorError(
                        "验证池 session 与发现 executor 是同一对象:"
                        "发现者≠校验者(DESIGN §3.3),禁止自证"
                    )
        self._pool = verification_pool

    async def _validate_one(self, finding: Finding) -> Finding:
        """校验单条:有池走多数表决(异常降级单会话),无池走单会话校验。"""
        if self._pool is None:
            return await self._validator.validate(finding)
        try:
            candidate = _finding_to_pool_candidate(finding)
            # 池是同步阻塞接口(内部线程池),放执行器线程跑,不阻塞事件循环。
            report = await asyncio.to_thread(self._pool.verify_finding, candidate)
        except Exception:
            # 池不可用(构造/执行异常)→ 降级回单会话校验,不让 finding 漏校验。
            return await self._validator.validate(finding)
        return _apply_pool_report(finding, report)

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
                out.append(await self._validate_one(finding))
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
