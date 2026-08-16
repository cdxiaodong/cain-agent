"""FindingsPipeline 单元测试 —— fake executor + tmp_path workspace,零 token 零触网。

覆盖派活单全部自测要求:
- 全链路:新 finding → 校验 → confirmed,findings.json 与汇总双落盘;
- 终态跳过幂等:confirmed / false_positive 重跑不重复校验,数量不膨胀;
- 单条异常容错:非配置异常 → 该条 validation_system_error + 失败清单,
  流水线不炸;ValidatorError(配置级)直接上抛;
- 去重计数正确:大小写变体判同,dedup_removed 钉死;
- handler 与 Orchestrator 真实组装:recon → test → report 顺序跑通。
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from cain_agent.executor import ExecutorResult, SDKExecutor
from cain_agent.findings import (
    Finding,
    FindingResult,
    Severity,
    hash_evidence,
)
from cain_agent.multi_agent.verify_pool import (
    VerificationPool,
    VerificationSession,
    VerificationVerdict,
)
from cain_agent.orchestrator import Orchestrator
from cain_agent.pipeline import (
    REPORT_PLACEHOLDER_FILE,
    VALIDATION_SUMMARY_FILE,
    FindingsPipeline,
    make_report_handler,
)
from cain_agent.validator import ValidatorError
from cain_agent.workspace import Workspace


class ScriptedExecutor(SDKExecutor):
    """按脚本行动的假 executor:队列项为 ExecutorResult 直接返回,为异常则抛出。"""

    def __init__(self, steps: list[ExecutorResult | Exception]) -> None:
        super().__init__()
        assert steps, "至少需要一个脚本步骤"
        self._steps = list(steps)
        self.prompts: list[str] = []

    async def run(self, prompt: str) -> ExecutorResult:
        self.prompts.append(prompt)
        step = self._steps[min(len(self.prompts) - 1, len(self._steps) - 1)]
        if isinstance(step, Exception):
            raise step
        return step


def _ok(payload: dict[str, Any]) -> ExecutorResult:
    return ExecutorResult(text=json.dumps(payload, ensure_ascii=False))


def _confirmed(reason: str = "证据成立") -> ExecutorResult:
    return _ok({"result": "confirmed", "severity": "critical", "reason": reason})


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "scope.yaml").write_text(
        "in_scope:\n  - example.com\nout_of_scope: []\n", encoding="utf-8"
    )
    return Workspace(root)


def _finding(**overrides: Any) -> Finding:
    kwargs: dict[str, Any] = {
        "finding_id": "aliyun-oss-public-bucket-001",
        "result": FindingResult.VALIDATION_INCONCLUSIVE,
        "severity": Severity.INFO,
        "evidence_hash": hash_evidence("bucket acl = public-read"),
        "reason": "发现方:桶公开可读",
        "cloud": "aliyun",
        "service": "oss",
        "resource": "acs:oss:::demo-bucket",
        "issue_type": "public-read",
    }
    kwargs.update(overrides)
    return Finding(**kwargs)


def _seed(ws: Workspace, findings: list[Finding]) -> None:
    ws.save_findings([finding.to_dict() for finding in findings])


def _load(ws: Workspace) -> list[Finding]:
    return [Finding.from_dict(item) for item in ws.load_findings()]


def _pipeline(ws: Workspace, validation: SDKExecutor) -> FindingsPipeline:
    return FindingsPipeline(ws, discovery_executor=SDKExecutor(), validation_executor=validation)


class _StaticVoteSession(VerificationSession):
    """固定表决的验证池 session;``executor`` 仅用于防自证对照,不参与真实校验。"""

    def __init__(
        self,
        solver_id: str,
        verdict: VerificationVerdict,
        *,
        executor: SDKExecutor | None = None,
    ) -> None:
        super().__init__(solver_id)
        self.verdict = verdict
        self.executor = executor
        self.seen_finding_ids: list[str] = []

    def verify(self, finding) -> VerificationVerdict:  # type: ignore[no-untyped-def]
        self.seen_finding_ids.append(finding.finding_id)
        return self.verdict


def _pool(*verdicts: VerificationVerdict, executor: SDKExecutor | None = None) -> VerificationPool:
    sessions = [
        _StaticVoteSession(f"verify-{index}", verdict, executor=executor)
        for index, verdict in enumerate(verdicts)
    ]
    return VerificationPool(None, sessions)


# -- 防自证:同 session 硬拒绝 ---------------------------------------------------


def test_same_executor_object_rejected(ws: Workspace) -> None:
    shared = SDKExecutor()
    with pytest.raises(ValidatorError, match="禁止自证"):
        FindingsPipeline(ws, discovery_executor=shared, validation_executor=shared)


def test_pool_session_reusing_discovery_executor_rejected(ws: Workspace) -> None:
    shared = SDKExecutor()
    pool = _pool(
        VerificationVerdict.CONFIRMED, VerificationVerdict.CONFIRMED, executor=shared
    )
    with pytest.raises(ValidatorError, match="禁止自证"):
        FindingsPipeline(
            ws,
            discovery_executor=shared,
            validation_executor=SDKExecutor(),
            verification_pool=pool,
        )


# -- 全链路:新 finding → confirmed,双落盘 ----------------------------------------


def test_full_chain_new_findings_confirmed(ws: Workspace) -> None:
    _seed(ws, [
        _finding(finding_id="f-oss-public"),  # public-read → 规则表 high
        _finding(
            finding_id="f-ram-misconfig",
            service="ram",
            resource="acs:ram::123:user/demo",
            issue_type="misconfiguration",  # → 规则表 medium
        ),
    ])
    validation = ScriptedExecutor([_confirmed("桶确公开"), _confirmed("确为误配")])
    summary = asyncio.run(_pipeline(ws, validation).run())

    assert len(validation.prompts) == 2, "两条非终态 finding 都应送校验"
    stored = {f.finding_id: f for f in _load(ws)}
    assert stored["f-oss-public"].result is FindingResult.CONFIRMED
    assert stored["f-oss-public"].severity is Severity.HIGH  # 模型 critical 被规则表压住
    assert stored["f-ram-misconfig"].result is FindingResult.CONFIRMED
    assert stored["f-ram-misconfig"].severity is Severity.MEDIUM

    assert summary.total == 2
    assert summary.validated == 2
    assert summary.skipped_terminal == 0
    assert summary.dedup_removed == 0
    assert summary.results["confirmed"] == 2
    assert summary.failures == []

    on_disk = ws.read_json(VALIDATION_SUMMARY_FILE)
    assert on_disk == summary.to_dict(), "汇总必须落盘 validation-summary.json"


def test_empty_findings_still_writes_summary(ws: Workspace) -> None:
    validation = ScriptedExecutor([_confirmed()])
    summary = asyncio.run(_pipeline(ws, validation).run())
    assert summary.total == 0
    assert validation.prompts == []
    assert ws.read_json(VALIDATION_SUMMARY_FILE)["total"] == 0


# -- 幂等:终态跳过,重跑不膨胀 -----------------------------------------------------


def test_terminal_states_skipped_on_rerun(ws: Workspace) -> None:
    _seed(ws, [
        _finding(result=FindingResult.CONFIRMED, severity=Severity.HIGH),
        _finding(
            finding_id="f-fp",
            result=FindingResult.FALSE_POSITIVE,
            resource="acs:oss:::other-bucket",
        ),
    ])
    validation = ScriptedExecutor([_confirmed()])
    pipeline = _pipeline(ws, validation)

    first = asyncio.run(pipeline.run())
    assert validation.prompts == [], "终态 finding 一律不送校验"
    assert first.skipped_terminal == 2
    assert first.validated == 0
    before = ws.load_findings()

    second = asyncio.run(pipeline.run())
    assert validation.prompts == [], "重跑仍不触发任何校验调用"
    assert second.to_dict() == first.to_dict(), "重跑汇总必须一致"
    assert ws.load_findings() == before, "重跑后 findings.json 不变"


def test_rerun_does_not_inflate_counts(ws: Workspace) -> None:
    _seed(ws, [_finding(), _finding(finding_id="f-2", resource="acs:oss:::bucket-2")])
    validation = ScriptedExecutor([_confirmed(), _confirmed()])
    pipeline = _pipeline(ws, validation)

    asyncio.run(pipeline.run())
    assert len(validation.prompts) == 2
    second = asyncio.run(pipeline.run())  # 首轮全部 confirmed → 次轮全跳过
    assert len(validation.prompts) == 2, "次轮不应再发起校验"
    assert second.total == 2
    assert second.validated == 0
    assert len(ws.load_findings()) == 2, "去重后数量不膨胀"


def test_inconclusive_revalidated_on_rerun(ws: Workspace) -> None:
    _seed(ws, [_finding()])
    validation = ScriptedExecutor([
        _ok({"result": "validation_inconclusive", "severity": "low", "reason": "证据不足"}),
        _confirmed("补证据后成立"),
    ])
    pipeline = _pipeline(ws, validation)

    first = asyncio.run(pipeline.run())
    assert first.results["validation_inconclusive"] == 1
    second = asyncio.run(pipeline.run())  # 非终态重跑时再校验
    assert len(validation.prompts) == 2
    assert second.results["confirmed"] == 1


# -- 容错:单条异常不炸流水线 -------------------------------------------------------


def test_single_failure_marked_and_pipeline_continues(ws: Workspace) -> None:
    _seed(ws, [_finding(), _finding(finding_id="f-boom", resource="acs:oss:::boom-bucket")])
    validation = ScriptedExecutor([_confirmed(), RuntimeError("sdk exploded")])
    summary = asyncio.run(_pipeline(ws, validation).run())

    stored = {f.finding_id: f for f in _load(ws)}
    assert stored["aliyun-oss-public-bucket-001"].result is FindingResult.CONFIRMED
    broken = stored["f-boom"]
    assert broken.result is FindingResult.VALIDATION_SYSTEM_ERROR
    assert broken.reason == "校验执行异常,待复验"

    assert summary.results["confirmed"] == 1
    assert summary.results["validation_system_error"] == 1
    assert len(summary.failures) == 1
    assert summary.failures[0]["finding_id"] == "f-boom"
    assert "RuntimeError" in summary.failures[0]["error"]
    assert ws.read_json(VALIDATION_SUMMARY_FILE)["failures"] == summary.failures


def test_validator_config_error_propagates(ws: Workspace) -> None:
    _seed(ws, [_finding()])
    validation = ScriptedExecutor([ValidatorError("配置级硬约束,不吞")])
    with pytest.raises(ValidatorError, match="配置级硬约束"):
        asyncio.run(_pipeline(ws, validation).run())


# -- 去重:指纹判同,计数钉死 -------------------------------------------------------


def test_dedup_removed_counted(ws: Workspace) -> None:
    _seed(ws, [
        _finding(resource="acs:oss:::demo-bucket"),
        _finding(finding_id="f-dup", resource=" ACS:OSS:::Demo-Bucket "),  # 大小写/空白变体判同
        _finding(finding_id="f-distinct", resource="acs:oss:::another-bucket"),
    ])
    validation = ScriptedExecutor([_confirmed(), _confirmed()])
    summary = asyncio.run(_pipeline(ws, validation).run())

    assert summary.dedup_removed == 1
    assert summary.total == 2
    assert len(validation.prompts) == 2, "重复指纹只校验首次出现的那条"
    assert [f.finding_id for f in _load(ws)] == [
        "aliyun-oss-public-bucket-001",
        "f-distinct",
    ], "dedup 保序,保留首次出现"


# -- 组装:make_report_handler 与 Orchestrator 真实跑通 ------------------------------


def test_report_handler_assembled_into_orchestrator(ws: Workspace) -> None:
    _seed(ws, [_finding()])
    validation = ScriptedExecutor([_confirmed()])
    pipeline = _pipeline(ws, validation)
    orch = Orchestrator(SDKExecutor(), ws, handlers={"report": make_report_handler(pipeline)})

    state = orch.run()

    assert state["completed_stages"] == ["recon", "test", "report"], "阶段顺序钉死"
    stored = _load(ws)
    assert stored[0].result is FindingResult.CONFIRMED, "report 阶段先跑校验流水线"
    assert ws.path(VALIDATION_SUMMARY_FILE).exists()
    placeholder = ws.stage_dir("report") / REPORT_PLACEHOLDER_FILE
    assert placeholder.exists(), "校验后落占位报告产物"
    payload = json.loads(placeholder.read_text(encoding="utf-8"))
    assert payload["validation"]["results"]["confirmed"] == 1

    report_history = state["history"][-1]
    assert report_history["stage"] == "report"
    assert VALIDATION_SUMMARY_FILE in report_history["artifacts"]
    assert f"report/{REPORT_PLACEHOLDER_FILE}" in report_history["artifacts"]


def test_report_handler_skips_terminal_findings(ws: Workspace) -> None:
    _seed(ws, [_finding(result=FindingResult.CONFIRMED, severity=Severity.HIGH)])
    validation = ScriptedExecutor([_confirmed()])
    handler = make_report_handler(_pipeline(ws, validation))
    orch = Orchestrator(SDKExecutor(), ws, handlers={"report": handler})

    orch.run()

    assert validation.prompts == [], "handler 路径同样遵守终态跳过"
    summary = ws.read_json(VALIDATION_SUMMARY_FILE)
    assert summary["skipped_terminal"] == 1
    assert summary["validated"] == 0


# -- 并行验证池:多数表决接线 -----------------------------------------------------


def _pool_pipeline(ws: Workspace, validation: SDKExecutor, pool) -> FindingsPipeline:  # type: ignore[no-untyped-def]
    return FindingsPipeline(
        ws,
        discovery_executor=SDKExecutor(),
        validation_executor=validation,
        verification_pool=pool,
    )


def test_pool_confirmed_majority_marks_confirmed(ws: Workspace) -> None:
    _seed(ws, [_finding(finding_id="f-pool")])  # public-read → 规则表 high
    validation = ScriptedExecutor([_confirmed()])
    pool = _pool(
        VerificationVerdict.CONFIRMED,
        VerificationVerdict.CONFIRMED,
        VerificationVerdict.REJECTED,
    )
    summary = asyncio.run(_pool_pipeline(ws, validation, pool).run())

    stored = _load(ws)[0]
    assert stored.result is FindingResult.CONFIRMED, "多数确认 → confirmed"
    assert stored.severity is Severity.HIGH, "池只表决真伪,severity 仍过规则表"
    assert stored.reason == "并行验证池多数确认"
    assert validation.prompts == [], "走池后不再调单会话校验"
    assert summary.results["confirmed"] == 1
    assert summary.failures == []


def test_pool_rejected_majority_marks_false_positive(ws: Workspace) -> None:
    _seed(ws, [_finding(finding_id="f-pool")])
    pool = _pool(
        VerificationVerdict.REJECTED,
        VerificationVerdict.REJECTED,
        VerificationVerdict.INCONCLUSIVE,
    )
    summary = asyncio.run(_pool_pipeline(ws, ScriptedExecutor([_confirmed()]), pool).run())

    stored = _load(ws)[0]
    assert stored.result is FindingResult.FALSE_POSITIVE, "多数判误报 → false_positive"
    assert stored.reason == "并行验证池多数判误报"
    assert summary.results["false_positive"] == 1


def test_pool_contested_marks_inconclusive(ws: Workspace) -> None:
    _seed(ws, [_finding(finding_id="f-pool")])
    pool = _pool(VerificationVerdict.CONFIRMED, VerificationVerdict.REJECTED)
    summary = asyncio.run(_pool_pipeline(ws, ScriptedExecutor([_confirmed()]), pool).run())

    stored = _load(ws)[0]
    assert stored.result is FindingResult.VALIDATION_INCONCLUSIVE, "无多数/分歧 → inconclusive"
    assert stored.reason == "并行验证池未达多数"
    assert summary.results["validation_inconclusive"] == 1


def test_pool_each_session_verifies_candidate(ws: Workspace) -> None:
    _seed(ws, [_finding(finding_id="f-pool")])
    sessions = [
        _StaticVoteSession(f"verify-{i}", VerificationVerdict.CONFIRMED) for i in range(3)
    ]
    pool = VerificationPool(None, sessions)
    asyncio.run(_pool_pipeline(ws, ScriptedExecutor([_confirmed()]), pool).run())

    assert [s.seen_finding_ids for s in sessions] == [["f-pool"]] * 3, (
        "池内每个 session 都独立校验同一条 finding"
    )


class _ExplodingPool:
    """verify_finding 必抛异常的坏池,用于验证降级路径。"""

    sessions: tuple = ()

    def verify_finding(self, candidate):  # type: ignore[no-untyped-def]
        raise RuntimeError("pool exploded")


def test_pool_error_falls_back_to_single_session(ws: Workspace) -> None:
    _seed(ws, [_finding(finding_id="f-pool")])
    validation = ScriptedExecutor([_confirmed("降级单会话确认")])
    summary = asyncio.run(_pool_pipeline(ws, validation, _ExplodingPool()).run())

    stored = _load(ws)[0]
    assert stored.result is FindingResult.CONFIRMED, "池异常 → 降级单会话校验"
    assert stored.reason == "降级单会话确认"
    assert len(validation.prompts) == 1, "降级路径调用了单会话校验"
    assert summary.failures == [], "降级是预期路径,不计入失败清单"


def test_pool_terminal_findings_still_skipped(ws: Workspace) -> None:
    _seed(ws, [_finding(result=FindingResult.CONFIRMED, severity=Severity.HIGH)])
    sessions = [
        _StaticVoteSession(f"verify-{i}", VerificationVerdict.REJECTED) for i in range(2)
    ]
    pool = VerificationPool(None, sessions)
    summary = asyncio.run(_pool_pipeline(ws, ScriptedExecutor([_confirmed()]), pool).run())

    assert all(s.seen_finding_ids == [] for s in sessions), "终态 finding 不送池"
    assert summary.skipped_terminal == 1
    assert summary.validated == 0
