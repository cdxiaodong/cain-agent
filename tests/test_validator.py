"""FindingValidator 单元测试 —— fake executor 注入,零 token 零触网。

覆盖派活单全部自测要求:同 session 拒绝、四状态映射、SDK 返回乱码 →
validation_system_error、定级被规则表压住(模型 critical / 规则表 high →
最终 high)、reason 超长截断标记;另钉死超时/SDK 异常/非法状态值/非法
severity 建议/证据哈希同源/[UNTRUSTED_DATA] 标注等边界行为。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from cain_agent.executor import ExecutorResult, SDKExecutor
from cain_agent.findings import (
    REASON_MAX_LEN,
    Finding,
    FindingResult,
    Severity,
    hash_evidence,
)
from cain_agent.validator import (
    TRUNCATION_MARK,
    UNTRUSTED_OPEN,
    FindingValidator,
    ValidatorError,
)


class FakeExecutor(SDKExecutor):
    """替换 ``run`` 的假 executor:按队列返回预制 ExecutorResult,记录 prompt。"""

    def __init__(self, results: list[ExecutorResult]) -> None:
        super().__init__()
        assert results, "至少需要一个预制结果"
        self._results = list(results)
        self.prompts: list[str] = []

    async def run(self, prompt: str) -> ExecutorResult:
        self.prompts.append(prompt)
        index = min(len(self.prompts) - 1, len(self._results) - 1)
        return self._results[index]


def _ok(payload: dict[str, Any]) -> ExecutorResult:
    return ExecutorResult(text=json.dumps(payload, ensure_ascii=False))


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


# -- 防自证:同 session 硬拒绝 ---------------------------------------------------


def test_same_executor_object_rejected() -> None:
    shared = FakeExecutor([_ok({"result": "confirmed", "severity": "high", "reason": "x"})])
    with pytest.raises(ValidatorError, match="禁止自证"):
        FindingValidator(shared, discovery_executor=shared)


def test_distinct_executors_accepted() -> None:
    validator = FindingValidator(FakeExecutor([ExecutorResult()]), discovery_executor=SDKExecutor())
    assert isinstance(validator, FindingValidator)


def test_discovery_executor_optional() -> None:
    validator = FindingValidator(FakeExecutor([ExecutorResult()]))
    assert isinstance(validator, FindingValidator)


# -- 四状态映射 -----------------------------------------------------------------


@pytest.mark.parametrize(
    "state",
    [
        "confirmed",
        "false_positive",
        "validation_inconclusive",
        "validation_system_error",
    ],
)
def test_four_states_mapped(state: str) -> None:
    executor = FakeExecutor([_ok({"result": state, "severity": "low", "reason": "校验完毕"})])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert out.result is FindingResult(state)


# -- 失败不猜:乱码 / 非法状态 / 超时 / SDK 异常 → system_error --------------------


def test_garbage_output_becomes_system_error() -> None:
    executor = FakeExecutor([ExecutorResult(text="我觉得应该是真的吧(无任何JSON)")])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert out.result is FindingResult.VALIDATION_SYSTEM_ERROR
    assert out.reason == "校验返回无法解析"


def test_unknown_state_value_becomes_system_error() -> None:
    executor = FakeExecutor([_ok({"result": "maybe_true", "severity": "low", "reason": "x"})])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert out.result is FindingResult.VALIDATION_SYSTEM_ERROR


def test_interrupted_run_becomes_system_error() -> None:
    executor = FakeExecutor([ExecutorResult(interrupted=True, interrupt_reason="idle_timeout")])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert out.result is FindingResult.VALIDATION_SYSTEM_ERROR
    assert out.reason == "校验超时中断,无法判定"


def test_sdk_error_becomes_system_error() -> None:
    executor = FakeExecutor([ExecutorResult(is_error=True, error="RuntimeError: boom")])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert out.result is FindingResult.VALIDATION_SYSTEM_ERROR
    assert out.reason == "校验通道异常,无法判定"


def test_json_embedded_in_prose_still_parsed() -> None:
    text = '分析过程略。最终结论:\n{"result": "confirmed", "severity": "low", "reason": "证据成立"}'
    executor = FakeExecutor([ExecutorResult(text=text)])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert out.result is FindingResult.CONFIRMED


# -- 定级收口:规则表压过模型建议 -------------------------------------------------


def test_rule_table_caps_model_suggestion() -> None:
    # issue_type=public-read 命中规则表 high;模型建议 critical 一律作废
    executor = FakeExecutor([_ok({"result": "confirmed", "severity": "critical", "reason": "成立"})])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert out.severity is Severity.HIGH


def test_no_rule_hit_degrades_to_lower_of_suggested_and_info() -> None:
    # 规则表无命中:模型建议 critical 也只给 info(Day 3 降级取低规则)
    executor = FakeExecutor([_ok({"result": "confirmed", "severity": "critical", "reason": "成立"})])
    out = asyncio.run(FindingValidator(executor).validate(_finding(issue_type="no-such-rule")))
    assert out.severity is Severity.INFO


def test_invalid_suggested_severity_falls_back_to_rule_table() -> None:
    executor = FakeExecutor([_ok({"result": "confirmed", "severity": "super-critical", "reason": "成立"})])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert out.severity is Severity.HIGH  # 非法建议不炸,规则表照常命中


# -- 回写:reason 截断标记 / 证据哈希同源 -----------------------------------------


def test_reason_truncated_with_mark() -> None:
    long_reason = "证据链完整且可复现," * 10  # 远超 30 字
    executor = FakeExecutor([_ok({"result": "confirmed", "severity": "high", "reason": long_reason})])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert len(out.reason) == REASON_MAX_LEN
    assert out.reason.endswith(TRUNCATION_MARK)


def test_missing_reason_uses_fallback() -> None:
    executor = FakeExecutor([_ok({"result": "confirmed", "severity": "high"})])
    out = asyncio.run(FindingValidator(executor).validate(_finding()))
    assert out.result is FindingResult.CONFIRMED
    assert 0 < len(out.reason) <= REASON_MAX_LEN


def test_evidence_hash_and_identity_preserved() -> None:
    original = _finding()
    executor = FakeExecutor([_ok({"result": "confirmed", "severity": "high", "reason": "成立"})])
    out = asyncio.run(FindingValidator(executor).validate(original))
    assert out.evidence_hash == original.evidence_hash
    assert out.finding_id == original.finding_id
    assert (out.cloud, out.service, out.resource, out.issue_type) == (
        original.cloud,
        original.service,
        original.resource,
        original.issue_type,
    )


# -- prompt:数据信任边界标注 -----------------------------------------------------


def test_prompt_marks_finding_as_untrusted_data() -> None:
    original = _finding()
    executor = FakeExecutor([_ok({"result": "confirmed", "severity": "high", "reason": "成立"})])
    asyncio.run(FindingValidator(executor).validate(original))
    prompt = executor.prompts[0]
    assert UNTRUSTED_OPEN in prompt
    assert original.resource in prompt  # finding 内容确实进了标记区
    assert prompt.index(UNTRUSTED_OPEN) < prompt.index(original.resource)
