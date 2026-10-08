"""C2 根因谓词蒸馏首版(Phase 5-C2)——prompt 模板 + 确定性防幻觉校验。

经验吸收(匿名化):diff→根因→模式蒸馏→变体搜索是最高产的流水线;
LLM 蒸馏的最大风险是**幻觉谓词**(编造变更集中不存在的符号)。本模块
产出蒸馏 prompt 模板(纯字符串,不调 LLM),并以 ``validate_predicate``
做确定性校验:谓词必须引用变更集的实际符号,不引用即拒。
"""

from __future__ import annotations

from typing import Any

from cain_agent.patchdiff.parser import ChangeSet

_DISTILL_INSTRUCTIONS = """你是漏洞根因分析引擎。基于下列补丁变更集,蒸馏出"根因谓词"——
可跨代码面搜索的漏洞不变量(供变体挖掘复用)。

要求:
1. 只输出一个 JSON 对象(不要散文/markdown 围栏),五字段:
   {"target_kind": "...", "invariant": "...", "violation": "...",
    "verify_method": "...", "confidence_prior": 0.0~1.0}
2. **invariant 与 violation 必须引用变更集中实际出现的符号/函数名/
   字段名**(下方"变更集符号表"列出)——引用表外符号输出无效;
3. confidence_prior 按证据强度保守取值:仅单点修改 0.5~0.7,
   多 hunk 同模式 ≥0.8;
4. verify_method 写可执行的一句话验证法(对照差异/断言/回放);
5. 不得编造补丁意图之外的修复背景。"""


def build_distill_prompt(changeset: ChangeSet) -> str:
    """变更集 → LLM 蒸馏 prompt(纯模板;空变更集返回空串)。"""
    if not changeset.hunks:
        return ""
    symbols = sorted(changeset.symbols())
    lines = [_DISTILL_INSTRUCTIONS, "", "## 变更集符号表(引用白名单)"]
    lines += [f"- {s}" for s in symbols] if symbols else ["- (无提取符号——禁止输出)"]
    lines += ["", "## 变更集内容(hunk 摘要)"]
    for h in changeset.hunks:
        lines.append(f"### {h.file_path} @@ -{h.old_start} +{h.new_start}")
        for name in h.signature_changes:
            lines.append(f"- 签名变化: {name}")
        for c in h.added_checks:
            lines.append(f"- 新增校验: {c[:80]}")
        for r in h.removed_paths:
            lines.append(f"- 删除路径: {r[:80]}")
    return "\n".join(lines)


_PREDICATE_FIELDS = ("target_kind", "invariant", "violation", "verify_method")


class PredicateError(ValueError):
    """谓词校验失败(结构或符号引用)。"""


def validate_predicate(predicate: object, changeset: ChangeSet) -> dict[str, Any]:
    """确定性校验蒸馏产物;不合格抛 ``PredicateError``。

    结构:dict 且五字段齐全(target_kind/invariant/violation/
    verify_method 非空字符串;confidence_prior∈(0,1] 有限数,bool 拒)。
    符号引用:invariant 与 violation 的**至少一个字段**须含变更集符号表
    中的完整符号(词边界匹配)——都不含即判幻觉拒绝。
    """
    if not isinstance(predicate, dict):
        raise PredicateError(f"谓词必须为 dict(得到 {type(predicate).__name__})")
    for key in _PREDICATE_FIELDS:
        value = predicate.get(key)
        if not isinstance(value, str) or not value.strip():
            raise PredicateError(f"字段 {key} 必须为非空字符串")
    prior = predicate.get("confidence_prior")
    if (
        isinstance(prior, bool)
        or not isinstance(prior, (int, float))
        or not 0.0 < float(prior) <= 1.0
    ):
        raise PredicateError(f"confidence_prior 必须为 (0,1] 内有限数({prior!r})")
    symbols = changeset.symbols()
    if symbols:
        import re

        def _hits(text: str) -> bool:
            return any(re.search(rf"\b{re.escape(s)}\b", text) for s in symbols)

        if not (_hits(predicate["invariant"]) or _hits(predicate["violation"])):
            sample = ", ".join(sorted(symbols)[:8])
            raise PredicateError(
                f"幻觉拒绝:invariant/violation 均未引用变更集符号(白名单样例: {sample})"
            )
    return predicate


__all__ = ["PredicateError", "build_distill_prompt", "validate_predicate"]
