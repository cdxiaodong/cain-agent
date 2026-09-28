"""patterns.jsonl 校验器(Phase 5-B1)——五字段假设格式的确定性加载。

经验吸收(匿名化):把方向性知识固化为**浓缩模式库**而非全量技能注入,
recon→test 间按模式产定点假设,防单体上下文过早收敛。本模块只做
格式校验与加载(纯函数零 IO),坏行拒绝带行号。
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

_PATTERN_FIELDS = ("target_kind", "invariant", "violation", "verify_method")
"""必填四字段(第五字段 confidence_prior 单独校验数值)。"""


class PatternError(ValueError):
    """patterns.jsonl 行校验失败。"""


def validate_pattern(raw: object, source: str = "pattern") -> dict[str, object]:
    """校验单条 pattern dict;非法抛 ``PatternError``(消息含 source 定位)。

    规则:必须为 dict;四必填字段非空字符串;``confidence_prior`` 为
    (0,1] 内有限数(bool 冒充 float 拒绝)。
    """
    if not isinstance(raw, dict):
        raise PatternError(f"{source}: 必须为 JSON 对象(得到 {type(raw).__name__})")
    for key in _PATTERN_FIELDS:
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            raise PatternError(f"{source}: 字段 {key} 必须为非空字符串")
    prior = raw.get("confidence_prior")
    if (
        isinstance(prior, bool)
        or not isinstance(prior, (int, float))
        or not 0.0 < float(prior) <= 1.0
    ):
        raise PatternError(
            f"{source}: confidence_prior 必须为 (0,1] 内有限数(得到 {prior!r})"
        )
    return raw


def iter_patterns(text: str) -> Iterator[dict[str, object]]:
    """逐行加载 JSONL;空行跳过,坏行抛 ``PatternError``(带行号)。"""
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise PatternError(f"line {lineno}: JSON 解析失败({exc.msg})") from exc
        yield validate_pattern(payload, f"line {lineno}")


def load_patterns(path: str | Path) -> list[dict[str, object]]:
    """从 patterns.jsonl 加载全量(坏行立即抛错,坏文件不半载)。"""
    return list(iter_patterns(Path(path).read_text(encoding="utf-8")))


__all__ = ["PatternError", "iter_patterns", "load_patterns", "validate_pattern"]
