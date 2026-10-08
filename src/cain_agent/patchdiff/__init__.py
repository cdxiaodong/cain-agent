"""patchdiff 子包(Phase 5-C)——补丁 diff → 结构化变更集 → 根因谓词蒸馏。

经验吸收(匿名化):1-day 补丁是最便宜的情报,diff→根因→模式蒸馏→
变体搜索是最高产的可复制流水线。本包 C1 为纯函数解析地基。
"""

from cain_agent.patchdiff.distill import (
    PredicateError,
    build_distill_prompt,
    validate_predicate,
)
from cain_agent.patchdiff.parser import (
    ChangeSet,
    Hunk,
    PatchDiffError,
    parse_unified_diff,
)

__all__ = [
    "ChangeSet",
    "Hunk",
    "PatchDiffError",
    "PredicateError",
    "build_distill_prompt",
    "parse_unified_diff",
    "validate_predicate",
]
