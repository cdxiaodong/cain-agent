"""BAC/IDOR 判定核心 — 双账号请求对重放对照的纯函数判定。

方法论对照(产线 BAC 技能,请求构造/判定标准/证据要求):

- **RBAC 读越权**:用攻击者(B)会话重放受害者(A)的读请求,B 实际读到
  A 私有数据即成立;相似度阈值 ``0.7`` 起步,且必须人工核验归属字段;
  对比前先过滤公共页面(共享资源不算越权)。
- **MBAC 未授权写**(直接响应不可靠,依赖页面反馈判定):
  ``INSERT`` = Victim 依赖页出现新 token;``UPDATE`` = 新 token 出现且
  旧值消失;``DELETE`` = Victim 原有记录/字段消失。
- **质量要求**:已确认漏洞至少复现两次;GET 触发修改属异常场景须人工复核;
  重放前确认对象真实归属,防止共享资源误判。

本模块只做判定(输入请求对与响应差异,输出结论),不做 HTTP、不做 IO。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import StrEnum

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
"""只读方法集;其余(POST/PUT/PATCH/DELETE)视为写操作,进 MBAC 判定。"""

_FORBIDDEN_STATUS = frozenset({401, 403})
"""拒绝类状态码:B 重放被拒说明防护在位。"""

_GRAY_ZONE_LOW = 0.5
"""相似度灰区下沿:低于它视为内容显著不同(多数是拒页/错误页)。"""


class Kind(StrEnum):
    """判定结论类型。"""

    HORIZONTAL = "horizontal"  # 水平越权:同级他人会话读到/改了受害者资源
    VERTICAL = "vertical"    # 垂直越权:低权角色完成了需高权的动作
    NONE = "none"            # 未发现越权


class VictimSideChange(StrEnum):
    """Victim 依赖页面的变化形态(MBAC 判定的证据源)。"""

    NONE = "none"
    NEW_TOKEN = "insert"        # 出现新 token(INSERT)
    TOKEN_REPLACED = "update"   # 新 token 出现且旧值消失(UPDATE)
    TOKEN_GONE = "delete"       # 原有记录/字段消失(DELETE)


@dataclass(frozen=True)
class RequestPair:
    """请求对:受害者(A)原始请求 + 攻击者(B)重放请求的元数据。

    ``object_owner`` 是被访问资源的真实归属者标识;``replay_as`` 是重放
    所用会话的用户标识——两者不同才构成"跨账号重放"前提。
    """

    method_a: str
    url_a: str
    method_b: str
    url_b: str
    object_owner: str
    replay_as: str
    is_privileged_action: bool = False
    """A 的动作是否需要高于 B 的权限(垂直越权判定前提)。"""
    replay_role_lower: bool = False
    """B 的角色是否明确低于 A(垂直越权判定前提)。"""


@dataclass(frozen=True)
class ResponseDiff:
    """两次响应的差异三元组(+MBAC 证据)。"""

    status_a: int
    status_b: int
    owner_fields_match: bool
    """B 的响应中资源归属字段是否仍指向 ``object_owner``(读到他人数据)。"""
    content_similarity: float
    """A/B 正文相似度 0~1(归一化后由调用方计算)。"""
    victim_side_change: VictimSideChange = VictimSideChange.NONE
    """写操作后 Victim 依赖页的变化(MBAC 证据;读请求恒为 NONE)。"""


@dataclass(frozen=True)
class BACConfig:
    """判定阈值(默认对齐方法论:相似度 0.7 起步)。"""

    similarity_threshold: float = 0.7
    forbidden_status: frozenset[int] = field(default_factory=lambda: _FORBIDDEN_STATUS)


@dataclass(frozen=True)
class BACVerdict:
    """判定结论:类型 + 置信度 + 依据链 + MBAC 标记。"""

    kind: Kind
    confidence: float
    rationale: str
    mbac: bool = False
    victim_side_change: VictimSideChange = VictimSideChange.NONE


def judge_bac(pair: RequestPair, diff: ResponseDiff, config: BACConfig | None = None) -> BACVerdict:
    """对一次重放对照下判定结论(纯函数)。

    判定序(证据从硬到软):

    0. 数值非法(similarity/阈值 NaN、Inf、越界)→ 显式 ``ValueError``,
       拒绝产生任何结论;
    1. 重放者身份缺失 → ``none``;
    2. Victim 依赖页变化(MBAC 证据,以效果为准,先于拒绝状态码)→
       **MBAC 成立**,归属 ``horizontal`` + ``mbac=True``;归属缺失/同账号
       排除;拒绝状态码与之并存属冲突证据,降置信并要求人工复核;读方法
       触发的异常场景降置信;
    3. B 被拒(401/403)且依赖页无变化 → 防护在位,``none``;
    4. 同账号/归属缺失 → ``none``(防同账号重放误报);
    5. 读方法 + B 2xx + 归属字段指向原属主 → 读到他人私有数据,
       ``horizontal``;相似度 ≥ 阈值增强置信,灰区降置信并提示人工核验;
    6. 特权动作 + B 角色更低 + B 200 → ``vertical``;
    7. 其余(读到共享/自身资源、内容完全不同、非 2xx)→ ``none``。
    """
    cfg = config or BACConfig()
    method = pair.method_b.upper()
    is_write = method not in _READ_METHODS  # 仅用于读分支的排除,MBAC 以效果为准
    reasons: list[str] = []

    # 0) 数值显式校验:非法输入拒绝产生任何结论(issue #9 同源缺陷类)
    if not math.isfinite(diff.content_similarity) or not 0.0 <= diff.content_similarity <= 1.0:
        raise ValueError(
            f"content_similarity 非法: {diff.content_similarity!r}(须为 [0,1] 内有限数)"
        )
    if not math.isfinite(cfg.similarity_threshold) or not 0.0 < cfg.similarity_threshold <= 1.0:
        raise ValueError(
            f"similarity_threshold 非法: {cfg.similarity_threshold!r}(须为 (0,1] 内有限数)"
        )

    # 1) 身份前置检查:重放者身份缺失,任何越权结论都失去跨账号前提
    if not pair.replay_as:
        return BACVerdict(
            kind=Kind.NONE,
            confidence=0.5,
            rationale="replay_as 为空:重放者身份缺失,无法构成跨账号越权证据",
        )

    # 2) MBAC:以 Victim 依赖页变化为准(直接响应不可靠),先于拒绝状态码——
    #    依赖页变化是比状态码更硬的写效果证据;拒绝状态码与之并存属冲突证据
    if diff.victim_side_change is not VictimSideChange.NONE:
        change = diff.victim_side_change
        if not pair.object_owner or pair.object_owner == pair.replay_as:
            return BACVerdict(
                kind=Kind.NONE,
                confidence=0.6,
                rationale=(
                    "Victim 依赖页有变化,但资源归属身份缺失或与重放者相同,"
                    "不构成跨账号越权写(须人工核验归属)"
                ),
                victim_side_change=change,
            )
        is_read = method in _READ_METHODS
        confidence = 0.75 if not is_read else 0.5
        if diff.status_b in cfg.forbidden_status:
            confidence = min(confidence, 0.55)
            reasons.append(
                f"冲突证据:响应被拒(status={diff.status_b})但依赖页发生"
                f"{change.value} 变化——写效果已发生,不能仅凭状态码称防护在位,须人工复核"
            )
        if is_read:
            reasons.append("GET/HEAD 触发修改属异常场景,须人工复核(降置信)")
        reasons.append(
            f"写操作后 Victim 依赖页变化={change.value}(依赖页面反馈判定,"
            "直接响应不可靠)"
        )
        return BACVerdict(
            kind=Kind.HORIZONTAL,
            confidence=confidence,
            rationale=";".join(reasons),
            mbac=True,
            victim_side_change=change,
        )

    # 3) 拒绝类状态码:防护在位(依赖页无变化时状态码才是充分证据)
    if diff.status_b in cfg.forbidden_status:
        return BACVerdict(
            kind=Kind.NONE,
            confidence=0.9,
            rationale=f"B 重放被拒(status={diff.status_b}),鉴权防护在位",
        )

    # 4) 同账号/归属缺失排除:读越权前提是资源明确归属他人
    if not pair.object_owner or pair.object_owner == pair.replay_as:
        if _is_success(diff.status_b) and not diff.owner_fields_match:
            return BACVerdict(
                kind=Kind.NONE,
                confidence=0.6,
                rationale="B 响应归属字段不指向原属主(共享资源或自身资源,排除越权)",
            )
        return BACVerdict(
            kind=Kind.NONE,
            confidence=0.6,
            rationale=(
                "资源归属身份缺失或与重放者相同,不构成跨账号读越权"
                "(共享/自身资源排除,防同账号重放误报)"
            ),
        )

    # 5) RBAC 读越权:B 2xx 且归属字段仍指向原属主
    if not is_write and _is_success(diff.status_b) and diff.owner_fields_match:
        confidence = 0.7
        if diff.content_similarity >= cfg.similarity_threshold:
            confidence += 0.15
            reasons.append(
                f"正文相似度 {diff.content_similarity:.2f} ≥ 阈值 "
                f"{cfg.similarity_threshold:.2f}"
            )
        elif diff.content_similarity >= _GRAY_ZONE_LOW:
            confidence = 0.55
            reasons.append(
                f"相似度 {diff.content_similarity:.2f} 处于灰区"
                f"({_GRAY_ZONE_LOW}~{cfg.similarity_threshold}),须人工核验归属字段"
            )
        else:
            confidence = 0.5
            reasons.append(
                f"相似度 {diff.content_similarity:.2f} 低于灰区下沿,"
                "响应内容与原请求显著不同(疑似拒页),须人工复核"
            )
        reasons.append(
            f"B 会话({pair.replay_as})读到归属字段仍指向 {pair.object_owner} 的资源"
        )
        return BACVerdict(
            kind=Kind.HORIZONTAL,
            confidence=min(confidence, 0.95),
            rationale=";".join(reasons),
        )

    # 6) 垂直越权:特权动作 + 角色更低 + B 仍成功
    if (
        pair.is_privileged_action
        and pair.replay_role_lower
        and _is_success(diff.status_b)
    ):
        return BACVerdict(
            kind=Kind.VERTICAL,
            confidence=0.8,
            rationale=(
                f"特权动作({pair.method_b} {pair.url_b})由低权角色 "
                f"({pair.replay_as})完成且成功(status={diff.status_b})"
            ),
        )

    # 7) 未构成越权
    if _is_success(diff.status_b) and not diff.owner_fields_match:
        reason = "B 响应归属字段不指向原属主(共享资源或自身资源,排除越权)"
    elif not _is_success(diff.status_b):
        reason = f"B 响应非成功状态(status={diff.status_b})"
    else:
        reason = "无可判定的越权证据"
    return BACVerdict(kind=Kind.NONE, confidence=0.6, rationale=reason)


def _is_success(status: int) -> bool:
    return 200 <= status < 300
