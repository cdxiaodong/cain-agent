"""web 子包 — 业务逻辑漏洞检测(BAC/IDOR 等判定核心)。

Phase 3 功能主线第一件(2026-09-07 派活单任务 1 最小切片):双账号请求对
重放对照的**判定核心**——纯函数、零副作用、零 IO,HTTP 执行层与编排接入
留后续任务。
"""

from cain_agent.web.bac_core import (
    BACConfig,
    BACVerdict,
    Kind,
    RequestPair,
    ResponseDiff,
    VictimSideChange,
    judge_bac,
)

__all__ = [
    "BACConfig",
    "BACVerdict",
    "Kind",
    "RequestPair",
    "ResponseDiff",
    "VictimSideChange",
    "judge_bac",
]
