"""BAC 离线证据包输入验证 — load_evidence 纯函数(09-09 任务 2)。

把外部证据包(离线重放对照的记录)严格校验并构造为
``RequestPair`` / ``ResponseDiff``:

- **只验证/构造,不判定**:本模块不调用 ``judge_bac`` —— 输入合法只代表
  「证据包可解析」,不代表漏洞已确认。
- **严格白名单**:顶层与 request/response 各层均只允许既定键,未知键
  (含 headers / cookies / token / body 等敏感字段)一律拒绝——证据包只
  收判定所需元数据,明文请求体与凭证不得进入。
- **错误信息只含字段路径名**:不含输入值,杜绝凭证经报错外泄。
- 零 IO / 零 HTTP / 零新依赖。
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import NoReturn

from cain_agent.web.bac_core import RequestPair, ResponseDiff, VictimSideChange

_TOP_KEYS = frozenset({"request", "response"})
"""顶层白名单:证据包只含请求对与响应差两节。"""

_REQUEST_KEYS = frozenset({
    "method_a", "url_a", "method_b", "url_b", "object_owner", "replay_as",
    "is_privileged_action", "replay_role_lower",
})
_REQUEST_REQUIRED = ("method_a", "url_a", "method_b", "url_b", "object_owner", "replay_as")

_RESPONSE_KEYS = frozenset({
    "status_a", "status_b", "owner_fields_match", "content_similarity",
    "victim_side_change",
})
_RESPONSE_REQUIRED = ("status_a", "status_b", "owner_fields_match", "content_similarity")

_FORBIDDEN_NAME_FRAGMENTS = (
    "header", "cookie", "token", "body", "authoriz", "secret", "password", "credential",
)
"""键名黑名单片段:命中即拒绝——证据包不得携带请求头/Cookie/令牌/正文类字段。"""

_CHANGE_VALUES = frozenset(c.value for c in VictimSideChange)


def _reject(field: str, reason: str) -> NoReturn:
    """抛出只含字段名与原因的 ValueError(绝不包含输入值)。"""
    raise ValueError(f"evidence[{field}]: {reason}")


def _check_key_whitelist(section: Mapping[str, object], allowed: frozenset[str], prefix: str) -> None:
    for key in section:
        if key not in allowed:
            low = str(key).lower()
            if any(frag in low for frag in _FORBIDDEN_NAME_FRAGMENTS):
                _reject(f"{prefix}.{key}", "敏感字段被拒绝(证据包仅收判定所需元数据)")
            _reject(f"{prefix}.{key}", "未知字段")


def _req_str(section: Mapping[str, object], key: str, prefix: str) -> str:
    value = section.get(key)
    if not isinstance(value, str) or isinstance(value, bool) or not value.strip():
        _reject(f"{prefix}.{key}", "必须为非空字符串")
    return value


def _req_status(section: Mapping[str, object], key: str, prefix: str) -> int:
    value = section.get(key)
    # bool 是 int 子类,显式排除(bool 冒充 int 必须拒绝)
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        _reject(f"{prefix}.{key}", "必须为 100-599 的整数 HTTP 状态码")
    return value


def _req_bool(section: Mapping[str, object], key: str, prefix: str) -> bool:
    value = section.get(key)
    if not isinstance(value, bool):
        _reject(f"{prefix}.{key}", "必须为布尔值")
    return value


def _req_similarity(section: Mapping[str, object], key: str, prefix: str) -> float:
    value = section.get(key)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 1.0
    ):
        _reject(f"{prefix}.{key}", "必须为 [0,1] 内有限数值")
    return float(value)


def load_evidence(data: Mapping[str, object]) -> tuple[RequestPair, ResponseDiff]:
    """校验并构造一次重放对照的证据对(纯函数,不判定漏洞)。

    返回 ``(RequestPair, ResponseDiff)``;任何结构/类型/取值违规抛
    ``ValueError``,消息只含字段路径与原因,不含输入内容。
    """
    if not isinstance(data, Mapping):
        _reject("(root)", "证据包必须为对象映射")

    _check_key_whitelist(data, _TOP_KEYS, "")
    request = data.get("request")
    response = data.get("response")
    if not isinstance(request, Mapping):
        _reject("request", "缺失或不是对象")
    if not isinstance(response, Mapping):
        _reject("response", "缺失或不是对象")

    _check_key_whitelist(request, _REQUEST_KEYS, "request")
    _check_key_whitelist(response, _RESPONSE_KEYS, "response")

    for key in _REQUEST_REQUIRED:
        if key not in request:
            _reject(f"request.{key}", "必填字段缺失")
    for key in _RESPONSE_REQUIRED:
        if key not in response:
            _reject(f"response.{key}", "必填字段缺失")

    pair = RequestPair(
        method_a=_req_str(request, "method_a", "request"),
        url_a=_req_str(request, "url_a", "request"),
        method_b=_req_str(request, "method_b", "request"),
        url_b=_req_str(request, "url_b", "request"),
        object_owner=_req_str(request, "object_owner", "request"),
        replay_as=_req_str(request, "replay_as", "request"),
        is_privileged_action=_req_bool(request, "is_privileged_action", "request")
        if "is_privileged_action" in request else False,
        replay_role_lower=_req_bool(request, "replay_role_lower", "request")
        if "replay_role_lower" in request else False,
    )

    change_raw = response.get("victim_side_change", VictimSideChange.NONE.value)
    if not isinstance(change_raw, str) or change_raw not in _CHANGE_VALUES:
        _reject("response.victim_side_change", f"必须为 {sorted(_CHANGE_VALUES)} 之一")

    diff = ResponseDiff(
        status_a=_req_status(response, "status_a", "response"),
        status_b=_req_status(response, "status_b", "response"),
        owner_fields_match=_req_bool(response, "owner_fields_match", "response"),
        content_similarity=_req_similarity(response, "content_similarity", "response"),
        victim_side_change=VictimSideChange(change_raw),
    )
    return pair, diff


__all__: list[str] = ["load_evidence"]
