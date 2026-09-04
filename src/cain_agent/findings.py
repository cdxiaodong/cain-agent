"""Findings —— 校验闭环的确定性底座:数据模型 / 指纹去重 / 定级规则表。

DESIGN.md §3.3:发现者 Agent 与校验 Agent 分离之前,先把三件确定性工程
做死在本模块——

- ``Finding`` 数据类:四状态校验结果 + 五级定级 + 证据哈希(证据本身只
  哈希不落明文,遵循 §3.2 数据信任边界)+ ≤30 字结论。
- 指纹去重:``cloud+service+resource+issue_type`` 四元组归一化(小写、
  去首尾空白)后的 sha256;``dedup`` 保序去重(教训:CyberStrikeAI #178
  重复漏洞淹没)。
- 定级规则表:``SEVERITY_RULES`` 为代码常量数据,``classify`` 纯函数查表;
  模型只能给"建议 severity",规则表无命中时取建议与 info 的较低者
  (教训:CyberStrikeAI #163 定级虚高)。

本模块纯逻辑零触网;``to_dict`` / ``from_dict`` 与 Workspace 的
``findings.json``(顶层为 dict 列表)读写兼容,round-trip 无损。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, TypeVar

__all__ = [
    "Finding",
    "FindingError",
    "FindingResult",
    "SEVERITY_RULES",
    "Severity",
    "SeverityRule",
    "classify",
    "dedup",
    "fingerprint",
    "hash_evidence",
    "has_confirmable_provenance",
]

REASON_MAX_LEN = 30
"""``Finding.reason`` 的字符上限(按 Unicode 码点计,中文一字一码点)。"""

_EVIDENCE_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")


class FindingError(ValueError):
    """Finding 数据非法(枚举值、reason 超长、哈希格式错误等)时抛出。"""


class FindingResult(StrEnum):
    """校验结果四状态(DESIGN §3.3,沿用 4 状态思想)。"""

    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    VALIDATION_SYSTEM_ERROR = "validation_system_error"
    VALIDATION_INCONCLUSIVE = "validation_inconclusive"


class Severity(StrEnum):
    """定级五级,自高到低:critical > high > medium > low > info。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
""" rank 越小定级越高;``less_severe`` 取 rank 较大者。"""


def _less_severe(a: Severity, b: Severity) -> Severity:
    """返回两者中定级较低(更保守)的一个。"""
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b


_E = TypeVar("_E", FindingResult, Severity)


def _coerce_enum(value: object, enum_cls: type[_E], field: str) -> _E:
    """字符串/枚举成员统一收敛为枚举成员;非法值抛 ``FindingError``。"""
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)  # type: ignore[arg-type]
    except ValueError:
        legal = [member.value for member in enum_cls]
        raise FindingError(f"{field} 非法值: {value!r}(合法值: {legal})") from None


def hash_evidence(evidence: str) -> str:
    """从证据文本计算 ``sha256:<hex>`` 哈希。

    证据原文(可能含凭证样式字符串)只进哈希,任何落盘的 Finding 只携带
    哈希值,不落明文(DESIGN §3.2 数据信任边界)。
    """
    if not isinstance(evidence, str):
        raise FindingError(f"证据必须是字符串: {type(evidence).__name__}")
    return "sha256:" + hashlib.sha256(evidence.encode("utf-8")).hexdigest()


def _normalize(text: str) -> str:
    """指纹归一化:去首尾空白 + 小写。"""
    return text.strip().lower()


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FindingError(f"{field} 必须是非空字符串: {value!r}")
    return value


@dataclass(frozen=True)
class Finding:
    """一条"发现"的不可变记录,字段对齐 DESIGN §3.3。

    构造即校验:非法枚举值、超长 reason、格式错误的 evidence_hash 一律
    抛 ``FindingError``,绝不让带病数据进入 findings.json。
    """

    finding_id: str
    result: FindingResult
    severity: Severity
    evidence_hash: str
    reason: str
    cloud: str
    service: str
    resource: str
    issue_type: str
    provenance: dict[str, Any] | None = None
    invalid_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "finding_id")
        object.__setattr__(self, "result", _coerce_enum(self.result, FindingResult, "result"))
        object.__setattr__(self, "severity", _coerce_enum(self.severity, Severity, "severity"))
        if not _EVIDENCE_HASH_RE.fullmatch(self.evidence_hash):
            raise FindingError(
                f"evidence_hash 必须是 sha256:<64位小写hex>: {self.evidence_hash!r}"
            )
        _require_text(self.reason, "reason")
        if len(self.reason) > REASON_MAX_LEN:
            raise FindingError(
                f"reason 超长: {len(self.reason)} 字(上限 {REASON_MAX_LEN} 字)"
            )
        for field in ("cloud", "service", "resource", "issue_type"):
            _require_text(getattr(self, field), field)
        if self.provenance is not None and not isinstance(self.provenance, dict):
            raise FindingError("provenance 必须是 dict 或 null")
        if not isinstance(self.invalid_reasons, tuple):
            object.__setattr__(self, "invalid_reasons", tuple(self.invalid_reasons))
        if any(not isinstance(reason, str) or not reason for reason in self.invalid_reasons):
            raise FindingError("invalid_reasons 必须是非空字符串列表")

    # -- findings.json 序列化 ---------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """转为纯 dict(枚举取 value),可直接进 Workspace.findings.json。"""
        data: dict[str, Any] = {
            "finding_id": self.finding_id,
            "result": self.result.value,
            "severity": self.severity.value,
            "evidence_hash": self.evidence_hash,
            "reason": self.reason,
            "cloud": self.cloud,
            "service": self.service,
            "resource": self.resource,
            "issue_type": self.issue_type,
        }
        if self.provenance is not None:
            data["provenance"] = dict(self.provenance)
        if self.invalid_reasons:
            data["invalid_reasons"] = list(self.invalid_reasons)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """从 findings.json 的 dict 还原;缺键/多键/类型错误一律拒绝。"""
        if not isinstance(data, dict):
            raise FindingError(f"Finding 必须是 dict: {type(data).__name__}")
        required = {
            "finding_id", "result", "severity", "evidence_hash", "reason",
            "cloud", "service", "resource", "issue_type",
        }
        optional = {"provenance", "invalid_reasons"}
        keys = set(data)
        missing = required - keys
        extra = keys - required - optional
        if missing:
            raise FindingError(f"Finding 缺字段: {sorted(missing)}")
        if extra:
            raise FindingError(f"Finding 含未知字段: {sorted(extra)}")
        payload = dict(data)
        payload["invalid_reasons"] = tuple(payload.get("invalid_reasons") or ())
        return cls(**payload)


def has_confirmable_provenance(finding: Finding) -> bool:
    """Return True only for a complete, internally linked executed request record."""
    p = finding.provenance
    if not isinstance(p, dict):
        return False
    required_text = ("request_id", "url", "host", "method", "timestamp", "response_hash")
    if any(not isinstance(p.get(key), str) or not str(p[key]).strip() for key in required_text):
        return False
    if p.get("evidence_request_id") != p.get("request_id"):
        return False
    if p.get("evidence_hash") != finding.evidence_hash:
        return False
    if p.get("executed") is not True:
        return False
    status = p.get("status_code")
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        return False
    if not _EVIDENCE_HASH_RE.fullmatch(str(p["response_hash"])):
        return False
    try:
        datetime.fromisoformat(str(p["timestamp"]).replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def fingerprint(finding: Finding) -> str:
    """``cloud+service+resource+issue_type`` 四元组归一化后的 sha256。

    大小写/首尾空白变体判同(归一化后哈希),指纹相同的 Finding 视为同一
    问题的重复报告。
    """
    parts = (
        _normalize(finding.cloud),
        _normalize(finding.service),
        _normalize(finding.resource),
        _normalize(finding.issue_type),
    )
    return "sha256:" + hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def dedup(findings: list[Finding]) -> list[Finding]:
    """按指纹保序去重:同指纹只保留首次出现的那条。"""
    seen: set[str] = set()
    out: list[Finding] = []
    for finding in findings:
        fp = fingerprint(finding)
        if fp not in seen:
            seen.add(fp)
            out.append(finding)
    return out


@dataclass(frozen=True)
class SeverityRule:
    """定级规则:命中的 Finding 定级为 ``severity``。

    ``cloud`` / ``service`` / ``issue_type`` 为匹配条件,``None`` 表示该维
    任意(通配);匹配前双方都做小写 + 去首尾空白归一化。规则表按优先级
    从高到低排列,``classify`` 取第一条命中规则。
    """

    severity: Severity
    issue_type: str | None = None
    cloud: str | None = None
    service: str | None = None
    description: str = ""

    def matches(self, finding: Finding) -> bool:
        return (
            self._match(self.cloud, finding.cloud)
            and self._match(self.service, finding.service)
            and self._match(self.issue_type, finding.issue_type)
        )

    @staticmethod
    def _match(pattern: str | None, value: str) -> bool:
        return pattern is None or _normalize(pattern) == _normalize(value)


SEVERITY_RULES: tuple[SeverityRule, ...] = (
    # 表即代码常量,按优先级从高到低排列,先命中先生效。
    SeverityRule(
        severity=Severity.CRITICAL,
        issue_type="public-write-storage",
        description="公开可写存储(任何人可上传/覆盖对象)",
    ),
    SeverityRule(
        severity=Severity.HIGH,
        issue_type="public-read-sensitive",
        description="公开读且含敏感数据(DESIGN §3.3:公开桶+敏感数据 high 起步)",
    ),
    SeverityRule(
        severity=Severity.HIGH,
        issue_type="public-read",
        description="公开可读存储(匿名列对象/读对象)",
    ),
    SeverityRule(
        severity=Severity.HIGH,
        issue_type="metadata-endpoint-reachable",
        description="云元数据端点可达(凭证窃取面)",
    ),
    SeverityRule(
        severity=Severity.MEDIUM,
        issue_type="misconfiguration",
        description="仅配置不规范,无直接数据暴露面",
    ),
)
"""内置云场景定级规则表:代码常量数据,模型不可绕过。"""


def classify(finding: Finding, suggested: Severity | str | None = None) -> Severity:
    """定级纯函数:查规则表,返回最终 severity。

    - 规则表命中:直接返回规则定级,模型建议一律作废(规则优先)。
    - 无命中:取 ``suggested``(模型建议)与 info 的较低者——即保守降级
      为 info,不给模型自评抬级的机会(教训:CyberStrikeAI #163)。
    """
    for rule in SEVERITY_RULES:
        if rule.matches(finding):
            return rule.severity
    if suggested is None:
        return Severity.INFO
    suggested_sev = _coerce_enum(suggested, Severity, "suggested")
    return _less_severe(suggested_sev, Severity.INFO)
