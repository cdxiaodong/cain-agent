"""Aliyun RAM privilege-escalation path analysis (read-only).

Maps the RhinoSecurity Labs published AWS privesc research to Alibaba Cloud
RAM equivalents. Only **Get/List** RAM API operations are used -- never write,
attach, create, or delete. Severity is assigned by **hardcoded rule constants**,
never by a model.

Security contract
-----------------
* Credentials are read from constructor arguments, falling back to the
  ``ALIBABA_CLOUD_*`` environment variables. They are never logged, never
  written to disk, and there is **no default or hardcoded key**.
* Recommended practice: provision a RAM sub-account with a read-only policy
  (e.g. ``AliyunRAMReadOnlyAccess``) and pass its keys via environment
  variables or constructor arguments.
* SDK selection: this module uses ``requests`` with the Aliyun RPC v1
  signature (HMAC-SHA1) rather than the official ``alibabacloud-ram20150501``
  SDK.  Rationale: (1) ``requests`` is already available transitively via
  ``oss2``, so no new heavyweight dependency is introduced; (2) the RPC-style
  RAM APIs are simple GET endpoints whose signing is ~30 lines of code;
  (3) the internal ``_call_api`` method is the single mock seam, keeping the
  test suite fully isolated from the network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import requests

__all__ = [
    "PRIVESC_RULES",
    "RamCredentialError",
    "RamFinding",
    "RamPrivescAnalyzer",
    "PrivescRule",
]

# --------------------------------------------------------------------------- #
# Environment variable names (priority order). Parameters always win.
# --------------------------------------------------------------------------- #

_ENV_AK_ID = ("ALIBABA_CLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY")
_ENV_AK_SECRET = ("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALICLOUD_SECRET_KEY")
_ENV_REGION = ("ALIBABA_CLOUD_REGION",)

_DEFAULT_REGION = "cn-hangzhou"
_RAM_ENDPOINT = "https://ram.aliyuncs.com"


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PrivescRule:
    """A single RAM privesc path (code constant, not model output).

    ``required_perms`` is a set of RAM action strings; a principal is
    considered to have this path if **all** permissions in at least one
    inner set are present (AND-within-set, OR-across-sets). A ``"*"`` in the
    action list matches any action (administrator-equivalent).
    """

    rule_id: str
    required_perms: tuple[tuple[str, ...], ...]
    description: str
    severity: str  # "critical" | "high" | "medium"

    def matches(self, actions: set[str]) -> bool:
        """True if any permission-set is fully covered by *actions*.

        Supports service wildcards: ``ram:*`` covers any ``ram:PassRole``,
        ``ram:AttachPolicyToUser``, etc. Action strings are compared
        case-insensitively.
        """
        if "*" in actions:
            return True
        return any(
            all(self._perm_covered(perm, actions) for perm in perms)
            for perms in self.required_perms
        )

    @staticmethod
    def _perm_covered(perm: str, actions: set[str]) -> bool:
        """Check whether a single permission is covered by the action set."""
        p = perm.lower()
        if p in actions:
            return True
        svc = p.split(":", 1)[0]
        return f"{svc}:*" in actions


@dataclass
class RamFinding:
    """Structured finding for a single RAM privesc path hit.

    Fields align with ``findings.Finding`` so the result can be converted
    directly: ``cloud="aliyun"``, ``service="ram"``.
    """

    rule_id: str
    resource: str  # user ARN / role ARN / "account-root"
    issue_type: str  # maps to Finding.issue_type
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class RamCredentialError(RuntimeError):
    """Raised when no access-key pair is available from params or env."""


# --------------------------------------------------------------------------- #
# Privesc rules table (code constants)
#
# Source: RhinoSecurity Labs "AWS IAM Privilege Escalation - Methods and
# Mitigation" mapped to Alibaba Cloud RAM equivalents. Each rule lists the
# minimum permission set that opens the path.
# --------------------------------------------------------------------------- #

PRIVESC_RULES: tuple[PrivescRule, ...] = (
    PrivescRule(
        rule_id="ram:PassRole-to-Compute",
        required_perms=(
            ("ram:PassRole", "fc:CreateFunction"),
            ("ram:PassRole", "ecs:RunInstances"),
        ),
        description=(
            "可 PassRole 且能创建函数/实例:借高权角色执行代码,等同角色权限"
        ),
        severity="critical",
    ),
    PrivescRule(
        rule_id="ram:AttachPolicyToSelf",
        required_perms=(
            ("ram:AttachPolicyToUser",),
            ("ram:AttachPolicyToGroup",),
            ("ram:AttachPolicyToRole",),
        ),
        description=(
            "可给自己或可控实体挂载任意策略:直接 Attach 管理员策略完成提权"
        ),
        severity="critical",
    ),
    PrivescRule(
        rule_id="ram:CreateAccessKey-for-HighPriv",
        required_perms=(
            ("ram:CreateAccessKey",),
        ),
        description=(
            "可为任意用户创建 AccessKey:窃取高权用户凭证冒用其身份"
        ),
        severity="critical",
    ),
    PrivescRule(
        rule_id="ram:LoginProfile-Hijack",
        required_perms=(
            ("ram:CreateLoginProfile",),
            ("ram:UpdateLoginProfile",),
        ),
        description=(
            "可创建/修改控制台登录配置:劫持高权用户控制台登录"
        ),
        severity="high",
    ),
    PrivescRule(
        rule_id="ram:AssumeRole-Chain",
        required_perms=(
            ("sts:AssumeRole",),
        ),
        description=(
            "可 AssumeRole 高权角色且该角色信任当前实体:角色链提权"
        ),
        severity="high",
    ),
)


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #


class RamPrivescAnalyzer:
    """Read-only RAM privilege-escalation path analyzer.

    All network calls go through ``_call_api``, the single mock seam. Tests
    monkeypatch this method to return canned responses without touching the
    network.
    """

    def __init__(
        self,
        access_key_id: str | None = None,
        access_key_secret: str | None = None,
        region: str | None = None,
    ) -> None:
        ak_id = access_key_id or _first_env(_ENV_AK_ID)
        ak_secret = access_key_secret or _first_env(_ENV_AK_SECRET)
        if not ak_id or not ak_secret:
            raise RamCredentialError(
                "RAM 凭证缺失: 请通过参数 access_key_id/access_key_secret 或环境变量 "
                f"{_ENV_AK_ID[0]}/{_ENV_AK_SECRET[0]} 提供只读 RAM 子账号凭证"
            )
        self.access_key_id: str = ak_id
        self.access_key_secret: str = ak_secret
        self.region: str = region or _first_env(_ENV_REGION) or _DEFAULT_REGION

    # -- API layer (mockable seam) -------------------------------------------

    def _call_api(self, action: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        """Call an Aliyun RAM RPC GET endpoint.

        Returns the parsed JSON body. Raises ``requests.HTTPError`` on non-2xx.
        This is the **only** network call site -- monkeypatch it in tests.
        """
        query = self._sign(action, params or {})
        resp = requests.get(_RAM_ENDPOINT, params=query, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def _sign(self, action: str, extra: dict[str, str]) -> dict[str, str]:
        """Build the signed query dict for an Aliyun RPC v1 call (HMAC-SHA1)."""
        params: dict[str, str] = {
            "Action": action,
            "Format": "JSON",
            "Version": "2015-05-01",
            "AccessKeyId": self.access_key_id,
            "SignatureMethod": "HMAC-SHA1",
            "SignatureVersion": "1.0",
            "SignatureNonce": uuid.uuid4().hex,
            "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "RegionId": self.region,
        }
        params.update(extra)

        # Canonical query string: sort keys, percent-encode, join with &
        sorted_items = sorted(params.items())
        canonical = "&".join(
            f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in sorted_items
        )
        string_to_sign = "GET&" + quote("/", safe="") + "&" + quote(canonical, safe="")
        digest = hmac.new(
            (self.access_key_secret + "&").encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha1,
        ).digest()
        signature = base64.b64encode(digest).decode("ascii")
        params["Signature"] = signature
        return params

    # -- RAM read-only API wrappers ------------------------------------------

    def list_users(self) -> list[dict[str, Any]]:
        """List all IAM users visible to the credentials."""
        result = self._call_api("ListUsers")
        return _extract_list(result, "Users", "User")

    def list_roles(self) -> list[dict[str, Any]]:
        """List all IAM roles visible to the credentials."""
        result = self._call_api("ListRoles")
        return _extract_list(result, "Roles", "Role")

    def list_policies_for_user(self, user_name: str) -> list[dict[str, Any]]:
        """List policies attached to a user."""
        result = self._call_api("ListPoliciesForUser", {"UserName": user_name})
        return _extract_list(result, "Policies", "Policy")

    def list_policies_for_role(self, role_name: str) -> list[dict[str, Any]]:
        """List policies attached to a role."""
        result = self._call_api("ListPoliciesForRole", {"RoleName": role_name})
        return _extract_list(result, "Policies", "Policy")

    def get_policy_document(self, policy_name: str, policy_type: str = "Custom") -> str | None:
        """Fetch a policy's default-version Document string."""
        try:
            meta = self._call_api("GetPolicy", {
                "PolicyName": policy_name,
                "PolicyType": policy_type,
            })
            version_id = meta.get("DefaultPolicyVersionId", "v1")
            detail = self._call_api("GetPolicyVersion", {
                "PolicyName": policy_name,
                "PolicyType": policy_type,
                "VersionId": version_id,
            })
            doc = detail.get("PolicyVersion", {}).get("PolicyDocument")
            return doc if isinstance(doc, str) else None
        except Exception:
            return None

    # -- analysis ------------------------------------------------------------

    def analyze(self) -> list[RamFinding]:
        """Enumerate users/roles and match their effective permissions against rules.

        Per-entity failures (permission denied, API error) are recorded in
        ``RamFinding.error`` and never abort the full scan.
        """
        findings: list[RamFinding] = []

        for user in self._safe_list(self.list_users):
            name = user.get("UserName", "?")
            arn = user.get("Arn", f"acs:ram::*:user/{name}")
            actions = self._collect_user_actions(name)
            findings.extend(self._match_rules(actions, arn, entity_type="user", name=name))

        for role in self._safe_list(self.list_roles):
            name = role.get("RoleName", "?")
            arn = role.get("Arn", f"acs:ram::*:role/{name}")
            actions = self._collect_role_actions(name)
            findings.extend(self._match_rules(actions, arn, entity_type="role", name=name))

        return findings

    # -- permission collection ----------------------------------------------

    def _collect_user_actions(self, user_name: str) -> set[str]:
        """Union of all allowed actions from policies attached to a user."""
        actions: set[str] = set()
        for policy in self._safe_list(lambda: self.list_policies_for_user(user_name)):
            doc = self.get_policy_document(
                policy.get("PolicyName", ""), policy.get("PolicyType", "Custom")
            )
            actions |= _extract_allowed_actions(doc)
        return actions

    def _collect_role_actions(self, role_name: str) -> set[str]:
        """Union of all allowed actions from policies attached to a role."""
        actions: set[str] = set()
        for policy in self._safe_list(lambda: self.list_policies_for_role(role_name)):
            doc = self.get_policy_document(
                policy.get("PolicyName", ""), policy.get("PolicyType", "Custom")
            )
            actions |= _extract_allowed_actions(doc)
        return actions

    # -- rule matching -------------------------------------------------------

    def _match_rules(
        self,
        actions: set[str],
        arn: str,
        entity_type: str,
        name: str,
    ) -> list[RamFinding]:
        """Return one RamFinding per rule that matches the principal's actions."""
        hits: list[RamFinding] = []
        for rule in PRIVESC_RULES:
            if rule.matches(actions):
                hits.append(
                    RamFinding(
                        rule_id=rule.rule_id,
                        resource=arn,
                        issue_type=rule.rule_id,
                        severity=rule.severity,
                        description=rule.description,
                        evidence={
                            "entity_type": entity_type,
                            "entity_name": name,
                            "matched_perms": sorted(
                                s for s in actions if not s.startswith("_")
                            )[:20],  # cap to avoid huge evidence
                            "is_admin": "*" in actions,
                        },
                    )
                )
        return hits

    # -- utility -------------------------------------------------------------

    @staticmethod
    def _safe_list(fn: Any) -> list[dict[str, Any]]:
        """Call a list-returning function; on error return [] (fault isolation)."""
        try:
            result = fn()
            return result if isinstance(result, list) else []
        except Exception:
            return []


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _first_env(names: Sequence[str]) -> str | None:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return None


def _extract_list(
    data: dict[str, Any], wrapper: str, item_key: str
) -> list[dict[str, Any]]:
    """Drill into Aliyun's nested list envelope: {wrapper: {item_key: [...]}}."""
    container = data.get(wrapper, {})
    if isinstance(container, dict):
        items = container.get(item_key, [])
    elif isinstance(container, list):
        items = container
    else:
        items = []
    return [i for i in items if isinstance(i, dict)]


def _extract_allowed_actions(policy_doc: str | None) -> set[str]:
    """Parse a policy document and return the set of allowed Action strings.

    Handles both ``"ram:AttachPolicyToUser"`` and ``["ram:*", "oss:*"]`` forms.
    ``"*"`` expands to ``"*"``. Statements with ``Effect != Allow`` are skipped.
    Returns empty set on parse failure (never raises).
    """
    if not policy_doc:
        return set()
    try:
        doc = json.loads(policy_doc)
    except (json.JSONDecodeError, TypeError):
        return set()

    actions: set[str] = set()
    for stmt in doc.get("Statement", []):
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        raw = stmt.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        if isinstance(raw, list):
            for a in raw:
                if isinstance(a, str):
                    actions.add(a.lower())
    return actions
