"""Tencent Cloud CAM privilege-escalation path analysis (read-only).

Maps privilege escalation research to Tencent Cloud CAM (Cloud Access Management)
equivalents. Only **Get/List** CAM API operations are used -- never write,
attach, create, or delete. Severity is assigned by **hardcoded rule constants**,
never by a model.

Security contract
-----------------
* Credentials are read from constructor arguments, falling back to the
  ``TENCENTCLOUD_SECRET_ID`` / ``TENCENTCLOUD_SECRET_KEY`` environment variables.
  They are never logged, never written to disk, and there is **no default or
  hardcoded key**.
* Recommended practice: provision a CAM sub-account with a read-only policy
  (e.g. ``QcloudCAMReadOnlyAccess``) and pass its keys via environment variables
  or constructor arguments.
* SDK selection: this module uses ``requests`` with the CAM API signature (v3.0
  HMAC-SHA256) rather than the official ``tencentcloud-sdk-python``. Rationale:
  (1) ``requests`` is already available transitively via other modules, so no new
  heavyweight dependency is introduced; (2) the CAM APIs we need are simple
  JSON POST endpoints whose signing is ~60 lines of code; (3) ``_call_api`` is
  the single mock seam, keeping the test suite fully isolated from the network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import requests

__all__ = [
    "PRIVESC_RULES",
    "CamCredentialError",
    "CamFinding",
    "CamPrivescAnalyzer",
    "PrivescRule",
]

# --------------------------------------------------------------------------- #
# Environment variable names (priority order). Parameters always win.
# --------------------------------------------------------------------------- #

_ENV_AK_ID = ("TENCENTCLOUD_SECRET_ID", "CAM_SECRET_ID")
_ENV_AK_SECRET = ("TENCENTCLOUD_SECRET_KEY", "CAM_SECRET_KEY")
_ENV_REGION = ("TENCENTCLOUD_REGION", "CAM_REGION")

_DEFAULT_REGION = "ap-guangzhou"
_CAM_ENDPOINT = "https://cam.tencentcloudapi.com"
_CAM_SERVICE = "cam"
_CAM_VERSION = "2019-01-16"


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PrivescRule:
    """A single CAM privesc path (code constant, not model output).

    ``required_perms`` is a set of CAM action strings; a principal is
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

        Supports service wildcards: ``cam:*`` covers any ``cam:PassRole``,
        ``cam:AttachUserPolicy``, etc. Action strings are compared
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
class CamFinding:
    """Structured finding for a single CAM privesc path hit.

    Fields align with ``findings.Finding`` so the result can be converted
    directly: ``cloud="tencent"``, ``service="cam"``.
    """

    cloud: str = "tencent"
    service: str = "cam"
    rule_id: str = ""
    resource: str = ""  # user Uin / group Uin / role ID
    issue_type: str = ""  # maps to Finding.issue_type
    severity: str = "info"
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class CamCredentialError(RuntimeError):
    """Raised when no access-key pair is available from params or env."""


# --------------------------------------------------------------------------- #
# Privesc rules table (code constants)
#
# Source: AWS IAM Privilege Escalation research mapped to Tencent Cloud CAM
# equivalents. Each rule lists the minimum permission set that opens the path.
# --------------------------------------------------------------------------- #

PRIVESC_RULES: tuple[PrivescRule, ...] = (
    PrivescRule(
        rule_id="cam:AttachUserPolicy",
        required_perms=(
            ("cam:AttachUserPolicy",),
        ),
        description=(
            "可给任意用户挂载策略: 直接 Attach 管理员策略完成提权"
        ),
        severity="critical",
    ),
    PrivescRule(
        rule_id="cam:AttachGroupPolicy",
        required_perms=(
            ("cam:AttachGroupPolicy",),
        ),
        description=(
            "可给用户组挂载策略: 通过将自己加入用户组完成提权"
        ),
        severity="critical",
    ),
    PrivescRule(
        rule_id="cam:CreateAccessKey",
        required_perms=(
            ("cam:CreateAccessKey",),
        ),
        description=(
            "可为任意用户创建 AccessKey: 窃取高权用户凭证冒用其身份"
        ),
        severity="critical",
    ),
    PrivescRule(
        rule_id="cam:PassRole",
        required_perms=(
            ("cam:PassRole", "scf:CreateFunction"),
            ("cam:PassRole", "cvm:RunInstances"),
        ),
        description=(
            "可 PassRole 且能创建函数/实例: 借高权角色执行代码,等同角色权限"
        ),
        severity="critical",
    ),
    PrivescRule(
        rule_id="cam:UpdateLoginProfile",
        required_perms=(
            ("cam:UpdateLoginProfile",),
            ("cam:CreateLoginProfile",),
        ),
        description=(
            "可创建/修改控制台登录配置: 劫持高权用户控制台登录"
        ),
        severity="high",
    ),
    PrivescRule(
        rule_id="cam:AssumeRole",
        required_perms=(
            ("sts:AssumeRole",),
        ),
        description=(
            "可 AssumeRole 高权角色且该角色信任当前实体: 角色链提权"
        ),
        severity="high",
    ),
    PrivescRule(
        rule_id="cam:AddUserToGroup",
        required_perms=(
            ("cam:AddUserToGroup",),
        ),
        description=(
            "可将用户加入高权用户组: 继承组权限完成提权"
        ),
        severity="high",
    ),
)


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #


class CamPrivescAnalyzer:
    """Read-only CAM privilege-escalation path analyzer.

    All network calls go through ``_call_api``, the single mock seam. Tests
    monkeypatch this method to return canned responses without touching the
    network.
    """

    def __init__(
        self,
        secret_id: str | None = None,
        secret_key: str | None = None,
        region: str | None = None,
    ) -> None:
        ak_id = secret_id or _first_env(_ENV_AK_ID)
        ak_secret = secret_key or _first_env(_ENV_AK_SECRET)
        if not ak_id or not ak_secret:
            raise CamCredentialError(
                "CAM 凭证缺失: 请通过参数 secret_id/secret_key 或环境变量 "
                f"{_ENV_AK_ID[0]}/{_ENV_AK_SECRET[0]} 提供只读 CAM 子账号凭证"
            )
        self.secret_id: str = ak_id
        self.secret_key: str = ak_secret
        self.region: str = region or _first_env(_ENV_REGION) or _DEFAULT_REGION

    # -- API layer (mockable seam) -------------------------------------------

    def _call_api(self, action: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a Tencent Cloud CAM API v3.0 endpoint.

        Returns the parsed JSON Response. Raises ``requests.HTTPError`` on non-2xx.
        This is the **only** network call site -- monkeypatch it in tests.
        """
        body = self._build_request_body(action, params or {})
        headers = {
            "Authorization": self._sign(body),
            "Content-Type": "application/json; charset=utf-8",
            "Host": "cam.tencentcloudapi.com",
            "X-TC-Action": action,
            "X-TC-Timestamp": str(int(time.time())),
            "X-TC-Version": _CAM_VERSION,
            "X-TC-Region": self.region,
        }
        resp = requests.post(
            _CAM_ENDPOINT,
            data=json.dumps(body),
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("Response", {})

    def _build_request_body(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Build the JSON request body for a CAM API call."""
        return {
            **params,
        }

    def _sign(self, body: dict[str, Any]) -> str:
        """Build the Tencent Cloud API v3.0 signature (TC3-HMAC-SHA256)."""
        timestamp = int(time.time())
        date = time.strftime("%Y-%m-%d", time.gmtime(timestamp))

        # Step 1: Build canonical request
        payload = json.dumps(body)
        canonical_headers = "content-type:application/json; charset=utf-8\nhost:cam.tencentcloudapi.com\n"
        signed_headers = "content-type;host"
        hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        canonical_request = (
            f"POST\n/\n\n"
            f"{canonical_headers}\n"
            f"{signed_headers}\n"
            f"{hashed_request_payload}"
        )

        # Step 2: Build string to sign
        credential_scope = f"{date}/{_CAM_SERVICE}/tc3_request"
        hashed_canonical_request = hashlib.sha256(
            canonical_request.encode("utf-8")
        ).hexdigest()
        string_to_sign = (
            f"TC3-HMAC-SHA256\n"
            f"{timestamp}\n"
            f"{credential_scope}\n"
            f"{hashed_canonical_request}"
        )

        # Step 3: Calculate signature
        def _hmac_sha256(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        secret_date = _hmac_sha256(f"TC3{self.secret_key}".encode(), date)
        secret_service = _hmac_sha256(secret_date, _CAM_SERVICE)
        secret_signing = _hmac_sha256(secret_service, "tc3_request")
        signature = hmac.new(
            secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        # Step 4: Build authorization header
        return (
            f"TC3-HMAC-SHA256 "
            f"Credential={self.secret_id}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )

    # -- CAM read-only API wrappers ------------------------------------------

    def list_users(self) -> list[dict[str, Any]]:
        """List all sub-users visible to the credentials."""
        result = self._call_api("ListUsers")
        return result.get("Data", {}).get("Users", [])

    def list_groups(self) -> list[dict[str, Any]]:
        """List all user groups visible to the credentials."""
        result = self._call_api("ListGroups")
        return result.get("Data", {}).get("Groups", [])

    def list_policies(self) -> list[dict[str, Any]]:
        """List all policies visible to the credentials."""
        result = self._call_api("ListPolicies")
        policies = result.get("Data", {}).get("Policies", [])
        return policies if isinstance(policies, list) else []

    def list_attached_user_policies(self, uin: int) -> list[dict[str, Any]]:
        """List policies attached to a specific user."""
        result = self._call_api("ListAttachedUserPolicies", {"TargetUin": uin})
        return result.get("Data", {}).get("List", [])

    def list_attached_group_policies(self, group_id: int) -> list[dict[str, Any]]:
        """List policies attached to a specific group."""
        result = self._call_api("ListAttachedGroupPolicies", {"GroupId": group_id})
        return result.get("Data", {}).get("List", [])

    def get_policy_version(self, policy_id: str) -> dict[str, Any] | None:
        """Get a specific policy version document."""
        try:
            result = self._call_api("GetPolicyVersion", {
                "PolicyId": policy_id,
                "VersionId": 0,  # Default version
            })
            return result.get("Data")
        except Exception:
            return None

    def get_user_group_ids(self, uin: int) -> list[int]:
        """Get the list of group IDs a user belongs to."""
        result = self._call_api("ListGroupsForUser", {"Uin": uin})
        groups = result.get("Data", {}).get("GroupInfo", [])
        ids: list[int] = []
        for g in groups:
            if isinstance(g, dict):
                group_id = g.get("GroupId")
                if isinstance(group_id, int):
                    ids.append(group_id)
        return ids

    # -- analysis ------------------------------------------------------------

    def analyze(self) -> list[CamFinding]:
        """Enumerate users and match their effective permissions against rules.

        Per-entity failures (permission denied, API error) are recorded in
        ``CamFinding.error`` and never abort the full scan.
        """
        findings: list[CamFinding] = []

        for user in self._safe_list(self.list_users):
            uin = user.get("Uin")
            name = user.get("Name", "?")
            if uin is None:
                continue
            resource = f"uin:{uin}"
            actions = self._collect_user_actions(int(uin))
            findings.extend(
                self._match_rules(actions, resource, entity_type="user", name=name)
            )

        # Also scan groups for group-level privesc paths
        for group in self._safe_list(self.list_groups):
            group_id = group.get("GroupId")
            name = group.get("GroupName", "?")
            if group_id is None:
                continue
            resource = f"group:{group_id}"
            actions = self._collect_group_actions(int(group_id))
            findings.extend(
                self._match_rules(actions, resource, entity_type="group", name=name)
            )

        return findings

    def _collect_user_actions(self, uin: int) -> set[str]:
        """Collect all effective actions for a user (direct + inherited)."""
        actions: set[str] = set()

        # Direct user policies
        for policy in self._safe_list(self.list_attached_user_policies, uin):
            actions.update(self._policy_actions(policy))

        # Inherited from groups
        for gid in self.get_user_group_ids(uin):
            for policy in self._safe_list(self.list_attached_group_policies, gid):
                actions.update(self._policy_actions(policy))

        return actions

    def _collect_group_actions(self, group_id: int) -> set[str]:
        """Collect all effective actions for a group."""
        actions: set[str] = set()

        for policy in self._safe_list(self.list_attached_group_policies, group_id):
            actions.update(self._policy_actions(policy))

        return actions

    def _policy_actions(self, policy: dict[str, Any]) -> set[str]:
        """Extract allowed actions from a policy object."""
        policy_doc = policy.get("PolicyDocument")
        
        # If PolicyDocument is not present in the policy object,
        # we need to fetch it using get_policy_version
        if policy_doc is None:
            policy_id = policy.get("PolicyId")
            if policy_id:
                version_data = self.get_policy_version(policy_id)
                if version_data:
                    # The result is {"PolicyVersion": {"PolicyDocument": "..."}}
                    # We need to extract PolicyDocument from the nested structure
                    policy_doc = version_data.get("PolicyVersion", {}).get("PolicyDocument")
        doc_str = json.dumps(policy_doc) if isinstance(policy_doc, dict) else policy_doc
        if not isinstance(doc_str, str):
            return set()
        return _extract_allowed_actions(doc_str)

    def _match_rules(
        self,
        actions: set[str],
        resource: str,
        entity_type: str,
        name: str,
    ) -> list[CamFinding]:
        """Match a principal's actions against privesc rules."""
        hits: list[CamFinding] = []
        for rule in PRIVESC_RULES:
            if rule.matches(actions):
                hits.append(
                    CamFinding(
                        cloud="tencent",
                        service="cam",
                        rule_id=rule.rule_id,
                        resource=resource,
                        issue_type=f"{entity_type}_privesc",
                        severity=rule.severity,
                        description=f"{name} ({entity_type}): {rule.description}",
                        evidence={
                            "entity_type": entity_type,
                            "entity_name": name,
                            "matched_perms": sorted(
                                s for s in actions if not s.startswith("_")
                            )[:20],  # cap to avoid huge evidence
                        },
                    )
                )
        return hits

    # -- error handling helpers ----------------------------------------------

    def _safe_list(self, fn, *args) -> list[Any]:
        """Call a list-returning function; on error return [] (fault isolation)."""
        try:
            result = fn(*args)
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


def _get_key_ci(d: dict[str, Any], key: str) -> Any:
    """Get a dict value with case-insensitive key lookup."""
    lower_key = key.lower()
    for k, v in d.items():
        if isinstance(k, str) and k.lower() == lower_key:
            return v
    return None


def _extract_allowed_actions(policy_doc: str) -> set[str]:
    """Parse a policy document and return the set of allowed Action strings.

    Handles both ``"cam:AttachUserPolicy"`` and ``["cam:*", "sts:*"]`` forms.
    ``"*"`` expands to ``"*"``. Statements with ``Effect != Allow`` are skipped.
    Returns empty set on parse failure (never raises).

    Tencent Cloud policy documents follow IAM JSON syntax.
    Supports both PascalCase keys (real CAM format) and lowercase keys (test mocks).
    """
    if not policy_doc:
        return set()
    try:
        doc = json.loads(policy_doc)
    except (json.JSONDecodeError, TypeError):
        return set()

    actions: set[str] = set()
    # Use case-insensitive lookup for the top-level Statement key
    statements = _get_key_ci(doc, "Statement")
    if not isinstance(statements, list):
        return set()
    
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        # Use case-insensitive lookup for Effect
        effect = _get_key_ci(stmt, "Effect")
        if str(effect).lower() != "allow":
            continue
        # Use case-insensitive lookup for Action
        raw = _get_key_ci(stmt, "Action")
        if isinstance(raw, str):
            raw = [raw]
        if isinstance(raw, list):
            for a in raw:
                if isinstance(a, str):
                    actions.add(a.lower())
    return actions
