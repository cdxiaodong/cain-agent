"""Huawei Cloud OBS exposure detection (read-only).

Given an access-key pair (constructor arguments or environment variables only)
and a region, this module enumerates the buckets the account can see and
checks each bucket's ACL and bucket-policy for public exposure. Severity is
assigned by **hardcoded rules** -- never by a model. The module performs only
GET-class operations.

Huawei OBS is S3-API-compatible, so this module reuses the official ``boto3``
SDK with a custom ``endpoint_url``. The signing, request format, and response
schema are identical to S3's, which lets us share classification logic with
the AWS S3 module.

Security contract
-----------------
* Credentials are read from constructor arguments, falling back to the
  ``HUAWEICLOUD_ACCESS_KEY_ID`` / ``HUAWEICLOUD_SECRET_ACCESS_KEY`` /
  ``HUAWEICLOUD_REGION`` environment variables. They are never logged, never
  written to disk, and there is **no default or hardcoded key**.
* Recommended practice: provision an IAM user with a read-only policy and pass
  its keys via environment variables or constructor arguments.
* All network access goes through the official ``boto3`` SDK and is fully
  mockable for tests. The test suite never touches the network and never uses
  real credentials.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import boto3

__all__ = [
    "ACL_PRIVATE",
    "ACL_PUBLIC_READ",
    "ACL_PUBLIC_READ_WRITE",
    "ObsCredentialError",
    "ObsExposureChecker",
    "ObsFinding",
    "SEVERITY_BY_EXPOSURE",
]

# --------------------------------------------------------------------------- #
# Severity rules (hardcoded constants, not model output).
# --------------------------------------------------------------------------- #

_SEVERITY_RANK: dict[str, int] = {"info": 0, "high": 1, "critical": 2}

SEVERITY_BY_EXPOSURE: dict[str, str] = {
    "private": "info",
    "public_read": "high",
    "public_read_write": "critical",
    "policy_public": "high",
}

# S3-compatible canned ACL values (OBS accepts these in S3-compat mode).
ACL_PUBLIC_READ_WRITE = "public-read-write"
ACL_PUBLIC_READ = "public-read"
ACL_PRIVATE = "private"

# Environment variable names consulted, in priority order.
_ENV_AK_ID = ("HUAWEICLOUD_ACCESS_KEY_ID", "OBS_ACCESS_KEY_ID")
_ENV_AK_SECRET = ("HUAWEICLOUD_SECRET_ACCESS_KEY", "OBS_SECRET_ACCESS_KEY")
_ENV_REGION = ("HUAWEICLOUD_REGION", "OBS_REGION")

_DEFAULT_REGION = "cn-north-4"


@dataclass
class ObsFinding:
    """Structured finding for a single OBS bucket exposure check."""

    bucket: str
    region: str | None = None
    exposure_level: str = "private"
    severity: str = "info"
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class ObsCredentialError(RuntimeError):
    """Raised when no access-key pair is available from params or env."""


class ObsExposureChecker:
    """Read-only Huawei OBS bucket exposure checker.

    Keys come from ``access_key_id`` / ``access_key_secret`` or the
    ``HUAWEICLOUD_*`` / ``OBS_*`` environment variables -- never from a
    default. ``region`` selects the OBS endpoint used to enumerate buckets.

    All boto3 construction goes through ``_client``, the seam tests
    monkeypatch. No network call happens at construction time.
    """

    def __init__(
        self,
        access_key_id: str | None = None,
        access_key_secret: str | None = None,
        region: str | None = None,
    ) -> None:
        self.access_key_id = access_key_id or _first_env(_ENV_AK_ID)
        self.access_key_secret = access_key_secret or _first_env(_ENV_AK_SECRET)
        if not self.access_key_id or not self.access_key_secret:
            raise ObsCredentialError(
                "OBS 凭证缺失: 请通过参数 access_key_id/access_key_secret 或环境变量 "
                f"{_ENV_AK_ID[0]}/{_ENV_AK_SECRET[0]} 提供只读 IAM 凭证"
            )
        self.region = region or _first_env(_ENV_REGION) or _DEFAULT_REGION
        self._client_cache: Any = None

    # -- boto3 client construction (mockable seam) ---------------------------
    def _client(self) -> Any:
        """Build a boto3 S3-compatible client pointed at the OBS endpoint."""
        if self._client_cache is None:
            endpoint = f"https://obs.{self.region}.myhuaweicloud.com"
            self._client_cache = boto3.client(
                "s3",
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.access_key_secret,
                region_name=self.region,
                endpoint_url=endpoint,
            )
        return self._client_cache

    # -- public API ----------------------------------------------------------
    def list_buckets(self) -> list[str]:
        """Return the names of all buckets visible to the supplied credentials."""
        resp = self._client().list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]

    def check_all(self) -> list[ObsFinding]:
        """Check every visible bucket; a per-bucket failure never aborts the run."""
        return [self.check_bucket(name) for name in self.list_buckets()]

    def check_bucket(self, name: str) -> ObsFinding:
        """Inspect one bucket's ACL + policy and return a finding."""
        finding = ObsFinding(bucket=name, region=self.region)
        try:
            grant = self._read_acl(name)
            statements = self._read_policy(name)
            level, severity = _classify(grant, statements)
            finding.exposure_level = level
            finding.severity = severity
            finding.evidence = _build_evidence(grant, statements)
        except Exception as exc:
            finding.error = f"{type(exc).__name__}: {exc}"
        return finding

    # -- read helpers (each swallows errors for fault isolation) -------------
    def _read_acl(self, name: str) -> str | None:
        """Return the bucket's canned ACL grant, or None on error."""
        try:
            resp = self._client().get_bucket_acl(Bucket=name)
            grants = resp.get("Grants", [])
            return _obs_acl_from_grants(grants)
        except Exception:
            return None

    def _read_policy(self, name: str) -> list[dict[str, Any]]:
        """Return the bucket policy statements, or [] if none / unreadable."""
        try:
            resp = self._client().get_bucket_policy(Bucket=name)
            raw = resp.get("Policy", "")
        except Exception:
            return []
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8")
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
        stmts = parsed.get("Statement", []) if isinstance(parsed, dict) else []
        return [s for s in stmts if isinstance(s, dict)]


# --------------------------------------------------------------------------- #
# Classification helpers (pure functions, fully unit-testable).
# --------------------------------------------------------------------------- #


def _first_env(names: Sequence[str]) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _obs_acl_from_grants(grants: list[dict[str, Any]]) -> str:
    """Derive a canned-ACL equivalent from OBS/S3 ACL grant list.

    OBS returns individual grant entries in S3-compatible format. We look for
    AllUsers grantee to determine public exposure.
    """
    for g in grants:
        grantee = g.get("Grantee", {})
        uri = grantee.get("URI", "")
        permission = g.get("Permission", "")
        # OBS S3-compat uses the same AllUsers URI as AWS.
        if uri == "http://acs.amazonaws.com/groups/global/AllUsers":
            if permission == "WRITE":
                return ACL_PUBLIC_READ_WRITE
            if permission == "READ":
                return ACL_PUBLIC_READ
            if permission == "FULL_CONTROL":
                return ACL_PUBLIC_READ_WRITE
    return ACL_PRIVATE


def _principal_is_public(principal: Any) -> bool:
    """A Principal is public when it is ``"*"`` or lists/contains ``"*"``."""
    if principal is None:
        return False
    if isinstance(principal, str):
        return principal == "*"
    for entry in _as_list(principal):
        if entry == "*":
            return True
        if isinstance(entry, dict):
            for sub in entry.values():
                if "*" in _as_list(sub):
                    return True
    return False


def _action_allows_write(action: Any) -> bool:
    norm = str(action).lower()
    return norm == "obs:*" or norm == "s3:*" or norm == "*" or any(
        k in norm for k in ("put", "delete", "write", "post")
    )


def _action_allows_read(action: Any) -> bool:
    norm = str(action).lower()
    return norm == "obs:*" or norm == "s3:*" or norm == "*" or any(
        k in norm for k in ("get", "list", "read", "head")
    )


def _classify_acl(grant: str | None) -> tuple[str, str]:
    """Map an ACL grant to (exposure_level, severity)."""
    if grant == ACL_PUBLIC_READ_WRITE:
        return "public_read_write", "critical"
    if grant == ACL_PUBLIC_READ:
        return "public_read", "high"
    return "private", "info"


def _classify_policy(
    statements: list[dict[str, Any]],
) -> tuple[str, str]:
    """Map a policy to (exposure_level, severity).

    Only statements that are simultaneously ``Effect: Allow`` *and* carry a
    public principal count as exposing.
    """
    exposing = [
        s
        for s in statements
        if str(s.get("Effect", "")).lower() == "allow"
        and _principal_is_public(s.get("Principal"))
    ]
    if not exposing:
        return "private", "info"
    actions = [a for s in exposing for a in _as_list(s.get("Action"))]
    write = any(_action_allows_write(a) for a in actions)
    read = any(_action_allows_read(a) for a in actions)
    if write:
        return "policy_public", "critical"
    if read:
        return "policy_public", "high"
    return "policy_public", "high"


def _classify(
    grant: str | None,
    statements: list[dict[str, Any]],
) -> tuple[str, str]:
    """Combine ACL + policy classifications, worst severity wins."""
    acl_level, acl_severity = _classify_acl(grant)
    pol_level, pol_severity = _classify_policy(statements)
    if _SEVERITY_RANK[pol_severity] > _SEVERITY_RANK[acl_severity]:
        return pol_level, pol_severity
    return acl_level, acl_severity


def _build_evidence(
    grant: str | None,
    statements: list[dict[str, Any]],
) -> dict[str, Any]:
    """Record ACL grant and public policy statements (no credentials)."""
    public: list[dict[str, Any]] = []
    for statement in statements:
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        if not _principal_is_public(statement.get("Principal")):
            continue
        actions = _as_list(statement.get("Action"))
        public.append(
            {
                "sid": statement.get("Sid"),
                "effect": statement.get("Effect"),
                "principal_star": True,
                "read": any(_action_allows_read(a) for a in actions),
                "write": any(_action_allows_write(a) for a in actions),
            }
        )
    return {
        "acl": grant,
        "public_policy_statements": public,
    }
