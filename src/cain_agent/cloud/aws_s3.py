"""AWS S3 exposure detection (read-only).

Given an access-key pair (constructor arguments or environment variables only)
and a region, this module enumerates the buckets the account can see and
checks each bucket's ACL, bucket-policy, and public-access-block configuration
for public exposure. Severity is assigned by **hardcoded rules** -- never by a
model. The module performs only GET-class operations.

Security contract
-----------------
* Credentials are read from constructor arguments, falling back to the
  ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` / ``AWS_DEFAULT_REGION``
  environment variables. They are never logged, never written to disk, and
  there is **no default or hardcoded key**.
* Recommended practice: provision an IAM user with a read-only policy
  (e.g. ``AmazonS3ReadOnlyAccess``) and pass its keys via environment
  variables or constructor arguments.
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
    "ACL_AUTHENTICATED_READ",
    "S3CredentialError",
    "S3ExposureChecker",
    "S3Finding",
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
    "authenticated_read": "info",
    "policy_public": "high",
}

# S3 canned ACL values (source: AWS S3 docs).
ACL_PUBLIC_READ_WRITE = "public-read-write"
ACL_PUBLIC_READ = "public-read"
ACL_AUTHENTICATED_READ = "authenticated-read"
ACL_PRIVATE = "private"

# Environment variable names consulted, in priority order.
_ENV_AK_ID = ("AWS_ACCESS_KEY_ID",)
_ENV_AK_SECRET = ("AWS_SECRET_ACCESS_KEY",)
_ENV_REGION = ("AWS_DEFAULT_REGION", "AWS_REGION")

_DEFAULT_REGION = "us-east-1"


@dataclass
class S3Finding:
    """Structured finding for a single S3 bucket exposure check."""

    bucket: str
    region: str | None = None
    exposure_level: str = "private"
    severity: str = "info"
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class S3CredentialError(RuntimeError):
    """Raised when no access-key pair is available from params or env."""


class S3ExposureChecker:
    """Read-only S3 bucket exposure checker.

    Keys come from ``access_key_id`` / ``access_key_secret`` or the
    ``AWS_*`` environment variables -- never from a default. ``region`` selects
    the service endpoint used to enumerate buckets.

    All boto3 construction goes through small methods (``_client``) which are
    the seams tests monkeypatch. No network call happens at construction time.
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
            raise S3CredentialError(
                "S3 凭证缺失: 请通过参数 access_key_id/access_key_secret 或环境变量 "
                f"{_ENV_AK_ID[0]}/{_ENV_AK_SECRET[0]} 提供只读 IAM 凭证"
            )
        self.region = region or _first_env(_ENV_REGION) or _DEFAULT_REGION
        self._client_cache: Any = None

    # -- boto3 client construction (mockable seam) ---------------------------
    def _client(self) -> Any:
        if self._client_cache is None:
            self._client_cache = boto3.client(
                "s3",
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.access_key_secret,
                region_name=self.region,
            )
        return self._client_cache

    # -- public API ----------------------------------------------------------
    def list_buckets(self) -> list[str]:
        """Return the names of all buckets visible to the supplied credentials."""
        resp = self._client().list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]

    def check_all(self) -> list[S3Finding]:
        """Check every visible bucket; a per-bucket failure never aborts the run."""
        return [self.check_bucket(name) for name in self.list_buckets()]

    def check_bucket(self, name: str) -> S3Finding:
        """Inspect one bucket's ACL + policy + public-access-block."""
        finding = S3Finding(bucket=name, region=self.region)
        try:
            grant = self._read_acl(name)
            statements = self._read_policy(name)
            pab = self._read_public_access_block(name)
            level, severity = _classify(grant, statements, pab)
            finding.exposure_level = level
            finding.severity = severity
            finding.evidence = _build_evidence(grant, statements, pab)
        except Exception as exc:
            finding.error = f"{type(exc).__name__}: {exc}"
        return finding

    # -- read helpers (each swallows errors for fault isolation) -------------
    def _read_acl(self, name: str) -> str | None:
        """Return the bucket's canned ACL grant, or None on error."""
        try:
            resp = self._client().get_bucket_acl(Bucket=name)
            grants = resp.get("Grants", [])
            return _s3_acl_from_grants(grants)
        except Exception:
            return None

    def _read_policy(self, name: str) -> list[dict[str, Any]]:
        """Return the bucket policy statements, or [] if none / unreadable."""
        try:
            resp = self._client().get_bucket_policy(Bucket=name)
            raw = resp.get("Policy", "")
        except Exception:
            return []
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
        stmts = parsed.get("Statement", []) if isinstance(parsed, dict) else []
        return [s for s in stmts if isinstance(s, dict)]

    def _read_public_access_block(self, name: str) -> dict[str, bool] | None:
        """Return the PublicAccessBlockConfiguration, or None if not set."""
        try:
            resp = self._client().get_public_access_block(Bucket=name)
            cfg = resp.get("PublicAccessBlockConfiguration", {})
            return {
                "block_public_acls": cfg.get("BlockPublicAcls", False),
                "ignore_public_acls": cfg.get("IgnorePublicAcls", False),
                "block_public_policy": cfg.get("BlockPublicPolicy", False),
                "restrict_public_buckets": cfg.get("RestrictPublicBuckets", False),
            }
        except Exception:
            return None


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


def _s3_acl_from_grants(grants: list[dict[str, Any]]) -> str:
    """Derive a canned-ACL equivalent from S3 ACL grant list.

    S3 returns individual grant entries rather than a canned ACL label.
    We look for AllUsers grantee to determine public exposure.
    """
    for g in grants:
        grantee = g.get("Grantee", {})
        uri = grantee.get("URI", "")
        permission = g.get("Permission", "")
        if uri == "http://acs.amazonaws.com/groups/global/AllUsers":
            if permission == "WRITE":
                return ACL_PUBLIC_READ_WRITE
            if permission == "READ":
                return ACL_PUBLIC_READ
    for g in grants:
        grantee = g.get("Grantee", {})
        uri = grantee.get("URI", "")
        if uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
            return ACL_AUTHENTICATED_READ
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
    return norm == "s3:*" or "put" in norm or "delete" in norm or "write" in norm


def _action_allows_read(action: Any) -> bool:
    norm = str(action).lower()
    return norm == "s3:*" or "get" in norm or "list" in norm or "read" in norm


def _classify_acl(grant: str | None) -> tuple[str, str]:
    """Map an ACL grant to (exposure_level, severity)."""
    if grant == ACL_PUBLIC_READ_WRITE:
        return "public_read_write", "critical"
    if grant == ACL_PUBLIC_READ:
        return "public_read", "high"
    if grant == ACL_AUTHENTICATED_READ:
        return "authenticated_read", "info"
    return "private", "info"


def _classify_policy(
    statements: list[dict[str, Any]],
    pab: dict[str, bool] | None,
) -> tuple[str, str]:
    """Map a policy to (exposure_level, severity).

    If ``BlockPublicPolicy`` is True in the public-access-block config,
    the policy is effectively blocked even if it contains public statements.
    """
    if pab and pab.get("block_public_policy"):
        return "private", "info"
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


def _classify_acl_with_pab(
    grant: str | None,
    pab: dict[str, bool] | None,
) -> tuple[str, str]:
    """Classify ACL, considering public-access-block overrides."""
    if pab and pab.get("block_public_acls") and pab.get("ignore_public_acls"):
        # Both ACL-blocking flags are on: public ACLs are effectively blocked.
        return "private", "info"
    return _classify_acl(grant)


def _classify(
    grant: str | None,
    statements: list[dict[str, Any]],
    pab: dict[str, bool] | None,
) -> tuple[str, str]:
    """Combine ACL + policy + PAB classifications, worst severity wins."""
    acl_level, acl_severity = _classify_acl_with_pab(grant, pab)
    pol_level, pol_severity = _classify_policy(statements, pab)
    if _SEVERITY_RANK[pol_severity] > _SEVERITY_RANK[acl_severity]:
        return pol_level, pol_severity
    return acl_level, acl_severity


def _build_evidence(
    grant: str | None,
    statements: list[dict[str, Any]],
    pab: dict[str, bool] | None,
) -> dict[str, Any]:
    """Record ACL grant, public policy statements, and PAB status."""
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
        "public_access_block": pab,
    }
