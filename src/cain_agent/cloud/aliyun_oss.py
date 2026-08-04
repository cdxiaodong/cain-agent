"""Aliyun OSS exposure detection (read-only).

Given an access-key pair (constructor arguments or environment variables only)
and a region, this module enumerates the buckets the account can see and
checks each bucket's ACL and bucket-policy for public exposure. Severity is
assigned by **hardcoded rules** -- never by a model. The module performs only
GET-class operations: it never writes, deletes, or mutates any resource.

Security contract
-----------------
* Credentials are read from constructor arguments, falling back to the
  ``ALIBABA_CLOUD_*`` / ``OSS_*`` environment variables. They are never logged,
  never written to disk, and there is **no default or hardcoded key**.
* Recommended practice: provision a RAM sub-account with a read-only policy
  (e.g. ``AliyunOSSReadOnlyAccess``) and pass its keys via environment
  variables or constructor arguments.
* All network access goes through the official ``oss2`` SDK and is fully
  mockable for tests. The test suite never touches the network and never uses
  real credentials.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import oss2

__all__ = [
    "ACL_PRIVATE",
    "ACL_PUBLIC_READ",
    "ACL_PUBLIC_READ_WRITE",
    "OssCredentialError",
    "OssExposureChecker",
    "OssFinding",
    "SEVERITY_BY_EXPOSURE",
]

# --------------------------------------------------------------------------- #
# Severity rules (hardcoded constants, not model output).
# --------------------------------------------------------------------------- #

_SEVERITY_RANK: dict[str, int] = {"info": 0, "high": 1, "critical": 2}

# Base severity per exposure level. ``policy_public`` is upgraded to critical
# at classify-time when the matched policy grants write actions.
SEVERITY_BY_EXPOSURE: dict[str, str] = {
    "private": "info",
    "public_read": "high",
    "public_read_write": "critical",
    "policy_public": "high",
}

# OSS ACL grant values (source: Aliyun OSS docs).
ACL_PUBLIC_READ_WRITE = "public-read-write"
ACL_PUBLIC_READ = "public-read"
ACL_PRIVATE = "private"

# Environment variable names consulted, in priority order. Parameters always win.
_ENV_AK_ID = ("ALIBABA_CLOUD_ACCESS_KEY_ID", "OSS_ACCESS_KEY_ID")
_ENV_AK_SECRET = ("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "OSS_ACCESS_KEY_SECRET")
_ENV_REGION = ("ALIBABA_CLOUD_REGION", "OSS_REGION")

_DEFAULT_REGION = "oss-cn-hangzhou"
_ENDPOINT_TEMPLATE = "https://{region}.aliyuncs.com"


@dataclass
class OssFinding:
    """Structured finding for a single OSS bucket exposure check.

    ``evidence`` records only non-sensitive signals: the ACL grant string and,
    for each exposing policy statement, its Sid, Effect, and a read/write
    boolean pair that justifies the severity. No bucket object contents, no
    credentials, no secrets are ever placed in a finding.
    """

    bucket: str
    region: str | None = None
    exposure_level: str = "private"
    severity: str = "info"
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class OssCredentialError(RuntimeError):
    """Raised when no access-key pair is available from params or env."""


class OssExposureChecker:
    """Read-only OSS bucket exposure checker.

    Keys come from ``access_key_id`` / ``access_key_secret`` or the
    ``ALIBABA_CLOUD_*`` / ``OSS_*`` environment variables -- never from a
    default. ``region`` selects the service endpoint used to enumerate buckets;
    each bucket's own ``location`` is resolved dynamically so per-bucket
    ACL/policy calls land on the correct regional endpoint.

    All oss2 construction goes through small methods (``auth``, ``_service``,
    ``_bucket``) which are the seams tests monkeypatch. No network call happens
    at construction time.
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
            raise OssCredentialError(
                "OSS 凭证缺失: 请通过参数 access_key_id/access_key_secret 或环境变量 "
                f"{_ENV_AK_ID[0]}/{_ENV_AK_SECRET[0]} 提供只读 RAM 子账号凭证"
            )
        self.region = region or _first_env(_ENV_REGION) or _DEFAULT_REGION
        self._auth: Any = None

    # -- oss2 client construction (mockable seams) ---------------------------
    @property
    def auth(self) -> Any:
        if self._auth is None:
            self._auth = oss2.Auth(self.access_key_id, self.access_key_secret)
        return self._auth

    def _endpoint(self, region: str | None = None) -> str:
        return _ENDPOINT_TEMPLATE.format(region=region or self.region)

    def _service(self) -> Any:
        return oss2.Service(self.auth, self._endpoint())

    def _bucket(self, name: str, region: str | None = None) -> Any:
        return oss2.Bucket(self.auth, self._endpoint(region), name)

    # -- public API ----------------------------------------------------------
    def list_buckets(self) -> list[str]:
        """Return the names of all buckets visible to the supplied credentials."""
        return [b.name for b in oss2.BucketIterator(self._service())]

    def check_all(self) -> list[OssFinding]:
        """Check every visible bucket; a per-bucket failure never aborts the run."""
        return [self.check_bucket(name) for name in self.list_buckets()]

    def check_bucket(self, name: str) -> OssFinding:
        """Inspect one bucket's ACL + policy and return a structured finding."""
        finding = OssFinding(bucket=name)
        try:
            region = self._resolve_region(name)
            finding.region = region
            bucket = self._bucket(name, region)
            grant = bucket.get_bucket_acl().acl
            statements = self._read_policy(bucket)
            level, severity = _classify(grant, statements)
            finding.exposure_level = level
            finding.severity = severity
            finding.evidence = _build_evidence(grant, statements)
        except Exception as exc:  # per-bucket isolation: record and continue
            finding.error = f"{type(exc).__name__}: {exc}"
        return finding

    # -- helpers -------------------------------------------------------------
    def _resolve_region(self, name: str) -> str:
        """Best-effort region lookup from the bucket's own location."""
        try:
            location = self._bucket(name).get_bucket_info().location
        except Exception:
            return self.region
        return location or self.region

    def _read_policy(self, bucket: Any) -> list[dict[str, Any]]:
        """Return the bucket policy statements, or [] if none / unreadable."""
        try:
            raw = bucket.get_bucket_policy().policy
        except Exception:  # no policy, access denied, or transient error
            return []
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
        stmts = parsed.get("Statement", []) if isinstance(parsed, dict) else []
        return [s for s in stmts if isinstance(s, dict)]


# --------------------------------------------------------------------------- #
# Policy analysis helpers (pure functions, fully unit-testable).
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


def _principal_is_public(principal: Any) -> bool:
    """A Principal is public when it is ``"*"`` or lists/contains ``"*"``.

    Handles the shapes Aliyun policies use: bare ``"*"``, ``["*"]``, and
    service-keyed maps such as ``{"RAM": ["*"]}``.
    """
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
    return norm == "oss:*" or "put" in norm or "delete" in norm or "write" in norm


def _action_allows_read(action: Any) -> bool:
    norm = str(action).lower()
    return norm == "oss:*" or "get" in norm or "list" in norm or "read" in norm


def _classify_acl(grant: str | None) -> tuple[str, str]:
    """Map an ACL grant to (exposure_level, severity)."""
    if grant == ACL_PUBLIC_READ_WRITE:
        return "public_read_write", "critical"
    if grant == ACL_PUBLIC_READ:
        return "public_read", "high"
    return "private", "info"


def _classify_policy(statements: list[dict[str, Any]]) -> tuple[str, str]:
    """Map a policy to (exposure_level, severity).

    Only statements that are simultaneously ``Effect: Allow`` *and* carry a
    public (``"*"``) principal count as exposing -- a ``Deny`` principal of
    ``"*"`` is a guardrail, not an exposure.
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
    # Public principal but no recognisable action: exposed, conservatively high.
    return "policy_public", "high"


def _classify(grant: str | None, statements: list[dict[str, Any]]) -> tuple[str, str]:
    """Combine ACL and policy classifications, taking the worse severity."""
    acl_level, acl_severity = _classify_acl(grant)
    pol_level, pol_severity = _classify_policy(statements)
    if _SEVERITY_RANK[pol_severity] > _SEVERITY_RANK[acl_severity]:
        return pol_level, pol_severity
    return acl_level, acl_severity


def _build_evidence(grant: str | None, statements: list[dict[str, Any]]) -> dict[str, Any]:
    """Record only ACL grant + per-statement Sid/Effect/read-write flags."""
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
    return {"acl": grant, "public_policy_statements": public}
