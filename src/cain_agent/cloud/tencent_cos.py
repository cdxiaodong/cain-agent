"""Tencent Cloud COS exposure detection (read-only).

Given an access-key pair (constructor arguments or environment variables only)
and a region, this module enumerates the buckets the account can see, checks
each bucket's ACL and bucket-policy for public exposure, and scans object
listings for sensitive file name patterns (``.env`` / ``.key`` / ``.pem``
...). Severity is assigned by **hardcoded rules** -- never by a model. The
module performs only **GET/HEAD-class** operations: it never writes, deletes,
or mutates any resource.

Security contract
-----------------
* Credentials are read from constructor arguments, falling back to the
  ``TENCENTCLOUD_SECRET_ID`` / ``TENCENTCLOUD_SECRET_KEY`` environment
  variables. They are never logged, never written to disk, and there is
  **no default or hardcoded key**.
* Recommended practice: provision a CAM sub-account with a read-only policy
  (e.g. ``QcloudCOSReadOnlyAccess``) and pass its keys via environment
  variables or constructor arguments.
* SDK selection: this module uses ``requests`` with the COS XML-API signature
  (HMAC-SHA1 ``Authorization`` header, the scheme Tencent COS documents for
  its bucket/object REST endpoints) rather than the heavyweight ``cos-python-sdk``.
  Rationale: (1) ``requests`` is already a direct dependency, so no new SDK is
  introduced; (2) the read-only COS XML endpoints we need (GetService /
  GetBucket / GetBucketAcl / GetBucketPolicy) are simple GETs whose signing is
  a few dozen lines; (3) ``_request`` is the single mock seam, keeping the test
  suite fully isolated from the network and from real credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import requests

__all__ = [
    "CosCredentialError",
    "CosExposureChecker",
    "CosFinding",
    "SENSITIVE_FILE_PATTERNS",
    "SEVERITY_BY_EXPOSURE",
]

# --------------------------------------------------------------------------- #
# Severity rules (hardcoded constants, not model output).
# --------------------------------------------------------------------------- #

_SEVERITY_RANK: dict[str, int] = {"info": 0, "high": 1, "critical": 2}

# Base severity per exposure level. ``policy_public`` is upgraded to critical
# at classify-time when the matched policy grants write actions; any exposure
# that coincides with sensitive files is upgraded to critical.
SEVERITY_BY_EXPOSURE: dict[str, str] = {
    "private": "info",
    "public_read": "high",
    "public_read_write": "critical",
    "policy_public": "high",
}

# COS ACL shorthand for "anyone" (anonymous) grants. A Grant URI containing
# this value means the grant applies to the general public.
_COS_ALL_USERS_URI = "http://cam.qcloud.com/groups/global/AllUsers"

# Environment variable names consulted, in priority order. Parameters always win.
_ENV_AK_ID = ("TENCENTCLOUD_SECRET_ID", "COS_SECRET_ID")
_ENV_AK_SECRET = ("TENCENTCLOUD_SECRET_KEY", "COS_SECRET_KEY")
_ENV_REGION = ("TENCENTCLOUD_REGION", "COS_REGION")

_DEFAULT_REGION = "ap-guangzhou"
_SERVICE_HOST = "service.cos.myqcloud.com"

# Sensitive file name patterns (lower-case match against the object key's
# basename + suffix). Aligned with the cloud exposure-detection convention of
# flagging leaked secrets/config material.
SENSITIVE_FILE_PATTERNS: tuple[str, ...] = (
    ".env",
    ".git/",
    ".svn/",
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".jks",
    ".kdbx",
    ".sql",
    ".bak",
    ".backup",
    ".dump",
    "id_rsa",
    "id_dsa",
    "id_ed25519",
    "credentials",
    "secrets",
    "shadow",
    ".htpasswd",
    "web.config",
    "wp-config.php",
)


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #


@dataclass
class CosFinding:
    """Structured finding for a single COS bucket exposure check.

    ``evidence`` records only non-sensitive signals: the ACL public-permission
    list, per-statement public-policy flags, and the (truncated) list of
    sensitive object keys matched. No object contents, no credentials, no
    secrets are ever placed in a finding.
    """

    cloud: str = "tencent"
    service: str = "cos"
    resource: str = ""  # bucket name
    region: str | None = None
    exposure_level: str = "private"
    severity: str = "info"
    issue_type: str = "private"
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class CosCredentialError(RuntimeError):
    """Raised when no access-key pair is available from params or env."""


# --------------------------------------------------------------------------- #
# Checker
# --------------------------------------------------------------------------- #


class CosExposureChecker:
    """Read-only COS bucket exposure checker.

    Keys come from ``access_key_id`` / ``access_key_secret`` or the
    ``TENCENTCLOUD_*`` / ``COS_*`` environment variables -- never from a
    default. ``region`` selects the service endpoint used to enumerate buckets.

    All network access goes through :meth:`_request`, the single mock seam.
    Tests monkeypatch that method (or ``list_buckets`` / ``_read_acl`` /
    ``_read_policy`` / ``_list_keys``) to return canned responses without
    touching the network. No network call happens at construction time.
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
            raise CosCredentialError(
                "COS 凭证缺失: 请通过参数 access_key_id/access_key_secret 或环境变量 "
                f"{_ENV_AK_ID[0]}/{_ENV_AK_SECRET[0]} 提供只读 CAM 子账号凭证"
            )
        self.access_key_id: str = ak_id
        self.access_key_secret: str = ak_secret
        self.region = region or _first_env(_ENV_REGION) or _DEFAULT_REGION

    # -- network layer (single mockable seam) --------------------------------

    def _request(
        self,
        host: str,
        path: str = "/",
        params: dict[str, str] | None = None,
    ) -> bytes:
        """Perform a signed read-only GET against a COS XML endpoint.

        Returns the raw response body. Raises ``requests.HTTPError`` on
        non-2xx. This is the **only** network call site -- monkeypatch it in
        tests.
        """
        params = params or {}
        url = f"https://{host}{path}"
        headers = {"Authorization": self._sign(host, path, params)}
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.content

    def _sign(self, host: str, path: str, params: dict[str, str]) -> str:
        """Build the COS XML-API ``Authorization`` header (HMAC-SHA1 scheme).

        This is the documented Tencent COS signature: ``KeyTime`` scoped,
        canonical param/header lists, an HMAC-SHA1 ``StringToSign``, and a
        credential-bearing ``Authorization`` value. Read-only use only.
        """
        now = int(time.time())
        key_time = f"{now - 60};{now + 600}"

        # Only a fixed, minimal header set is signed (host). Parameters are the
        # sub-resource / query keys for this request.
        param_list = ";".join(sorted(params.keys()))
        header_list = "host"
        http_string = (
            f"get\n{path}\n"
            f"{_canonical_kv(params)}\n"
            f"host={quote(host, safe='')}\n"
        )
        string_to_sign = (
            f"sha1\n{key_time}\n{hashlib.sha1(http_string.encode('utf-8')).hexdigest()}\n"
        )
        sign_key = hmac.new(
            self.access_key_secret.encode("utf-8"),
            key_time.encode("utf-8"),
            hashlib.sha1,
        ).hexdigest()
        signature = hmac.new(
            sign_key.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha1,
        ).hexdigest()
        return (
            f"q-sign-algorithm=sha1&q-ak={self.access_key_id}"
            f"&q-sign-time={key_time}&q-key-time={key_time}"
            f"&q-header-list={header_list}&q-url-param-list={param_list}"
            f"&q-signature={signature}"
        )

    # -- read-only API wrappers ----------------------------------------------

    def list_buckets(self) -> list[str]:
        """Return the names of all buckets visible to the credentials.

        Uses ``GetService`` and parses the ``<Bucket><Name>`` entries.
        """
        body = self._request(_SERVICE_HOST, "/", {})
        return _parse_bucket_names(body)

    def _read_acl(self, bucket: str) -> list[str]:
        """Return the public permission strings granted by the bucket ACL.

        Uses ``GetBucketAcl``. Returns e.g. ``["READ"]`` / ``["WRITE"]`` /
        ``["FULL_CONTROL"]`` for grants that target the anonymous AllUsers
        group; ``[]`` when no public grant exists. Grant URIs are matched
        against the COS AllUsers URI (public) only.
        """
        host = f"{bucket}.cos.{self.region}.myqcloud.com"
        body = self._request(host, "/", {"acl": ""})
        return _parse_public_acl_permissions(body)

    def _read_policy(self, bucket: str) -> list[dict[str, Any]]:
        """Return the bucket policy statements, or ``[]`` if none / unreadable.

        Uses ``GetBucketPolicy``. A 404 (NoSuchBucketPolicy) or access-denied
        is treated as "no policy", not an error.
        """
        host = f"{bucket}.cos.{self.region}.myqcloud.com"
        try:
            body = self._request(host, "/", {"policy": ""})
        except Exception:
            return []
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        stmts = parsed.get("Statement", []) if isinstance(parsed, dict) else []
        if isinstance(stmts, dict):
            stmts = [stmts]
        return [s for s in stmts if isinstance(s, dict)]

    def _list_keys(self, bucket: str, max_keys: int = 200) -> list[str]:
        """Return up to ``max_keys`` object keys for sensitive-name scanning.

        Uses ``GetBucket`` (list objects). Read-only listing only; object
        contents are never fetched.
        """
        host = f"{bucket}.cos.{self.region}.myqcloud.com"
        body = self._request(host, "/", {"max-keys": str(max_keys)})
        return _parse_object_keys(body)

    # -- public API ----------------------------------------------------------

    def check_public_buckets(self) -> list[CosFinding]:
        """Check every visible bucket; a per-bucket failure never aborts the run."""
        return [self.check_bucket(name) for name in self.list_buckets()]

    def check_bucket(self, name: str) -> CosFinding:
        """Inspect one bucket's ACL + policy + objects and return a finding."""
        finding = CosFinding(resource=name, region=self.region)
        try:
            acl_perms = self._read_acl(name)
            statements = self._read_policy(name)
            acl_level, acl_severity = _classify_acl(acl_perms)
            pol_level, pol_severity = _classify_policy(statements)
            level, severity = _worse(acl_level, acl_severity, pol_level, pol_severity)

            sensitive = self._check_sensitive_files(name)
            if sensitive and severity != "critical" and level != "private":
                # Public exposure + sensitive material => escalate to critical.
                severity = "critical"

            finding.exposure_level = level
            finding.severity = severity
            finding.issue_type = _issue_type(level, bool(sensitive))
            finding.evidence = _build_evidence(acl_perms, statements, sensitive)
        except Exception as exc:  # per-bucket isolation: record and continue
            finding.error = f"{type(exc).__name__}: {exc}"
        return finding

    def _is_bucket_public(self, bucket: str) -> bool:
        """True when the bucket's ACL or policy grants anonymous access."""
        acl_perms = self._read_acl(bucket)
        statements = self._read_policy(bucket)
        if acl_perms:  # any AllUsers grant (READ/WRITE/FULL_CONTROL)
            return True
        exposing = [
            s
            for s in statements
            if str(s.get("Effect", "")).lower() == "allow"
            and _principal_is_public(s.get("Principal"))
        ]
        return bool(exposing)

    def _check_sensitive_files(self, bucket: str) -> list[str]:
        """Return object keys whose names match sensitive file patterns."""
        try:
            keys = self._list_keys(bucket)
        except Exception:
            return []
        return [k for k in keys if _is_sensitive_key(k)]


# --------------------------------------------------------------------------- #
# Classification + parsing helpers (pure functions, fully unit-testable).
# --------------------------------------------------------------------------- #


def _first_env(names: Sequence[str]) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _canonical_kv(params: dict[str, str]) -> str:
    """Encode parameters as sorted, percent-encoded ``k=v&...``."""
    return "&".join(
        f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in sorted(params.items())
    )


def _localname(tag: str) -> str:
    """Strip an XML namespace from a tag: ``{ns}Name`` -> ``Name``."""
    return tag.rsplit("}", 1)[-1]


def _parse_bucket_names(body: bytes) -> list[str]:
    """Extract ``<Bucket><Name>`` entries from a GetService XML body."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    names: list[str] = []
    for bucket in root.iter():
        if _localname(bucket.tag) != "Bucket":
            continue
        for child in bucket:
            if _localname(child.tag) == "Name" and child.text:
                names.append(child.text.strip())
    return names


def _parse_object_keys(body: bytes) -> list[str]:
    """Extract ``<Contents><Key>`` entries from a GetBucket (list) XML body."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    keys: list[str] = []
    for contents in root.iter():
        if _localname(contents.tag) != "Contents":
            continue
        for child in contents:
            if _localname(child.tag) == "Key" and child.text:
                keys.append(child.text.strip())
    return keys


def _parse_public_acl_permissions(body: bytes) -> list[str]:
    """Extract permissions granted to the anonymous AllUsers group.

    Walks ``AccessControlList/Grant`` entries; a grant whose Grantee URI is
    the COS AllUsers URI contributes its ``Permission`` value(s). Returns a
    de-duplicated list such as ``["READ", "WRITE"]``.
    """
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    perms: set[str] = set()
    for grant in root.iter():
        if _localname(grant.tag) != "Grant":
            continue
        grantee_uri = None
        permission = None
        for child in grant.iter():
            lname = _localname(child.tag)
            if lname == "URI" and child.text:
                grantee_uri = child.text.strip()
            elif lname == "Permission" and child.text:
                permission = child.text.strip()
        if grantee_uri == _COS_ALL_USERS_URI and permission:
            perms.add(permission)
    return sorted(perms)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _principal_is_public(principal: Any) -> bool:
    """A Principal is public when it is ``"*"`` or lists/contains ``"*"``.

    Handles the shapes Tencent/CAM policies use: bare ``"*"``, ``["*"]``, and
    service-keyed maps such as ``{"qcs": ["*"]}`` / ``{"cam": ["anyone"]}``.
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
                for leaf in _as_list(sub):
                    if leaf == "*" or str(leaf).lower() == "anyone":
                        return True
    return False


def _action_allows_write(action: Any) -> bool:
    norm = str(action).lower()
    return norm == "cos:*" or norm == "*" or any(
        k in norm for k in ("put", "delete", "write", "post")
    )


def _action_allows_read(action: Any) -> bool:
    norm = str(action).lower()
    return norm == "cos:*" or norm == "*" or any(
        k in norm for k in ("get", "list", "read", "head")
    )


def _classify_acl(perms: list[str]) -> tuple[str, str]:
    """Map public ACL permissions to (exposure_level, severity)."""
    norm = {p.upper() for p in perms}
    if "FULL_CONTROL" in norm or "WRITE" in norm or "WRITE_ACP" in norm:
        return "public_read_write", "critical"
    if "READ" in norm or "READ_ACP" in norm:
        return "public_read", "high"
    return "private", "info"


def _classify_policy(statements: list[dict[str, Any]]) -> tuple[str, str]:
    """Map a policy to (exposure_level, severity).

    Only statements that are simultaneously ``Effect: Allow`` *and* carry a
    public (``"*"``/anyone) principal count as exposing -- a ``Deny``
    principal of ``"*"`` is a guardrail, not an exposure.
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
    if any(_action_allows_write(a) for a in actions):
        return "policy_public", "critical"
    if any(_action_allows_read(a) for a in actions):
        return "policy_public", "high"
    # Public principal but no recognisable action: exposed, conservatively high.
    return "policy_public", "high"


def _worse(
    acl_level: str, acl_severity: str, pol_level: str, pol_severity: str
) -> tuple[str, str]:
    """Combine ACL and policy classifications, taking the worse severity."""
    if _SEVERITY_RANK[pol_severity] > _SEVERITY_RANK[acl_severity]:
        return pol_level, pol_severity
    return acl_level, acl_severity


def _issue_type(level: str, has_sensitive: bool) -> str:
    """Map an exposure level to a Finding.issue_type value (rule-table keyed)."""
    if level == "public_read_write":
        return "public-write-storage"
    if level in ("public_read", "policy_public"):
        return "public-read-sensitive" if has_sensitive else "public-read"
    return "private"


def _is_sensitive_key(key: str) -> bool:
    """True when an object key matches a sensitive file name pattern."""
    lowered = key.lower()
    basename = lowered.rsplit("/", 1)[-1]
    for pattern in SENSITIVE_FILE_PATTERNS:
        if pattern.endswith("/"):
            # Directory-style marker (e.g. ".git/"): match anywhere in path.
            if pattern in lowered:
                return True
        elif lowered.endswith(pattern) or basename == pattern:
            return True
    return False


def _build_evidence(
    acl_perms: list[str],
    statements: list[dict[str, Any]],
    sensitive: list[str],
) -> dict[str, Any]:
    """Record only ACL public perms + per-statement public flags + sensitive keys."""
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
        "acl_public_permissions": acl_perms,
        "public_policy_statements": public,
        "sensitive_files": sensitive[:20],  # cap to avoid huge evidence
    }
