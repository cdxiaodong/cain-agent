"""Tests for the Tencent COS exposure checker.

Every network call is mocked: the suite never touches the network and never
uses real credentials. The single seam is ``CosExposureChecker._request``;
higher-level helpers (``_read_acl`` / ``_read_policy`` / ``_list_keys``) are
also patched directly where convenient.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cain_agent.cloud.tencent_cos import (
    CosCredentialError,
    CosExposureChecker,
    CosFinding,
    _is_sensitive_key,
)

# Test-only credentials; never valid, never sent anywhere (network is mocked).
_AK_ID = "AKIDTESTFAKE"
_AK_SECRET = "SECRETFAKE"


def _checker() -> CosExposureChecker:
    return CosExposureChecker(
        access_key_id=_AK_ID, access_key_secret=_AK_SECRET, region="ap-guangzhou"
    )


def _getservice_xml(names: list[str]) -> bytes:
    buckets = "".join(f"<Bucket><Name>{n}</Name></Bucket>" for n in names)
    return f"<ListAllMyBucketsResult><Buckets>{buckets}</Buckets></ListAllMyBucketsResult>".encode()


def _acl_xml(public_perms: list[str]) -> bytes:
    grants = "".join(
        "<Grant><Grantee><URI>http://cam.qcloud.com/groups/global/AllUsers</URI></Grantee>"
        f"<Permission>{p}</Permission></Grant>"
        for p in public_perms
    )
    body = (
        f"<AccessControlPolicy><AccessControlList>{grants}</AccessControlList>"
        "</AccessControlPolicy>"
    )
    return body.encode()


def _listobjects_xml(keys: list[str]) -> bytes:
    contents = "".join(f"<Contents><Key>{k}</Key></Contents>" for k in keys)
    return f"<ListBucketResult>{contents}</ListBucketResult>".encode()


def _policy(principal: Any, action: Any, effect: str = "Allow", sid: str = "public") -> dict[str, Any]:
    return {
        "version": "2.0",
        "Statement": [
            {"Sid": sid, "Effect": effect, "Principal": principal, "Action": action}
        ],
    }


# --------------------------------------------------------------------------- #
# Credentials contract
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_credential_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no ambient credentials leak in from the real environment."""
    for var in (
        "TENCENTCLOUD_SECRET_ID", "COS_SECRET_ID",
        "TENCENTCLOUD_SECRET_KEY", "COS_SECRET_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


def test_missing_credentials_raises() -> None:
    with pytest.raises(CosCredentialError):
        CosExposureChecker()  # no params, env scrubbed by autouse fixture


def test_credentials_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "env-ak")
    monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "env-sk")
    checker = CosExposureChecker()
    assert checker.access_key_id == "env-ak"
    assert checker.access_key_secret == "env-sk"


def test_param_credentials_take_priority_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "env-ak")
    monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "env-sk")
    checker = CosExposureChecker(access_key_id="param-ak", access_key_secret="param-sk")
    assert checker.access_key_id == "param-ak"
    assert checker.access_key_secret == "param-sk"


# --------------------------------------------------------------------------- #
# list_buckets (GetService)
# --------------------------------------------------------------------------- #


def test_list_buckets_parses_getservice(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _checker()
    monkeypatch.setattr(
        checker, "_request", lambda *a, **k: _getservice_xml(["alpha", "beta"])
    )
    assert checker.list_buckets() == ["alpha", "beta"]


def test_list_buckets_empty_on_bad_xml(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _checker()
    monkeypatch.setattr(checker, "_request", lambda *a, **k: b"not xml")
    assert checker.list_buckets() == []


# --------------------------------------------------------------------------- #
# Read-only API surface (ACL / policy / object listing)
# --------------------------------------------------------------------------- #


def test_read_acl_returns_public_permissions(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _checker()
    monkeypatch.setattr(checker, "_request", lambda *a, **k: _acl_xml(["READ"]))
    assert checker._read_acl("b1") == ["READ"]


def test_read_acl_ignores_non_public_grantee(monkeypatch: pytest.MonkeyPatch) -> None:
    body = (
        b"<AccessControlPolicy><AccessControlList>"
        b"<Grant><Grantee><ID>qcs::cam::uin/1:uin/1</ID></Grantee>"
        b"<Permission>FULL_CONTROL</Permission></Grant>"
        b"</AccessControlList></AccessControlPolicy>"
    )
    checker = _checker()
    monkeypatch.setattr(checker, "_request", lambda *a, **k: body)
    assert checker._read_acl("b1") == []


def test_read_policy_parses_statements(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _checker()
    body = json.dumps(_policy("*", "cos:GetObject")).encode()
    monkeypatch.setattr(checker, "_request", lambda *a, **k: body)
    stmts = checker._read_policy("b1")
    assert len(stmts) == 1
    assert stmts[0]["Effect"] == "Allow"


def test_read_policy_empty_when_no_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _checker()

    def _raise(*a: Any, **k: Any) -> bytes:
        raise RuntimeError("NoSuchBucketPolicy")

    monkeypatch.setattr(checker, "_request", _raise)
    assert checker._read_policy("b1") == []


def test_list_keys_parses_getbucket(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _checker()
    monkeypatch.setattr(
        checker, "_request", lambda *a, **k: _listobjects_xml(["a.txt", "config/.env"])
    )
    assert checker._list_keys("b1") == ["a.txt", "config/.env"]


# --------------------------------------------------------------------------- #
# ACL-based classification (hardcoded rules)
# --------------------------------------------------------------------------- #


def _patch_bucket(
    monkeypatch: pytest.MonkeyPatch,
    acl: list[str] | None = None,
    policy: dict[str, Any] | None = None,
    keys: list[str] | None = None,
    acl_error: Exception | None = None,
) -> CosExposureChecker:
    checker = _checker()
    if acl_error is not None:
        def _acl_err(self: Any, b: str) -> list[str]:
            raise acl_error
        monkeypatch.setattr(CosExposureChecker, "_read_acl", _acl_err)
    else:
        monkeypatch.setattr(
            CosExposureChecker, "_read_acl", lambda self, b: list(acl or [])
        )
    monkeypatch.setattr(
        CosExposureChecker,
        "_read_policy",
        lambda self, b: (list(policy["Statement"]) if policy else []),
    )
    monkeypatch.setattr(
        CosExposureChecker, "_list_keys", lambda self, b, **k: list(keys or [])
    )
    return checker


def test_acl_private_is_info(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch, acl=[])
    f = checker.check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"
    assert f.issue_type == "private"
    assert f.error is None


def test_acl_public_read_is_high(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch, acl=["READ"])
    f = checker.check_bucket("b1")
    assert f.exposure_level == "public_read"
    assert f.severity == "high"
    assert f.issue_type == "public-read"


def test_acl_public_write_is_critical(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch, acl=["WRITE"])
    f = checker.check_bucket("b1")
    assert f.exposure_level == "public_read_write"
    assert f.severity == "critical"
    assert f.issue_type == "public-write-storage"


def test_acl_full_control_is_critical(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch, acl=["FULL_CONTROL"])
    f = checker.check_bucket("b1")
    assert f.exposure_level == "public_read_write"
    assert f.severity == "critical"


# --------------------------------------------------------------------------- #
# Policy-based classification
# --------------------------------------------------------------------------- #


def test_policy_public_read_is_high(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch, policy=_policy("*", "cos:GetObject"))
    f = checker.check_bucket("b1")
    assert f.exposure_level == "policy_public"
    assert f.severity == "high"


def test_policy_public_write_is_critical(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch, policy=_policy("*", "cos:PutObject"))
    f = checker.check_bucket("b1")
    assert f.exposure_level == "policy_public"
    assert f.severity == "critical"
    assert f.issue_type == "public-read"  # policy_public maps to public-read*


def test_policy_wildcard_cos_star_is_critical(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch, policy=_policy("*", "cos:*"))
    f = checker.check_bucket("b1")
    assert f.severity == "critical"
    assert f.exposure_level == "policy_public"


def test_policy_non_public_principal_is_private(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(
        monkeypatch, policy=_policy("qcs::cam::uin/100:root", "cos:GetObject")
    )
    f = checker.check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"


def test_policy_principal_anyone_in_dict_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(
        monkeypatch, policy=_policy({"qcs": ["anyone"]}, "cos:GetObject")
    )
    f = checker.check_bucket("b1")
    assert f.exposure_level == "policy_public"
    assert f.severity == "high"


def test_policy_deny_principal_star_is_not_exposure(monkeypatch: pytest.MonkeyPatch) -> None:
    # A Deny statement with a "*" principal is a guardrail, not an exposure.
    checker = _patch_bucket(monkeypatch, policy=_policy("*", "cos:*", effect="Deny"))
    f = checker.check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"


def test_acl_and_policy_combine_worst_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(
        monkeypatch, acl=["READ"], policy=_policy("*", "cos:PutObject")
    )
    f = checker.check_bucket("b1")
    assert f.severity == "critical"
    assert f.exposure_level == "policy_public"


# --------------------------------------------------------------------------- #
# _is_bucket_public
# --------------------------------------------------------------------------- #


def test_is_bucket_public_via_acl(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch, acl=["READ"])
    assert checker._is_bucket_public("b1") is True


def test_is_bucket_public_via_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch, policy=_policy("*", "cos:GetObject"))
    assert checker._is_bucket_public("b1") is True


def test_is_bucket_not_public_when_private(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(monkeypatch)
    assert checker._is_bucket_public("b1") is False


# --------------------------------------------------------------------------- #
# Sensitive file detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (".env", True),
        ("config/app.env", True),
        ("backup/db.sql", True),
        ("certs/server.pem", True),
        ("keys/id_rsa", True),
        ("repo/.git/config", True),
        ("site/wp-config.php", True),
        ("images/photo.jpg", False),
        ("docs/readme.md", False),
        ("app.js", False),
    ],
)
def test_is_sensitive_key_patterns(key: str, expected: bool) -> None:
    assert _is_sensitive_key(key) is expected


def test_check_sensitive_files_filters_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(
        monkeypatch, keys=["a.txt", "config/.env", "keys/server.pem", "b.md"]
    )
    assert checker._check_sensitive_files("b1") == ["config/.env", "keys/server.pem"]


def test_public_read_with_sensitive_files_is_critical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checker = _patch_bucket(monkeypatch, acl=["READ"], keys=["config/.env"])
    f = checker.check_bucket("b1")
    assert f.severity == "critical"
    assert f.issue_type == "public-read-sensitive"


def test_private_with_sensitive_files_stays_info(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sensitive files in a *private* bucket are not an exposure.
    checker = _patch_bucket(monkeypatch, acl=[], keys=["config/.env"])
    f = checker.check_bucket("b1")
    assert f.severity == "info"
    assert f.issue_type == "private"


def test_sensitive_files_listing_failure_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checker = _patch_bucket(monkeypatch, acl=["READ"])

    def _list_err(self: Any, b: str, **k: Any) -> list[str]:
        raise RuntimeError("list denied")

    monkeypatch.setattr(CosExposureChecker, "_list_keys", _list_err)
    f = checker.check_bucket("b1")
    assert f.severity == "high"  # falls back to ACL-only classification


# --------------------------------------------------------------------------- #
# Fault isolation + evidence hygiene
# --------------------------------------------------------------------------- #


def test_single_bucket_acl_failure_is_recorded_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checker = _patch_bucket(monkeypatch, acl_error=RuntimeError("AccessDenied"))
    f = checker.check_bucket("bad")
    assert f.error is not None
    assert "AccessDenied" in f.error
    assert f.severity == "info"


def test_check_public_buckets_continues_past_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checker = _checker()
    monkeypatch.setattr(checker, "list_buckets", lambda: ["good", "bad", "good2"])

    def _check(name: str) -> CosFinding:
        if name == "bad":
            return CosFinding(resource=name, error="RuntimeError: boom")
        return CosFinding(
            resource=name,
            exposure_level="public_read" if name == "good" else "private",
            severity="high" if name == "good" else "info",
        )

    monkeypatch.setattr(checker, "check_bucket", _check)
    findings = checker.check_public_buckets()
    by_bucket = {f.resource: f for f in findings}
    assert set(by_bucket) == {"good", "bad", "good2"}
    assert by_bucket["good"].severity == "high"
    assert by_bucket["bad"].error is not None
    assert by_bucket["good2"].severity == "info"


def test_evidence_contains_no_sensitive_content(monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _patch_bucket(
        monkeypatch, acl=["READ"], policy=_policy("*", "cos:PutObject"),
        keys=["config/.env"],
    )
    f = checker.check_bucket("b1")
    blob = json.dumps(f.evidence)
    assert _AK_ID not in blob and _AK_SECRET not in blob
    assert f.evidence["acl_public_permissions"] == ["READ"]
    stmt = f.evidence["public_policy_statements"][0]
    assert set(stmt) == {"sid", "effect", "principal_star", "read", "write"}
    assert stmt["write"] is True
    assert f.evidence["sensitive_files"] == ["config/.env"]


# --------------------------------------------------------------------------- #
# Finding shape / alignment
# --------------------------------------------------------------------------- #


def test_finding_default_shape() -> None:
    finding = CosFinding(resource="x")
    assert finding.cloud == "tencent"
    assert finding.service == "cos"
    assert finding.resource == "x"
    assert finding.region is None
    assert finding.exposure_level == "private"
    assert finding.severity == "info"
    assert finding.evidence == {}
    assert finding.error is None


def test_finding_cloud_service_resource_alignment(monkeypatch: pytest.MonkeyPatch) -> None:
    # CosFinding aligns with OssFinding: cloud=tencent, service=cos,
    # resource=bucketName.
    checker = _patch_bucket(monkeypatch, acl=["READ"])
    f = checker.check_bucket("my-bucket")
    assert f.cloud == "tencent"
    assert f.service == "cos"
    assert f.resource == "my-bucket"
    assert f.region == "ap-guangzhou"
