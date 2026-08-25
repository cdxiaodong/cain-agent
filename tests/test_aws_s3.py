"""Tests for the AWS S3 exposure checker.

Every boto3 call is mocked: the suite never touches the network and never uses
real credentials.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from cain_agent.cloud import aws_s3
from cain_agent.cloud.aws_s3 import (
    S3CredentialError,
    S3ExposureChecker,
    S3Finding,
)

_AK_ID = "AKIATESTFAKE"
_AK_SECRET = "SECRETFAKE"

_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

# --------------------------------------------------------------------------- #
# Fake boto3 surface
# --------------------------------------------------------------------------- #

_STATE: dict[str, Any] = {"buckets": {}}


class _FakeS3Client:
    """Deterministic mock of the boto3 S3 client surface we depend on."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    def list_buckets(self) -> dict[str, Any]:
        return {"Buckets": [{"Name": n} for n in _STATE["buckets"]]}

    def get_bucket_acl(self, *, Bucket: str) -> dict[str, Any]:
        cfg = _STATE["buckets"].get(Bucket, {})
        if "acl_error" in cfg:
            raise cfg["acl_error"]
        return cfg.get("acl_resp", {"Grants": []})

    def get_bucket_policy(self, *, Bucket: str) -> dict[str, str]:
        cfg = _STATE["buckets"].get(Bucket, {})
        if "policy_error" in cfg:
            raise cfg["policy_error"]
        if "policy" not in cfg:
            raise Exception("NoSuchBucketPolicy")
        return {"Policy": json.dumps(cfg["policy"])}

    def get_public_access_block(self, *, Bucket: str) -> dict[str, Any]:
        cfg = _STATE["buckets"].get(Bucket, {})
        if "pab_error" in cfg:
            raise cfg["pab_error"]
        if "pab" not in cfg:
            raise Exception("PublicAccessBlockNotFoundError")
        return {"PublicAccessBlockConfiguration": cfg["pab"]}


@pytest.fixture
def fake_boto3(monkeypatch: pytest.MonkeyPatch) -> Any:
    _STATE["buckets"] = {}
    monkeypatch.setattr(aws_s3, "boto3", SimpleNamespace(client=lambda *a, **kw: _FakeS3Client(**kw)))
    return _STATE


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION", "AWS_REGION"):
        monkeypatch.delenv(var, raising=False)


def _configure(buckets: dict[str, dict[str, Any]]) -> None:
    _STATE["buckets"] = dict(buckets)


def _checker() -> S3ExposureChecker:
    return S3ExposureChecker(access_key_id=_AK_ID, access_key_secret=_AK_SECRET, region="us-east-1")


def _acl_grant(uri: str, permission: str) -> dict[str, Any]:
    return {"Grants": [{"Grantee": {"Type": "Group", "URI": uri}, "Permission": permission}]}


def _policy(principal: Any, action: Any, effect: str = "Allow", sid: str = "public") -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": [{"Sid": sid, "Effect": effect,
                                                     "Principal": principal, "Action": action}]}


# --------------------------------------------------------------------------- #
# Credentials contract
# --------------------------------------------------------------------------- #

def test_missing_credentials_raises() -> None:
    with pytest.raises(S3CredentialError):
        S3ExposureChecker()


def test_credentials_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "env-ak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-sk")
    checker = S3ExposureChecker()
    assert checker.access_key_id == "env-ak"
    assert checker.access_key_secret == "env-sk"


def test_param_credentials_take_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "env-ak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-sk")
    checker = S3ExposureChecker(access_key_id="param-ak", access_key_secret="param-sk")
    assert checker.access_key_id == "param-ak"


# --------------------------------------------------------------------------- #
# list_buckets
# --------------------------------------------------------------------------- #

def test_list_buckets(fake_boto3: Any) -> None:
    _configure({"alpha": {}, "beta": {}})
    assert _checker().list_buckets() == ["alpha", "beta"]


# --------------------------------------------------------------------------- #
# ACL-based classification
# --------------------------------------------------------------------------- #

def test_acl_private_is_info(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"


def test_acl_public_read_is_high(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_ALL_USERS, "READ")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "public_read"
    assert f.severity == "high"


def test_acl_public_read_write_is_critical(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_ALL_USERS, "WRITE")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "public_read_write"
    assert f.severity == "critical"


def test_acl_authenticated_read_is_info(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_AUTH_USERS, "READ")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "authenticated_read"
    assert f.severity == "info"


# --------------------------------------------------------------------------- #
# Policy-based classification
# --------------------------------------------------------------------------- #

def test_policy_public_read_is_high(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}, "policy": _policy("*", "s3:GetObject")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "policy_public"
    assert f.severity == "high"


def test_policy_public_write_is_critical(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}, "policy": _policy("*", "s3:PutObject")}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"


def test_policy_s3_star_is_critical(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}, "policy": _policy("*", "s3:*")}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"


def test_policy_deny_is_not_exposure(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}, "policy": _policy("*", "s3:*", effect="Deny")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"


def test_policy_arn_principal_is_private(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []},
                       "policy": _policy("arn:aws:iam::123456:root", "s3:GetObject")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"


def test_acl_and_policy_worst_wins(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_ALL_USERS, "READ"),
                       "policy": _policy("*", "s3:PutObject")}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"


# --------------------------------------------------------------------------- #
# Public Access Block
# --------------------------------------------------------------------------- #

def test_pab_blocks_public_acl(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_ALL_USERS, "READ"),
                       "pab": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                               "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"


def test_pab_blocks_public_policy(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []},
                       "policy": _policy("*", "s3:PutObject"),
                       "pab": {"BlockPublicAcls": False, "IgnorePublicAcls": False,
                               "BlockPublicPolicy": True, "RestrictPublicBuckets": False}}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"


def test_partial_pab_only_block_acls_still_allows_policy(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []},
                       "policy": _policy("*", "s3:GetObject"),
                       "pab": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                               "BlockPublicPolicy": False, "RestrictPublicBuckets": False}}})
    f = _checker().check_bucket("b1")
    assert f.severity == "high"
    assert f.exposure_level == "policy_public"


# --------------------------------------------------------------------------- #
# Fault isolation
# --------------------------------------------------------------------------- #

def test_acl_error_falls_back_gracefully(fake_boto3: Any) -> None:
    """ACL read failure is isolated: ACL returns None, severity stays info."""
    _configure({"bad": {"acl_resp": {}, "acl_error": RuntimeError("AccessDenied")}})
    f = _checker().check_bucket("bad")
    assert f.error is None  # no bucket-level error: ACL failure is swallowed
    assert f.severity == "info"
    assert f.evidence["acl"] is None


def test_check_all_handles_acl_errors(fake_boto3: Any) -> None:
    """ACL failure on one bucket doesn't affect others."""
    _configure({
        "good": {"acl_resp": _acl_grant(_ALL_USERS, "READ")},
        "bad": {"acl_resp": {}, "acl_error": RuntimeError("boom")},
        "good2": {"acl_resp": {"Grants": []}},
    })
    findings = _checker().check_all()
    by_bucket = {f.bucket: f for f in findings}
    assert set(by_bucket) == {"good", "bad", "good2"}
    assert by_bucket["good"].severity == "high"
    assert by_bucket["bad"].severity == "info"  # ACL error -> info, not crash


def test_policy_failure_falls_back_to_acl(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_ALL_USERS, "READ"),
                       "policy_error": RuntimeError("none")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "public_read"
    assert f.severity == "high"


# --------------------------------------------------------------------------- #
# Evidence hygiene
# --------------------------------------------------------------------------- #

def test_evidence_no_credentials(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_ALL_USERS, "READ"),
                       "policy": _policy("*", "s3:PutObject")}})
    f = _checker().check_bucket("b1")
    blob = json.dumps(f.evidence)
    assert _AK_ID not in blob and _AK_SECRET not in blob


def test_evidence_records_pab(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []},
                       "pab": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                               "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}})
    f = _checker().check_bucket("b1")
    assert f.evidence["public_access_block"] is not None
    assert f.evidence["public_access_block"]["block_public_acls"] is True


def test_severity_rules_are_constants() -> None:
    assert aws_s3.SEVERITY_BY_EXPOSURE["public_read_write"] == "critical"
    assert aws_s3.SEVERITY_BY_EXPOSURE["public_read"] == "high"
    assert aws_s3.SEVERITY_BY_EXPOSURE["private"] == "info"


def test_finding_default_shape() -> None:
    finding = S3Finding(bucket="x")
    assert finding.region is None
    assert finding.exposure_level == "private"
    assert finding.severity == "info"
    assert finding.evidence == {}
    assert finding.error is None
