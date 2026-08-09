"""Tests for the Huawei Cloud OBS exposure checker.

Every boto3 call is mocked: the suite never touches the network and never uses
real credentials.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cain_agent.cloud import huawei_obs
from cain_agent.cloud.huawei_obs import (
    ObsCredentialError,
    ObsExposureChecker,
    ObsFinding,
)

_AK_ID = "AKTESTFAKE"
_AK_SECRET = "SECRETFAKE"

_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"

# --------------------------------------------------------------------------- #
# Fake boto3 surface
# --------------------------------------------------------------------------- #

_STATE: dict[str, Any] = {"buckets": {}}


class _FakeObsClient:
    """Deterministic mock of the boto3 S3-compatible client for OBS."""

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


@pytest.fixture
def fake_boto3(monkeypatch: pytest.MonkeyPatch) -> Any:
    _STATE["buckets"] = {}
    monkeypatch.setattr(huawei_obs.boto3, "client", lambda *a, **kw: _FakeObsClient(**kw))
    return _STATE


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "HUAWEICLOUD_ACCESS_KEY_ID",
        "HUAWEICLOUD_SECRET_ACCESS_KEY",
        "HUAWEICLOUD_REGION",
        "OBS_ACCESS_KEY_ID",
        "OBS_SECRET_ACCESS_KEY",
        "OBS_REGION",
    ):
        monkeypatch.delenv(var, raising=False)


def _configure(buckets: dict[str, dict[str, Any]]) -> None:
    _STATE["buckets"] = dict(buckets)


def _checker() -> ObsExposureChecker:
    return ObsExposureChecker(access_key_id=_AK_ID, access_key_secret=_AK_SECRET, region="cn-north-4")


def _acl_grant(uri: str, permission: str) -> dict[str, Any]:
    return {"Grants": [{"Grantee": {"Type": "Group", "URI": uri}, "Permission": permission}]}


def _policy(principal: Any, action: Any, effect: str = "Allow", sid: str = "public") -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": [{"Sid": sid, "Effect": effect,
                                                     "Principal": principal, "Action": action}]}


# --------------------------------------------------------------------------- #
# Credentials contract
# --------------------------------------------------------------------------- #

def test_missing_credentials_raises() -> None:
    with pytest.raises(ObsCredentialError):
        ObsExposureChecker()


def test_credentials_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUAWEICLOUD_ACCESS_KEY_ID", "env-ak")
    monkeypatch.setenv("HUAWEICLOUD_SECRET_ACCESS_KEY", "env-sk")
    checker = ObsExposureChecker()
    assert checker.access_key_id == "env-ak"
    assert checker.access_key_secret == "env-sk"


def test_param_credentials_take_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUAWEICLOUD_ACCESS_KEY_ID", "env-ak")
    monkeypatch.setenv("HUAWEICLOUD_SECRET_ACCESS_KEY", "env-sk")
    checker = ObsExposureChecker(access_key_id="param-ak", access_key_secret="param-sk")
    assert checker.access_key_id == "param-ak"


def test_obs_env_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OBS_ACCESS_KEY_ID", "obs-ak")
    monkeypatch.setenv("OBS_SECRET_ACCESS_KEY", "obs-sk")
    checker = ObsExposureChecker()
    assert checker.access_key_id == "obs-ak"
    assert checker.access_key_secret == "obs-sk"


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


def test_acl_public_write_is_critical(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_ALL_USERS, "WRITE")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "public_read_write"
    assert f.severity == "critical"


def test_acl_full_control_is_critical(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_ALL_USERS, "FULL_CONTROL")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "public_read_write"
    assert f.severity == "critical"


# --------------------------------------------------------------------------- #
# Policy-based classification
# --------------------------------------------------------------------------- #

def test_policy_public_read_is_high(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}, "policy": _policy("*", "obs:GetObject")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "policy_public"
    assert f.severity == "high"


def test_policy_public_write_is_critical(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}, "policy": _policy("*", "obs:PutObject")}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"


def test_policy_obs_star_is_critical(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}, "policy": _policy("*", "obs:*")}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"


def test_policy_s3_star_is_critical(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}, "policy": _policy("*", "s3:*")}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"


def test_policy_deny_is_not_exposure(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []}, "policy": _policy("*", "obs:*", effect="Deny")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"


def test_policy_arn_principal_is_private(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []},
                       "policy": _policy("arn:huawei::iam::123456:root", "obs:GetObject")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"


def test_acl_and_policy_worst_wins(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": _acl_grant(_ALL_USERS, "READ"),
                       "policy": _policy("*", "obs:PutObject")}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"


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
    assert by_bucket["bad"].severity == "info"


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
                       "policy": _policy("*", "obs:PutObject")}})
    f = _checker().check_bucket("b1")
    blob = json.dumps(f.evidence)
    assert _AK_ID not in blob and _AK_SECRET not in blob


def test_evidence_records_public_statements(fake_boto3: Any) -> None:
    _configure({"b1": {"acl_resp": {"Grants": []},
                       "policy": _policy("*", "obs:GetObject")}})
    f = _checker().check_bucket("b1")
    assert len(f.evidence["public_policy_statements"]) == 1
    stmt = f.evidence["public_policy_statements"][0]
    assert stmt["read"] is True
    assert stmt["write"] is False
    assert stmt["principal_star"] is True


def test_severity_rules_are_constants() -> None:
    assert huawei_obs.SEVERITY_BY_EXPOSURE["public_read_write"] == "critical"
    assert huawei_obs.SEVERITY_BY_EXPOSURE["public_read"] == "high"
    assert huawei_obs.SEVERITY_BY_EXPOSURE["private"] == "info"


def test_finding_default_shape() -> None:
    finding = ObsFinding(bucket="x")
    assert finding.region is None
    assert finding.exposure_level == "private"
    assert finding.severity == "info"
    assert finding.evidence == {}
    assert finding.error is None


def test_client_uses_obs_endpoint(fake_boto3: Any) -> None:
    """The boto3 client should be pointed at the OBS endpoint."""
    _configure({"b1": {}})
    c = _checker()
    c.check_all()
    # _client_cache stores the _FakeObsClient which recorded its kwargs
    kwargs = c._client_cache.kwargs  # type: ignore[attr-defined]
    assert "obs.cn-north-4.myhuaweicloud.com" in kwargs.get("endpoint_url", "")
    assert kwargs.get("region_name") == "cn-north-4"
    assert kwargs.get("aws_access_key_id") == _AK_ID
