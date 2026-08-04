"""Tests for the Aliyun OSS exposure checker.

Every oss2 call is mocked: the suite never touches the network and never uses
real credentials. Fake classes mirror the real oss2 surface we depend on
(``oss2.Auth`` / ``Service`` / ``BucketIterator`` / ``Bucket`` and the
``.acl`` / ``.policy`` / ``.location`` / ``.name`` result attributes).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cain_agent.cloud import aliyun_oss
from cain_agent.cloud.aliyun_oss import (
    OssCredentialError,
    OssExposureChecker,
    OssFinding,
)

# Test-only credentials; never valid, never sent anywhere (oss2 is mocked).
_AK_ID = "AKIDTESTFAKE"
_AK_SECRET = "SECRETFAKE"


# --------------------------------------------------------------------------- #
# Fake oss2 surface
# --------------------------------------------------------------------------- #


class _NoPolicy(Exception):
    """Mirrors oss2 raising when a bucket has no policy configured."""


class _FakeAcl:
    def __init__(self, acl: str) -> None:
        self.acl = acl


class _FakePolicy:
    def __init__(self, policy_obj: dict[str, Any]) -> None:
        self.policy = json.dumps(policy_obj)


class _FakeInfo:
    def __init__(self, location: str) -> None:
        self.location = location


class _FakeBucketInfo:
    def __init__(self, name: str, location: str = "oss-cn-hangzhou") -> None:
        self.name = name
        self.location = location


class _FakeAuth:
    def __init__(self, ak_id: str, ak_secret: str) -> None:
        self.ak_id = ak_id
        self.ak_secret = ak_secret


class _FakeService:
    def __init__(self, auth: Any, endpoint: str, **_: Any) -> None:
        self.auth = auth
        self.endpoint = endpoint


class _FakeBucket:
    def __init__(self, auth: Any, endpoint: str, name: str, **_: Any) -> None:
        self.auth = auth
        self.endpoint = endpoint
        self.name = name
        self._cfg = _STATE["buckets"].get(name, {})

    def get_bucket_acl(self) -> _FakeAcl:
        if "acl_error" in self._cfg:
            raise self._cfg["acl_error"]
        return _FakeAcl(self._cfg.get("acl", "private"))

    def get_bucket_policy(self) -> _FakePolicy:
        if "policy_error" in self._cfg:
            raise self._cfg["policy_error"]
        policy = self._cfg.get("policy")
        if policy is None:
            raise _NoPolicy("no policy")
        return _FakePolicy(policy)

    def get_bucket_info(self) -> _FakeInfo:
        if "info_error" in self._cfg:
            raise self._cfg["info_error"]
        return _FakeInfo(self._cfg.get("location", "oss-cn-hangzhou"))


# Module-global state populated by the `fake_oss2` fixture so the fake classes
# (which patch the real oss2 attributes) can resolve per-test bucket configs.
_STATE: dict[str, Any] = {"buckets": {}}


class _FakeBucketIterator:
    def __init__(self, service: Any, **_: Any) -> None:
        self.service = service

    def __iter__(self) -> Any:
        for name, cfg in list(_STATE["buckets"].items()):
            yield _FakeBucketInfo(name, cfg.get("location", "oss-cn-hangzhou"))


@pytest.fixture
def fake_oss2(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Patch the oss2 seams referenced by aliyun_oss with deterministic fakes."""
    _STATE["buckets"] = {}
    monkeypatch.setattr(aliyun_oss.oss2, "Auth", _FakeAuth)
    monkeypatch.setattr(aliyun_oss.oss2, "Service", _FakeService)
    monkeypatch.setattr(aliyun_oss.oss2, "Bucket", _FakeBucket)
    monkeypatch.setattr(aliyun_oss.oss2, "BucketIterator", _FakeBucketIterator)
    return _STATE


def _configure(buckets: dict[str, dict[str, Any]]) -> None:
    """Install a bucket configuration into the fake oss2 state."""
    _STATE["buckets"] = dict(buckets)


def _checker() -> OssExposureChecker:
    return OssExposureChecker(
        access_key_id=_AK_ID, access_key_secret=_AK_SECRET, region="oss-cn-hangzhou"
    )


def _policy(principal: Any, action: Any, effect: str = "Allow", sid: str = "public") -> dict[str, Any]:
    return {"Version": "1", "Statement": [{"Sid": sid, "Effect": effect,
                                           "Principal": principal, "Action": action}]}


# --------------------------------------------------------------------------- #
# Credentials contract
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_credential_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no ambient credentials leak in from the real environment."""
    for var in (
        "ALIBABA_CLOUD_ACCESS_KEY_ID", "OSS_ACCESS_KEY_ID",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "OSS_ACCESS_KEY_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)


def test_missing_credentials_raises() -> None:
    with pytest.raises(OssCredentialError):
        OssExposureChecker()  # no params, env scrubbed by autouse fixture


def test_credentials_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "env-ak")
    monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "env-sk")
    checker = OssExposureChecker()
    assert checker.access_key_id == "env-ak"
    assert checker.access_key_secret == "env-sk"


def test_param_credentials_take_priority_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "env-ak")
    monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "env-sk")
    checker = OssExposureChecker(access_key_id="param-ak", access_key_secret="param-sk")
    assert checker.access_key_id == "param-ak"
    assert checker.access_key_secret == "param-sk"


# --------------------------------------------------------------------------- #
# list_buckets
# --------------------------------------------------------------------------- #


def test_list_buckets_enumerates_all(fake_oss2: Any) -> None:
    _configure({"alpha": {}, "beta": {}, "gamma": {}})
    assert _checker().list_buckets() == ["alpha", "beta", "gamma"]


# --------------------------------------------------------------------------- #
# ACL-based classification (hardcoded rules)
# --------------------------------------------------------------------------- #


def test_acl_private_is_info(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "private"}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"
    assert f.error is None


def test_acl_public_read_is_high(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "public-read"}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "public_read"
    assert f.severity == "high"


def test_acl_public_read_write_is_critical(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "public-read-write"}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "public_read_write"
    assert f.severity == "critical"


# --------------------------------------------------------------------------- #
# Policy-based classification
# --------------------------------------------------------------------------- #


def test_policy_public_read_is_high(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "private", "policy": _policy("*", "oss:GetObject")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "policy_public"
    assert f.severity == "high"


def test_policy_public_write_is_critical(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "private", "policy": _policy("*", "oss:PutObject")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "policy_public"
    assert f.severity == "critical"


def test_policy_wildcard_oss_star_is_critical(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "private", "policy": _policy("*", "oss:*")}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"
    assert f.exposure_level == "policy_public"


def test_policy_delete_action_is_write(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "private", "policy": _policy("*", ["oss:DeleteObject"])}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"


def test_policy_non_public_principal_is_private(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "private",
                       "policy": _policy("acs:ram::123456:root", "oss:GetObject")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"


def test_policy_public_principal_in_dict_form_flagged(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "private",
                       "policy": _policy({"RAM": ["*"]}, "oss:GetObject")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "policy_public"
    assert f.severity == "high"


def test_policy_deny_principal_star_is_not_exposure(fake_oss2: Any) -> None:
    # A Deny statement with a "*" principal is a guardrail, not an exposure.
    _configure({"b1": {"acl": "private", "policy": _policy("*", "oss:*", effect="Deny")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "private"
    assert f.severity == "info"


def test_acl_and_policy_combine_worst_wins(fake_oss2: Any) -> None:
    # ACL says public-read (high); policy grants public write (critical).
    _configure({"b1": {"acl": "public-read", "policy": _policy("*", "oss:PutObject")}})
    f = _checker().check_bucket("b1")
    assert f.severity == "critical"
    assert f.exposure_level == "policy_public"


# --------------------------------------------------------------------------- #
# Fault isolation
# --------------------------------------------------------------------------- #


def test_single_bucket_acl_failure_is_recorded_not_raised(fake_oss2: Any) -> None:
    _configure({"bad": {"acl_error": RuntimeError("AccessDenied: no permission")}})
    f = _checker().check_bucket("bad")
    assert f.error is not None
    assert "AccessDenied" in f.error
    assert f.severity == "info"
    assert f.exposure_level == "private"


def test_check_all_continues_past_failures(fake_oss2: Any) -> None:
    _configure({
        "good": {"acl": "public-read"},
        "bad": {"acl_error": RuntimeError("boom")},
        "good2": {"acl": "private"},
    })
    findings = _checker().check_all()
    by_bucket = {f.bucket: f for f in findings}
    assert set(by_bucket) == {"good", "bad", "good2"}
    assert by_bucket["good"].severity == "high"
    assert by_bucket["bad"].error is not None
    assert by_bucket["good2"].severity == "info"


def test_policy_read_failure_falls_back_to_acl(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "public-read", "policy_error": _NoPolicy("none")}})
    f = _checker().check_bucket("b1")
    assert f.exposure_level == "public_read"
    assert f.severity == "high"


# --------------------------------------------------------------------------- #
# Region resolution + evidence hygiene
# --------------------------------------------------------------------------- #


def test_region_resolved_from_bucket_location(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "private", "location": "oss-us-west-1"}})
    f = _checker().check_bucket("b1")
    assert f.region == "oss-us-west-1"


def test_region_falls_back_on_info_error(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "private", "info_error": RuntimeError("no info")}})
    f = _checker().check_bucket("b1")
    assert f.region == "oss-cn-hangzhou"


def test_evidence_contains_no_sensitive_content(fake_oss2: Any) -> None:
    _configure({"b1": {"acl": "public-read", "policy": _policy("*", "oss:PutObject")}})
    f = _checker().check_bucket("b1")
    blob = json.dumps(f.evidence)
    assert _AK_ID not in blob and _AK_SECRET not in blob
    # Evidence records ACL grant + per-statement sid/effect/read/write only.
    assert f.evidence["acl"] == "public-read"
    stmt = f.evidence["public_policy_statements"][0]
    assert set(stmt) == {"sid", "effect", "principal_star", "read", "write"}
    assert stmt["write"] is True


def test_severity_rules_are_module_constants() -> None:
    # Requirement: severity is hardcoded, not model-derived.
    assert aliyun_oss.SEVERITY_BY_EXPOSURE == {
        "private": "info",
        "public_read": "high",
        "public_read_write": "critical",
        "policy_public": "high",
    }


def test_finding_default_shape() -> None:
    finding = OssFinding(bucket="x")
    assert finding.region is None
    assert finding.exposure_level == "private"
    assert finding.severity == "info"
    assert finding.evidence == {}
    assert finding.error is None
