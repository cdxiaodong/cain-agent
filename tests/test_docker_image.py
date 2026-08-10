"""Tests for the Docker image vulnerability checker.

Every requests call is mocked: the suite never touches the network and never
uses real credentials. Fake classes mirror the requests Session surface we
depend on (``Session``, ``post``, ``raise_for_status``, ``json`` methods and
their result objects).
"""

from __future__ import annotations

from typing import Any

import pytest

from cain_agent.cloud import docker_image
from cain_agent.cloud.docker_image import (
    CVSS_CRITICAL_THRESHOLD,
    CVSS_HIGH_THRESHOLD,
    CVSS_LOW_THRESHOLD,
    CVSS_MEDIUM_THRESHOLD,
    DockerCredentialError,
    DockerFinding,
    DockerImageChecker,
    SEVERITY_BY_CVSS,
    _as_list,
    _build_evidence,
    _classify_overall_severity,
    _normalize_vulnerability,
    _severity_by_cvss,
)

# Test-only credentials; never valid, never sent anywhere (requests is mocked).
_TEST_USERNAME = "test-user"
_TEST_PASSWORD = "test-pass"
_TEST_REGISTRY = "registry.example.com"
_TEST_TRIVY_URL = "http://trivy.example.com"


# --------------------------------------------------------------------------- #
# Fake requests surface
# --------------------------------------------------------------------------- #


class _FakeResponse:
    def __init__(self, json_data: dict[str, Any], status_code: int = 200) -> None:
        self._json_data = json_data
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}: Error")

    def json(self) -> dict[str, Any]:
        return self._json_data


class _FakeSession:
    def __init__(self, username: str | None = None, password: str | None = None) -> None:
        self.auth = (username, password) if username and password else None
        self._calls: list[tuple[str, dict[str, Any]]] = []

    def post(self, url: str, json: dict[str, Any], headers: dict[str, Any], timeout: int) -> _FakeResponse:
        self._calls.append(("POST", url, json))
        # Return a mock response with scan results
        return _FakeResponse(_get_mock_scan_result(json.get("target", "")))

    def get(self, url: str, params: dict[str, Any] | None = None, timeout: int = 30) -> _FakeResponse:
        self._calls.append(("GET", url, params or {}))
        return _FakeResponse({})


def _get_mock_scan_result(image_ref: str) -> dict[str, Any]:
    """Generate mock Trivy scan result based on image name."""
    if "vuln" in image_ref.lower():
        # Image with vulnerabilities
        return {
            "metadata": {
                "ImageID": "sha256:abc123",
                "SchemaVersion": 2,
                "ArtifactType": "container",
                "OS": {"Family": "debian", "Name": "debian"},
                "digest": "sha256:def456",
            },
            "Results": [
                {
                    "Target": "debian:11",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "FixedVersion": "1.1.1k",
                            "Severity": "CRITICAL",
                            "CVSS": {
                                "V3": {
                                    "BaseScore": 9.8,
                                    "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            },
                            "Title": "OpenSSL critical vulnerability",
                            "Description": "A critical flaw in OpenSSL",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                            "References": ["https://example.com/ref1"],
                        },
                        {
                            "VulnerabilityID": "CVE-2023-5678",
                            "PkgName": "curl",
                            "InstalledVersion": "7.74.0",
                            "FixedVersion": "7.75.0",
                            "Severity": "HIGH",
                            "CVSS": {
                                "V3": {
                                    "BaseScore": 7.5,
                                    "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                }
                            },
                            "Title": "curl DoS vulnerability",
                            "Description": "A DoS issue in curl",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-5678",
                            "References": ["https://example.com/ref2"],
                        },
                    ]
                }
            ]
        }
    else:
        # Image without vulnerabilities
        return {
            "metadata": {
                "ImageID": "sha256:clean123",
                "SchemaVersion": 2,
                "ArtifactType": "container",
                "OS": {"Family": "alpine", "Name": "alpine"},
                "digest": "sha256:clean456",
            },
            "Results": []
        }


@pytest.fixture
def fake_requests(monkeypatch: pytest.MonkeyPatch) -> _FakeSession:
    """Patch requests.Session with deterministic fake."""
    fake = _FakeSession()
    monkeypatch.setattr(docker_image.requests, "Session", lambda: fake)
    return fake


def _checker(
    username: str | None = None,
    password: str | None = None,
    registry: str | None = None,
    trivy_url: str | None = None,
) -> DockerImageChecker:
    return DockerImageChecker(
        username=username, password=password, registry=registry, trivy_url=trivy_url
    )


# --------------------------------------------------------------------------- #
# CVSS severity mapping (pure function tests)
# --------------------------------------------------------------------------- #


def test_severity_by_cvss_none_is_info() -> None:
    assert _severity_by_cvss(None) == "info"


def test_severity_by_cvss_below_low_is_info() -> None:
    assert _severity_by_cvss(0.0) == "info"


def test_severity_by_cvss_low_threshold() -> None:
    assert _severity_by_cvss(0.1) == "low"
    assert _severity_by_cvss(1.0) == "low"


def test_severity_by_cvss_medium_threshold() -> None:
    assert _severity_by_cvss(4.0) == "medium"
    assert _severity_by_cvss(6.0) == "medium"


def test_severity_by_cvss_high_threshold() -> None:
    assert _severity_by_cvss(7.0) == "high"
    assert _severity_by_cvss(8.5) == "high"


def test_severity_by_cvss_critical_threshold() -> None:
    assert _severity_by_cvss(9.0) == "critical"
    assert _severity_by_cvss(10.0) == "critical"


def test_cvss_thresholds_are_constants() -> None:
    assert CVSS_LOW_THRESHOLD == 0.1
    assert CVSS_MEDIUM_THRESHOLD == 4.0
    assert CVSS_HIGH_THRESHOLD == 7.0
    assert CVSS_CRITICAL_THRESHOLD == 9.0


# --------------------------------------------------------------------------- #
# SEVERITY_BY_CVSS mapping constants
# --------------------------------------------------------------------------- #


def test_severity_by_cvss_mapping_constants() -> None:
    assert SEVERITY_BY_CVSS["CRITICAL"] == "critical"
    assert SEVERITY_BY_CVSS["HIGH"] == "high"
    assert SEVERITY_BY_CVSS["MEDIUM"] == "medium"
    assert SEVERITY_BY_CVSS["LOW"] == "low"
    assert SEVERITY_BY_CVSS["UNKNOWN"] == "info"


# --------------------------------------------------------------------------- #
# Credentials contract
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no ambient DOCKER_* credentials leak in."""
    for var in (
        "DOCKER_USERNAME",
        "REGISTRY_USERNAME",
        "DOCKER_PASSWORD",
        "REGISTRY_PASSWORD",
        "DOCKER_REGISTRY",
        "REGISTRY_URL",
        "TRIVY_URL",
        "TRIVY_SERVER_URL",
    ):
        monkeypatch.delenv(var, raising=False)


def test_checker_uses_param_credentials() -> None:
    checker = DockerImageChecker(
        username=_TEST_USERNAME, password=_TEST_PASSWORD, registry=_TEST_REGISTRY
    )
    assert checker.username == _TEST_USERNAME
    assert checker.password == _TEST_PASSWORD
    assert checker.registry == _TEST_REGISTRY


def test_credentials_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCKER_USERNAME", "env-user")
    monkeypatch.setenv("DOCKER_PASSWORD", "env-pass")
    monkeypatch.setenv("DOCKER_REGISTRY", "env-registry")
    checker = DockerImageChecker()
    assert checker.username == "env-user"
    assert checker.password == "env-pass"
    assert checker.registry == "env-registry"


def test_registry_from_env_second_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REGISTRY_URL", "registry2.example.com")
    checker = DockerImageChecker()
    assert checker.registry == "registry2.example.com"


def test_trivy_url_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIVY_URL", "http://custom-trivy:8080")
    checker = DockerImageChecker()
    assert checker.trivy_url == "http://custom-trivy:8080"


def test_param_credentials_override_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCKER_USERNAME", "env-user")
    monkeypatch.setenv("DOCKER_PASSWORD", "env-pass")
    checker = DockerImageChecker(username="param-user", password="param-pass")
    assert checker.username == "param-user"
    assert checker.password == "param-pass"


def test_default_registry_when_not_set() -> None:
    checker = DockerImageChecker()
    assert checker.registry == "docker.io"


def test_default_trivy_url_when_not_set() -> None:
    checker = DockerImageChecker()
    assert checker.trivy_url == "http://localhost:8080"


# --------------------------------------------------------------------------- #
# Image scanning
# --------------------------------------------------------------------------- #


def test_scan_clean_image(fake_requests: _FakeSession) -> None:
    checker = _checker(trivy_url=_TEST_TRIVY_URL)
    finding = checker.check("nginx:latest")
    assert finding.image == "nginx:latest"
    assert finding.severity == "info"
    assert finding.vulnerability_count == 0
    assert finding.digest == "sha256:clean456"
    assert finding.error is None


def test_scan_vulnerable_image(fake_requests: _FakeSession) -> None:
    checker = _checker(trivy_url=_TEST_TRIVY_URL)
    finding = checker.check("vulnerable-app:vuln")
    assert finding.image == "vulnerable-app:vuln"
    assert finding.severity == "critical"  # worst is CVE-2023-1234 with CVSS 9.8
    assert finding.vulnerability_count == 2
    assert finding.digest == "sha256:def456"
    assert len(finding.vulnerabilities) == 2


def test_scan_uses_trivy_url(fake_requests: _FakeSession) -> None:
    checker = _checker(trivy_url="http://custom-trivy:9000")
    checker.check("test:latest")
    calls = fake_requests._calls
    assert len(calls) == 1
    assert calls[0][1].startswith("http://custom-trivy:9000")


def test_scan_with_tag_parameter(fake_requests: _FakeSession) -> None:
    checker = _checker(trivy_url=_TEST_TRIVY_URL)
    finding = checker.check("nginx", tag="1.21")
    assert finding.image == "nginx"
    assert finding.tag == "1.21"


def test_scan_error_isolated_not_raised(fake_requests: _FakeSession) -> None:
    # Make the fake session raise an error
    def _raise_error(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("Network error")

    fake_requests.post = _raise_error  # type: ignore
    checker = _checker(trivy_url=_TEST_TRIVY_URL)
    finding = checker.check("error-image:latest")
    assert finding.error is not None
    assert "RuntimeError" in finding.error or "Network error" in finding.error
    assert finding.severity == "info"  # default on error


# --------------------------------------------------------------------------- #
# Vulnerability normalization
# --------------------------------------------------------------------------- #


def test_normalize_vulnerability_with_cvss_v3() -> None:
    vuln_data = {
        "VulnerabilityID": "CVE-2023-0001",
        "PkgName": "test-pkg",
        "InstalledVersion": "1.0.0",
        "FixedVersion": "1.0.1",
        "Severity": "CRITICAL",
        "CVSS": {
            "V3": {
                "BaseScore": 9.5,
                "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        },
        "Title": "Test CVE",
        "Description": "Test description",
        "PrimaryURL": "https://test.com",
        "References": ["https://ref.com"],
    }
    normalized = _normalize_vulnerability(vuln_data)
    assert normalized["vulnerability_id"] == "CVE-2023-0001"
    assert normalized["pkg_name"] == "test-pkg"
    assert normalized["cvss_score"] == 9.5
    assert normalized["severity"] == "critical"


def test_normalize_vulnerability_falls_back_to_cvss_v2() -> None:
    vuln_data = {
        "VulnerabilityID": "CVE-2023-0002",
        "PkgName": "test-pkg2",
        "InstalledVersion": "2.0.0",
        "FixedVersion": "2.0.1",
        "Severity": "HIGH",
        "CVSS": {
            "V2": {
                "BaseScore": 7.5,
                "Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            }
        },
    }
    normalized = _normalize_vulnerability(vuln_data)
    assert normalized["cvss_score"] == 7.5
    assert normalized["severity"] == "high"


def test_normalize_vulnerability_without_cvss_uses_severity() -> None:
    vuln_data = {
        "VulnerabilityID": "CVE-2023-0003",
        "PkgName": "test-pkg3",
        "InstalledVersion": "3.0.0",
        "FixedVersion": "3.0.1",
        "Severity": "MEDIUM",
    }
    normalized = _normalize_vulnerability(vuln_data)
    assert normalized["cvss_score"] is None
    assert normalized["severity"] == "medium"


def test_normalize_vulnerability_unknown_severity_is_info() -> None:
    vuln_data = {
        "VulnerabilityID": "CVE-2023-0004",
        "PkgName": "test-pkg4",
        "InstalledVersion": "4.0.0",
        "Severity": "UNKNOWN",
    }
    normalized = _normalize_vulnerability(vuln_data)
    assert normalized["severity"] == "info"


# --------------------------------------------------------------------------- #
# Overall severity classification
# --------------------------------------------------------------------------- #


def test_classify_overall_severity_empty_is_info() -> None:
    assert _classify_overall_severity([]) == "info"


def test_classify_overall_severity_wins_worst() -> None:
    vulns = [
        {"severity": "low"},
        {"severity": "medium"},
        {"severity": "critical"},
        {"severity": "high"},
    ]
    assert _classify_overall_severity(vulns) == "critical"


def test_classify_overall_severity_all_same() -> None:
    vulns = [
        {"severity": "high"},
        {"severity": "high"},
    ]
    assert _classify_overall_severity(vulns) == "high"


def test_classify_overall_severity_mixed() -> None:
    vulns = [
        {"severity": "low"},
        {"severity": "medium"},
    ]
    assert _classify_overall_severity(vulns) == "medium"


# --------------------------------------------------------------------------- #
# Evidence building
# --------------------------------------------------------------------------- #


def test_build_evidence_groups_by_severity() -> None:
    vulns = [
        {"vulnerability_id": "CVE-1", "pkg_name": "pkg1", "installed_version": "1.0", "fixed_version": "1.1", "cvss_score": 9.0, "severity": "critical"},
        {"vulnerability_id": "CVE-2", "pkg_name": "pkg2", "installed_version": "2.0", "fixed_version": "2.1", "cvss_score": 5.0, "severity": "medium"},
    ]
    scan_result = {
        "metadata": {
            "ImageID": "sha256:test",
            "SchemaVersion": 2,
            "ArtifactType": "container",
            "OS": {"Family": "debian", "Name": "debian"},
        },
        "Results": []
    }
    evidence = _build_evidence(vulns, scan_result)
    assert "vulnerabilities_by_severity" in evidence
    assert "critical" in evidence["vulnerabilities_by_severity"]
    assert "medium" in evidence["vulnerabilities_by_severity"]
    assert len(evidence["vulnerabilities_by_severity"]["critical"]) == 1
    assert len(evidence["vulnerabilities_by_severity"]["medium"]) == 1
    assert evidence["total_count"] == 2


def test_evidence_contains_scan_metadata() -> None:
    vulns = []
    scan_result = {
        "metadata": {
            "ImageID": "sha256:abc",
            "SchemaVersion": 2,
            "ArtifactType": "container",
            "OS": {"Family": "alpine", "Name": "alpine"},
        },
        "Results": []
    }
    evidence = _build_evidence(vulns, scan_result)
    assert evidence["scan_metadata"]["image_id"] == "sha256:abc"
    assert evidence["scan_metadata"]["os"] == "alpine"


def test_evidence_no_sensitive_data() -> None:
    vulns = [
        {"vulnerability_id": "CVE-1", "pkg_name": "pkg1", "installed_version": "1.0", "fixed_version": "1.1", "cvss_score": 9.0, "severity": "critical"},
    ]
    scan_result = {"metadata": {}, "Results": []}
    evidence = _build_evidence(vulns, scan_result)
    evidence_str = str(evidence)
    # Should contain vulnerability info, not credentials or secrets
    assert "CVE-1" in evidence_str
    assert "pkg1" in evidence_str
    assert _TEST_USERNAME not in evidence_str
    assert _TEST_PASSWORD not in evidence_str


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #


def test_as_list_with_none() -> None:
    assert _as_list(None) == []


def test_as_list_with_list() -> None:
    assert _as_list([1, 2, 3]) == [1, 2, 3]


def test_as_list_with_tuple() -> None:
    assert _as_list((1, 2, 3)) == [1, 2, 3]


def test_as_list_with_set() -> None:
    assert set(_as_list({1, 2, 3})) == {1, 2, 3}


def test_as_list_with_single_value() -> None:
    assert _as_list("single") == ["single"]


# --------------------------------------------------------------------------- #
# Finding dataclass
# --------------------------------------------------------------------------- #


def test_finding_default_shape() -> None:
    finding = DockerFinding(image="test:latest")
    assert finding.image == "test:latest"
    assert finding.registry is None
    assert finding.tag is None
    assert finding.digest is None
    assert finding.severity == "info"
    assert finding.vulnerability_count == 0
    assert finding.vulnerabilities == []
    assert finding.evidence == {}
    assert finding.error is None


def test_finding_with_values() -> None:
    finding = DockerFinding(
        image="nginx:1.21",
        registry="docker.io",
        tag="1.21",
        digest="sha256:abc123",
        severity="critical",
        vulnerability_count=5,
        vulnerabilities=[{"id": "CVE-1"}],
        evidence={"total": 5},
    )
    assert finding.image == "nginx:1.21"
    assert finding.registry == "docker.io"
    assert finding.tag == "1.21"
    assert finding.severity == "critical"
    assert finding.vulnerability_count == 5
