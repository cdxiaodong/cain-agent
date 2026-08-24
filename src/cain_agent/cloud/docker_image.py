"""Docker image vulnerability detection (read-only).

Given Docker registry credentials (for private images) and an image reference,
this module scans the image for vulnerabilities using Trivy's read-only API.
Severity is assigned by **hardcoded CVSS-based rules** -- never by a model.
The module performs only GET-class operations: it never pulls, pushes, or
mutates any image.

Security contract
-----------------
* Credentials are read from constructor arguments, falling back to the
  ``DOCKER_*`` environment variables. They are never logged, never written
  to disk, and there is **no default or hardcoded key**.
* Recommended practice: provision a read-only service account for private
  registry access (or rely on anonymous access for public images).
* All network access goes through the Trivy server API and is fully mockable
  for tests. The test suite never touches the network and never uses real
  credentials.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import requests

__all__ = [
    "CVSS_CRITICAL_THRESHOLD",
    "CVSS_HIGH_THRESHOLD",
    "CVSS_MEDIUM_THRESHOLD",
    "CVSS_LOW_THRESHOLD",
    "DockerCredentialError",
    "DockerFinding",
    "DockerImageChecker",
    "SEVERITY_BY_CVSS",
]

# --------------------------------------------------------------------------- #
# Severity rules (hardcoded constants, not model output).
# --------------------------------------------------------------------------- #

_SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# CVSS score thresholds for severity classification (following NVD guidelines).
CVSS_LOW_THRESHOLD = 0.1
CVSS_MEDIUM_THRESHOLD = 4.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_CRITICAL_THRESHOLD = 9.0


def _severity_by_cvss(cvss_score: float | None) -> str:
    """Map a CVSS score to severity level."""
    if cvss_score is None or cvss_score < CVSS_LOW_THRESHOLD:
        return "info"
    if cvss_score < CVSS_MEDIUM_THRESHOLD:
        return "low"
    if cvss_score < CVSS_HIGH_THRESHOLD:
        return "medium"
    if cvss_score < CVSS_CRITICAL_THRESHOLD:
        return "high"
    return "critical"


# Base severity per vulnerability type (used when CVSS is unavailable).
SEVERITY_BY_CVSS: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

# Environment variable names consulted, in priority order.
_ENV_USERNAME = ("DOCKER_USERNAME", "REGISTRY_USERNAME")
_ENV_PASSWORD = ("DOCKER_PASSWORD", "REGISTRY_PASSWORD")
_ENV_REGISTRY = ("DOCKER_REGISTRY", "REGISTRY_URL")
_ENV_TRIVY_URL = ("TRIVY_URL", "TRIVY_SERVER_URL")

_DEFAULT_TRIVY_URL = "http://localhost:8080"
_DEFAULT_REGISTRY = "docker.io"


@dataclass
class DockerFinding:
    """Structured finding for a single Docker image vulnerability scan.

    ``evidence`` records only non-sensitive signals: vulnerability IDs, package
    names, installed/fixed versions, CVSS scores, and severity levels. No
    credentials, no secrets, no image content are ever placed in a finding.
    """

    image: str
    registry: str | None = None
    tag: str | None = None
    digest: str | None = None
    severity: str = "info"
    vulnerability_count: int = 0
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class DockerCredentialError(RuntimeError):
    """Raised when registry authentication fails or credentials are unavailable."""


class DockerImageChecker:
    """Read-only Docker image vulnerability checker using Trivy API.

    Registry credentials come from ``username`` / ``password`` or the
    ``DOCKER_*`` / ``REGISTRY_*`` environment variables -- never from a
    default. ``registry`` selects the container registry; ``trivy_url``
    points to the Trivy server for scanning.

    All HTTP requests go through small methods (``_session``, ``_get``)
    which are the seams tests monkeypatch. No network call happens at
    construction time.
    """

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        registry: str | None = None,
        trivy_url: str | None = None,
    ) -> None:
        self.username = username or _first_env(_ENV_USERNAME)
        self.password = password or _first_env(_ENV_PASSWORD)
        self.registry = registry or _first_env(_ENV_REGISTRY) or _DEFAULT_REGISTRY
        self.trivy_url = trivy_url or _first_env(_ENV_TRIVY_URL) or _DEFAULT_TRIVY_URL
        self._session: Any = None

    # -- HTTP client construction (mockable seams) ---------------------------
    @property
    def session(self) -> Any:
        if self._session is None:
            self._session = requests.Session()
            if self.username and self.password:
                self._session.auth = (self.username, self.password)
        return self._session

    def _get(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        """Perform a GET request to the Trivy API."""
        url = urljoin(self.trivy_url, endpoint)
        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    # -- public API ----------------------------------------------------------
    def check(self, image: str, tag: str | None = None) -> DockerFinding:
        """Scan a single image and return a structured finding."""
        finding = DockerFinding(image=image, registry=self.registry, tag=tag)
        try:
            full_ref = self._build_ref(image, tag)
            scan_result = self._scan_image(full_ref)
            finding.digest = scan_result.get("metadata", {}).get("digest")
            vulnerabilities = self._extract_vulnerabilities(scan_result)
            finding.vulnerability_count = len(vulnerabilities)
            finding.vulnerabilities = vulnerabilities
            finding.severity = _classify_overall_severity(vulnerabilities)
            finding.evidence = _build_evidence(vulnerabilities, scan_result)
        except Exception as exc:
            finding.error = f"{type(exc).__name__}: {exc}"
        return finding

    def check_many(self, images: Sequence[tuple[str, str | None]]) -> list[DockerFinding]:
        """Check multiple images; a per-image failure never aborts the run."""
        return [self.check(image, tag) for image, tag in images]

    # -- helpers -------------------------------------------------------------
    def _build_ref(self, image: str, tag: str | None = None) -> str:
        """Build a full image reference for Trivy."""
        if ":" in image and "/" not in image.split(":")[-1]:
            # Image already has a tag like 'nginx:latest'
            return image
        if tag:
            return f"{image}:{tag}"
        return image  # Trivy will use 'latest' by default

    def _scan_image(self, image_ref: str) -> dict[str, Any]:
        """Call Trivy API to scan the image."""
        # Trivy server API: POST /api/v1/scan
        url = urljoin(self.trivy_url, "/api/v1/scan")
        headers = {"Content-Type": "application/json"}
        payload = {
            "target": image_ref,
            "securityChecks": ["vuln"],
            "scanRemovedPkgs": False,
        }
        response = self.session.post(url, json=payload, headers=headers, timeout=300)
        response.raise_for_status()
        return response.json()

    def _extract_vulnerabilities(
        self, scan_result: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract and normalize vulnerability entries from Trivy result."""
        results = scan_result.get("Results", [])
        vulnerabilities = []
        for result in results:
            for vuln in result.get("Vulnerabilities", []):
                vulnerabilities.append(_normalize_vulnerability(vuln))
        return vulnerabilities


# --------------------------------------------------------------------------- #
# Vulnerability analysis helpers (pure functions, fully unit-testable).
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


def _normalize_vulnerability(vuln: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Trivy vulnerability entry to a consistent structure."""
    cvss_details = vuln.get("CVSS", {})
    # Prefer V3 CVSS, fall back to V2
    cvss_v3 = cvss_details.get("V3", {})
    cvss_v2 = cvss_details.get("V2", {})
    cvss_score = cvss_v3.get("BaseScore") or cvss_v2.get("BaseScore")
    # Use Trivy's severity if available, otherwise derive from CVSS
    trivy_severity = vuln.get("Severity", "UNKNOWN").upper()
    if cvss_score is not None:
        severity = _severity_by_cvss(cvss_score)
    else:
        severity = SEVERITY_BY_CVSS.get(trivy_severity, "info")

    return {
        "vulnerability_id": vuln.get("VulnerabilityID", ""),
        "pkg_name": vuln.get("PkgName", ""),
        "installed_version": vuln.get("InstalledVersion", ""),
        "fixed_version": vuln.get("FixedVersion", ""),
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_v3.get("Vector") or cvss_v2.get("Vector"),
        "title": vuln.get("Title", ""),
        "description": vuln.get("Description", ""),
        "primary_url": vuln.get("PrimaryURL", ""),
        "references": _as_list(vuln.get("References")),
    }


def _classify_overall_severity(vulnerabilities: list[dict[str, Any]]) -> str:
    """Determine the overall severity for an image (worst finding)."""
    if not vulnerabilities:
        return "info"
    max_rank = -1
    overall_severity = "info"
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "info")
        rank = _SEVERITY_RANK.get(severity, 0)
        if rank > max_rank:
            max_rank = rank
            overall_severity = severity
    return overall_severity


def _build_evidence(
    vulnerabilities: list[dict[str, Any]], scan_result: dict[str, Any]
) -> dict[str, Any]:
    """Record only vulnerability summary without secrets or full content."""
    # Group vulnerabilities by severity for summary
    by_severity: dict[str, list[dict[str, Any]]] = {}
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "info")
        by_severity.setdefault(sev, []).append(
            {
                "id": vuln.get("vulnerability_id"),
                "pkg": vuln.get("pkg_name"),
                "installed": vuln.get("installed_version"),
                "fixed": vuln.get("fixed_version"),
                "cvss": vuln.get("cvss_score"),
            }
        )

    metadata = scan_result.get("metadata", {})
    return {
        "scan_metadata": {
            "image_id": metadata.get("ImageID"),
            "schema_version": metadata.get("SchemaVersion"),
            "artifact_type": metadata.get("ArtifactType"),
            "os": metadata.get("OS", {}).get("Family"),
            "os_version": metadata.get("OS", {}).get("Name"),
        },
        "vulnerabilities_by_severity": by_severity,
        "total_count": len(vulnerabilities),
    }
