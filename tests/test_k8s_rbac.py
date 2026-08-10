"""Tests for the Kubernetes RBAC privilege escalation checker.

Every kubernetes client call is mocked: the suite never touches the network and
never uses real credentials. Fake classes mirror the real kubernetes surface we
depend on (``ApiClient``, ``RbacAuthorizationV1Api``, ``CoreV1Api`` and the
``list_cluster_role``, ``list_namespaced_role``, ``list_cluster_role_binding``,
``list_namespaced_role_binding`` methods and their result objects).
"""

from __future__ import annotations

from typing import Any

import pytest

from cain_agent.cloud import k8s_rbac
from cain_agent.cloud.k8s_rbac import (
    K8sCredentialError,
    K8sRbacChecker,
    K8sRbacFinding,
    PRIVILEGE_RULES,
    SEVERITY_BY_PATH,
    _analyze_role_rules,
    _severity_for_paths,
)

# Test-only kubeconfig path; never valid, never read (k8s client is mocked).
_FAKE_KUBECONFIG = "/tmp/test-kubeconfig-fake.yaml"


# --------------------------------------------------------------------------- #
# Fake kubernetes surface
# --------------------------------------------------------------------------- #


class _FakeMetadata:
    def __init__(self, name: str, namespace: str | None = None) -> None:
        self.name = name
        self.namespace = namespace


class _FakeRule:
    def __init__(self, resources: list[str], verbs: list[str]) -> None:
        self.resources = resources
        self.verbs = verbs


class _FakeRoleRef:
    def __init__(self, kind: str, name: str) -> None:
        self.kind = kind
        self.name = name


class _FakeSubject:
    def __init__(self, kind: str, name: str, namespace: str | None = None) -> None:
        self.kind = kind
        self.name = name
        self.namespace = namespace


class _FakeClusterRole:
    def __init__(self, name: str, rules: list[_FakeRule]) -> None:
        self.metadata = _FakeMetadata(name)
        self.rules = rules


class _FakeRole:
    def __init__(self, name: str, namespace: str, rules: list[_FakeRule]) -> None:
        self.metadata = _FakeMetadata(name, namespace)
        self.rules = rules


class _FakeClusterRoleBinding:
    def __init__(self, name: str, role_ref: _FakeRoleRef, subjects: list[_FakeSubject]) -> None:
        self.metadata = _FakeMetadata(name)
        self.role_ref = role_ref
        self.subjects = subjects


class _FakeRoleBinding:
    def __init__(
        self, name: str, namespace: str, role_ref: _FakeRoleRef, subjects: list[_FakeSubject]
    ) -> None:
        self.metadata = _FakeMetadata(name, namespace)
        self.role_ref = role_ref
        self.subjects = subjects


class _FakeResourceList:
    def __init__(self, items: list[Any]) -> None:
        self.items = items


class _FakeNamespace:
    def __init__(self, name: str) -> None:
        self.metadata = _FakeMetadata(name)


# Module-global state populated by fixtures so fake classes can resolve per-test configs.
_K8S_STATE: dict[str, Any] = {
    "cluster_roles": [],
    "roles": {},
    "cluster_role_bindings": [],
    "role_bindings": {},
    "namespaces": [],
}


class _FakeRbacApi:
    def list_cluster_role(self, **_: Any) -> _FakeResourceList:
        return _FakeResourceList(_K8S_STATE["cluster_roles"])

    def list_namespaced_role(self, namespace: str, **_: Any) -> _FakeResourceList:
        return _FakeResourceList(_K8S_STATE["roles"].get(namespace, []))

    def list_cluster_role_binding(self, **_: Any) -> _FakeResourceList:
        return _FakeResourceList(_K8S_STATE["cluster_role_bindings"])

    def list_namespaced_role_binding(self, namespace: str, **_: Any) -> _FakeResourceList:
        return _FakeResourceList(_K8S_STATE["role_bindings"].get(namespace, []))


class _FakeCoreApi:
    def list_namespace(self, **_: Any) -> _FakeResourceList:
        return _FakeResourceList(_K8S_STATE["namespaces"])


class _FakeApiClient:
    pass


@pytest.fixture
def fake_k8s(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Patch the kubernetes seams referenced by k8s_rbac with deterministic fakes."""
    _K8S_STATE.update({
        "cluster_roles": [],
        "roles": {},
        "cluster_role_bindings": [],
        "role_bindings": {},
        "namespaces": [],
    })
    monkeypatch.setattr(k8s_rbac.kubernetes.client, "ApiClient", _FakeApiClient)
    monkeypatch.setattr(k8s_rbac.kubernetes.client, "RbacAuthorizationV1Api", lambda _: _FakeRbacApi())
    monkeypatch.setattr(k8s_rbac.kubernetes.client, "CoreV1Api", lambda _: _FakeCoreApi())
    # Mock config.load_kube_config to do nothing
    monkeypatch.setattr(k8s_rbac.config, "load_kube_config", lambda **_: None)
    # Mock os.path.exists to return True for fake kubeconfig
    monkeypatch.setattr(k8s_rbac.os.path, "exists", lambda _: True)
    return _K8S_STATE


def _reset_state() -> None:
    _K8S_STATE.update({
        "cluster_roles": [],
        "roles": {},
        "cluster_role_bindings": [],
        "role_bindings": {},
        "namespaces": [],
    })


def _checker(kubeconfig_path: str = _FAKE_KUBECONFIG) -> K8sRbacChecker:
    return K8sRbacChecker(kubeconfig_path=kubeconfig_path)


# --------------------------------------------------------------------------- #
# Credentials contract
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no ambient KUBECONFIG leaks in from the real environment."""
    monkeypatch.delenv("KUBECONFIG", raising=False)


def test_checker_requires_kubeconfig_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(k8s_rbac.os.path, "exists", lambda _: False)
    monkeypatch.delenv("KUBECONFIG", raising=False)
    with pytest.raises(K8sCredentialError, match="Kubeconfig not found"):
        K8sRbacChecker()


def test_kubeconfig_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBECONFIG", "/env/config.yaml")
    monkeypatch.setattr(k8s_rbac.os.path, "exists", lambda _: True)
    monkeypatch.setattr(k8s_rbac.config, "load_kube_config", lambda **_: None)
    checker = K8sRbacChecker()
    assert checker.kubeconfig_path == "/env/config.yaml"


def test_param_kubeconfig_takes_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBECONFIG", "/env/config.yaml")
    monkeypatch.setattr(k8s_rbac.os.path, "exists", lambda _: True)
    monkeypatch.setattr(k8s_rbac.config, "load_kube_config", lambda **_: None)
    checker = K8sRbacChecker(kubeconfig_path="/param/config.yaml")
    assert checker.kubeconfig_path == "/param/config.yaml"


# --------------------------------------------------------------------------- #
# Rule matching (pure function tests)
# --------------------------------------------------------------------------- #


def test_match_wildcard_permission() -> None:
    rules = [_FakeRule(["*"], ["*"])]
    paths = _analyze_role_rules(rules)
    # Wildcard matches many privilege paths
    assert "wildcard_permission" in paths
    assert len(paths) > 0


def test_match_create_pods() -> None:
    rules = [_FakeRule(["pods"], ["create"])]
    paths = _analyze_role_rules(rules)
    assert "create_pods" in paths


def test_match_pods_exec_subresource() -> None:
    # Direct subresource match
    rules = [_FakeRule(["pods/exec"], ["create"])]
    paths = _analyze_role_rules(rules)
    assert "pods_exec" in paths


def test_match_secrets_access() -> None:
    rules = [_FakeRule(["secrets"], ["get", "list"])]
    paths = _analyze_role_rules(rules)
    assert "secrets_access" in paths


def test_match_rbac_manage_roles() -> None:
    rules = [_FakeRule(["roles"], ["create", "delete"])]
    paths = _analyze_role_rules(rules)
    assert "rbac_manage" in paths


def test_match_specific_resource_and_verb() -> None:
    # Test that specific combinations match their intended paths
    rules = [
        _FakeRule(["pods"], ["create"]),
        _FakeRule(["secrets"], ["get"]),
    ]
    paths = _analyze_role_rules(rules)
    assert "create_pods" in paths
    assert "secrets_access" in paths


def test_no_match_for_safe_rules() -> None:
    rules = [_FakeRule(["configmaps"], ["get", "list"])]
    paths = _analyze_role_rules(rules)
    assert len(paths) == 0


def test_multiple_rules_aggregate_paths() -> None:
    rules = [
        _FakeRule(["pods"], ["create"]),
        _FakeRule(["secrets"], ["get"]),
        _FakeRule(["roles"], ["create"]),
    ]
    paths = _analyze_role_rules(rules)
    assert "create_pods" in paths
    assert "secrets_access" in paths
    assert "rbac_manage" in paths


# --------------------------------------------------------------------------- #
# Severity classification
# --------------------------------------------------------------------------- #


def test_severity_info_for_no_paths() -> None:
    assert _severity_for_paths([], is_cluster_scope=False) == "info"


def test_severity_by_path_mapping() -> None:
    assert _severity_for_paths(["wildcard_permission"], is_cluster_scope=False) == "critical"
    assert _severity_for_paths(["rbac_manage"], is_cluster_scope=False) == "critical"
    assert _severity_for_paths(["create_pods"], is_cluster_scope=False) == "high"
    assert _severity_for_paths(["pods_portforward"], is_cluster_scope=False) == "medium"


def test_severity_escalates_for_rbac_manage_cluster_scope() -> None:
    # Only rbac_manage escalates to critical for cluster scope
    assert _severity_for_paths(["rbac_manage"], is_cluster_scope=True) == "critical"


def test_worst_severity_wins() -> None:
    assert _severity_for_paths(["pods_portforward", "secrets_access"], is_cluster_scope=False) == "high"


# --------------------------------------------------------------------------- #
# ClusterRole analysis
# --------------------------------------------------------------------------- #


def test_check_clusterrole_with_no_privilege_paths(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["cluster_roles"] = [
        _FakeClusterRole("safe-role", [_FakeRule(["configmaps"], ["get"])]),
    ]
    findings = _checker().check_all()
    assert len(findings) == 1
    assert findings[0].resource_type == "ClusterRole"
    assert findings[0].resource_name == "safe-role"
    assert findings[0].severity == "info"


def test_check_clusterrole_with_wildcard_permission(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["cluster_roles"] = [
        _FakeClusterRole("dangerous-role", [_FakeRule(["*"], ["*"])]),
    ]
    findings = _checker().check_all()
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "wildcard_permission" in findings[0].privilege_paths


def test_check_clusterrole_with_multiple_privilege_paths(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["cluster_roles"] = [
        _FakeClusterRole(
            "multi-path-role",
            [_FakeRule(["pods"], ["create"]), _FakeRule(["secrets"], ["get", "list"])],
        ),
    ]
    findings = _checker().check_all()
    assert len(findings) == 1
    assert "create_pods" in findings[0].privilege_paths
    assert "secrets_access" in findings[0].privilege_paths
    assert findings[0].severity == "high"


def test_check_clusterrole_list_error_isolated(fake_k8s: Any) -> None:
    _reset_state()
    # Simulate list failure
    def _raise_error(**_: Any) -> None:
        raise RuntimeError("API server unavailable")

    fake_k8s["cluster_roles"] = []
    checker = _checker()
    checker.rbac_api.list_cluster_role = _raise_error  # type: ignore
    
    findings = checker._check_clusterroles()
    assert len(findings) == 1
    assert findings[0].error is not None
    assert "API server unavailable" in findings[0].error


# --------------------------------------------------------------------------- #
# Role analysis (namespace-scoped)
# --------------------------------------------------------------------------- #


def test_check_role_in_namespace(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["namespaces"] = [_FakeNamespace("default")]
    _K8S_STATE["roles"] = {
        "default": [_FakeRole("ns-role", "default", [_FakeRule(["pods"], ["create"])])]
    }
    findings = _checker().check_all()
    role_findings = [f for f in findings if f.resource_type == "Role"]
    assert len(role_findings) == 1
    assert role_findings[0].resource_name == "ns-role"
    assert role_findings[0].namespace == "default"
    assert "create_pods" in role_findings[0].privilege_paths


def test_check_role_multiple_namespaces(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["namespaces"] = [_FakeNamespace("ns1"), _FakeNamespace("ns2")]
    _K8S_STATE["roles"] = {
        "ns1": [_FakeRole("role1", "ns1", [_FakeRule(["secrets"], ["get"])])],
        "ns2": [_FakeRole("role2", "ns2", [_FakeRule(["pods/exec"], ["create"])])],
    }
    findings = _checker().check_all()
    role_findings = [f for f in findings if f.resource_type == "Role"]
    assert len(role_findings) == 2
    by_name = {f.resource_name: f for f in role_findings}
    assert "secrets_access" in by_name["role1"].privilege_paths
    assert "pods_exec" in by_name["role2"].privilege_paths


# --------------------------------------------------------------------------- #
# ClusterRoleBinding analysis
# --------------------------------------------------------------------------- #


def test_check_clusterrolebinding_dangerous_role(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["cluster_roles"] = [
        _FakeClusterRole("admin", [_FakeRule(["*"], ["*"])]),
    ]
    _K8S_STATE["cluster_role_bindings"] = [
        _FakeClusterRoleBinding(
            "admin-binding",
            _FakeRoleRef("ClusterRole", "admin"),
            [_FakeSubject("User", "attacker")],
        ),
    ]
    findings = _checker().check_all()
    binding_findings = [f for f in findings if f.resource_type == "ClusterRoleBinding"]
    assert len(binding_findings) == 1
    # The admin role itself has wildcard permissions, so it's critical
    assert binding_findings[0].severity == "critical"


def test_check_clusterrolebinding_cluster_admin_role(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["cluster_roles"] = [
        _FakeClusterRole("cluster-admin", [_FakeRule(["*"], ["*"])]),
    ]
    _K8S_STATE["cluster_role_bindings"] = [
        _FakeClusterRoleBinding(
            "cluster-admin-binding",
            _FakeRoleRef("ClusterRole", "cluster-admin"),
            [_FakeSubject("User", "attacker")],
        ),
    ]
    findings = _checker().check_all()
    binding_findings = [f for f in findings if f.resource_type == "ClusterRoleBinding"]
    assert len(binding_findings) == 1
    assert binding_findings[0].severity == "critical"  # cluster-admin is in dangerous_roles list


def test_check_clusterrolebinding_safe_role(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["cluster_roles"] = [
        _FakeClusterRole("viewer", [_FakeRule(["configmaps"], ["get"])]),
    ]
    _K8S_STATE["cluster_role_bindings"] = [
        _FakeClusterRoleBinding(
            "viewer-binding",
            _FakeRoleRef("ClusterRole", "viewer"),
            [_FakeSubject("User", "normal-user")],
        ),
    ]
    findings = _checker().check_all()
    binding_findings = [f for f in findings if f.resource_type == "ClusterRoleBinding"]
    assert len(binding_findings) == 1
    assert binding_findings[0].severity == "info"


# --------------------------------------------------------------------------- #
# RoleBinding analysis (namespace-scoped)
# --------------------------------------------------------------------------- #


def test_check_rolebinding_dangerous_role(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["namespaces"] = [_FakeNamespace("default")]
    _K8S_STATE["roles"] = {
        "default": [_FakeRole("cluster-admin", "default", [_FakeRule(["*"], ["*"])])]
    }
    _K8S_STATE["role_bindings"] = {
        "default": [
            _FakeRoleBinding(
                "cluster-admin-binding",
                "default",
                _FakeRoleRef("Role", "cluster-admin"),
                [_FakeSubject("ServiceAccount", "attacker-sa")],
            )
        ]
    }
    findings = _checker().check_all()
    binding_findings = [f for f in findings if f.resource_type == "RoleBinding"]
    assert len(binding_findings) == 1
    # cluster-admin is in dangerous_roles, namespace-scoped Role with cluster-admin is still critical
    assert binding_findings[0].severity == "critical"
    assert binding_findings[0].namespace == "default"


# --------------------------------------------------------------------------- #
# check_all aggregates all resource types
# --------------------------------------------------------------------------- #


def test_check_all_returns_all_resource_types(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["namespaces"] = [_FakeNamespace("default")]
    _K8S_STATE["cluster_roles"] = [_FakeClusterRole("cr1", [_FakeRule(["pods"], ["create"])])]
    _K8S_STATE["roles"] = {"default": [_FakeRole("r1", "default", [_FakeRule(["secrets"], ["get"])]),]
}
    _K8S_STATE["cluster_role_bindings"] = [
        _FakeClusterRoleBinding("crb1", _FakeRoleRef("ClusterRole", "cr1"), [])
    ]
    _K8S_STATE["role_bindings"] = {
        "default": [_FakeRoleBinding("rb1", "default", _FakeRoleRef("Role", "r1"), [])]
    }
    findings = _checker().check_all()
    resource_types = {f.resource_type for f in findings}
    assert resource_types == {"ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"}
    assert len(findings) == 4


# --------------------------------------------------------------------------- #
# Evidence hygiene - no secrets
# --------------------------------------------------------------------------- #


def test_evidence_contains_no_credentials(fake_k8s: Any) -> None:
    _reset_state()
    _K8S_STATE["cluster_roles"] = [
        _FakeClusterRole("test-role", [_FakeRule(["pods"], ["create"])])
    ]
    findings = _checker().check_all()
    evidence_str = str(findings[0].evidence)
    # Evidence should contain rule info, not credentials
    assert "pods" in evidence_str
    assert "create" in evidence_str
    assert "create_pods" in evidence_str


# --------------------------------------------------------------------------- #
# Constants are hardcoded
# --------------------------------------------------------------------------- #


def test_privilege_rules_are_module_constants() -> None:
    assert len(PRIVILEGE_RULES) >= 10
    # Check a few known rules exist
    rule_paths = {r["path"] for r in PRIVILEGE_RULES}
    assert "wildcard_permission" in rule_paths
    assert "create_pods" in rule_paths
    assert "secrets_access" in rule_paths
    assert "rbac_manage" in rule_paths


def test_severity_by_path_are_module_constants() -> None:
    assert "wildcard_permission" in SEVERITY_BY_PATH
    assert SEVERITY_BY_PATH["wildcard_permission"] == "critical"
    assert "create_pods" in SEVERITY_BY_PATH
    assert SEVERITY_BY_PATH["create_pods"] == "high"


def test_finding_default_shape() -> None:
    finding = K8sRbacFinding(resource_type="Role", resource_name="test")
    assert finding.namespace is None
    assert finding.severity == "info"
    assert finding.privilege_paths == []
    assert finding.evidence == {}
    assert finding.error is None
