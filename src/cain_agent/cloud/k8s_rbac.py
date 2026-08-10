"""Kubernetes RBAC privilege escalation analysis (read-only).

Given kubeconfig path or in-cluster config, this module enumerates RBAC
resources (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings) and
analyzes each for potential privilege escalation paths. Severity is assigned
by **hardcoded rules** -- never by a model. The module performs only GET-class
operations: it never writes, deletes, or mutates any resource.

Security contract
-----------------
* Credentials are read from kubeconfig file (default ~/.kube/config) or
  in-cluster service account token. They are never logged, never written to
  disk, and there is **no default or hardcoded credential**.
* Recommended practice: provision a service account with read-only RBAC
  permissions (get, list, watch on rbac resources) and use its kubeconfig.
* All network access goes through the official ``kubernetes`` client library
  and is fully mockable for tests. The test suite never touches the network
  and never uses real credentials.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

try:
    import kubernetes.client
    from kubernetes import config
except ImportError:
    kubernetes = None  # type: ignore
    config = None  # type: ignore

__all__ = [
    "K8sCredentialError",
    "K8sRbacChecker",
    "K8sRbacFinding",
    "PRIVILEGE_RULES",
    "SEVERITY_BY_PATH",
]

# --------------------------------------------------------------------------- #
# Severity rules (hardcoded constants, not model output).
# --------------------------------------------------------------------------- #

_SEVERITY_RANK: dict[str, int] = {"info": 0, "medium": 1, "high": 2, "critical": 3}

# Base severity per privilege escalation path. Some paths are upgraded at
# classify-time based on additional context (e.g., cluster scope).
SEVERITY_BY_PATH: dict[str, str] = {
    "create_pods": "high",
    "pods_exec": "high",
    "pods_portforward": "medium",
    "secrets_access": "high",
    "rbac_manage": "critical",
    "nodes_proxy": "critical",
    "wildcard_permission": "critical",
    "service_account_token": "high",
    "daemonset_deploy": "high",
}

# Privilege escalation rules: each maps a resource + verb pattern to a
# canonical path name and description. Rules are evaluated in order.
PRIVILEGE_RULES: list[dict[str, Any]] = [
    {
        "path": "wildcard_permission",
        "resource": "*",
        "verbs": ["*"],
        "description": "Wildcard permission on all resources",
    },
    {
        "path": "rbac_manage",
        "resource": "roles",
        "verbs": ["create", "update", "patch", "delete"],
        "description": "Can create or modify Roles (RBAC takeover)",
    },
    {
        "path": "rbac_manage",
        "resource": "clusterroles",
        "verbs": ["create", "update", "patch", "delete"],
        "description": "Can create or modify ClusterRoles (RBAC takeover)",
    },
    {
        "path": "rbac_manage",
        "resource": "rolebindings",
        "verbs": ["create", "update", "patch", "delete"],
        "description": "Can create or modify RoleBindings (privilege assignment)",
    },
    {
        "path": "rbac_manage",
        "resource": "clusterrolebindings",
        "verbs": ["create", "update", "patch", "delete"],
        "description": "Can create or modify ClusterRoleBindings (cluster admin)",
    },
    {
        "path": "create_pods",
        "resource": "pods",
        "verbs": ["create"],
        "description": "Can create pods (potential privilege escalation via hostPath/hostNetwork)",
    },
    {
        "path": "pods_exec",
        "resource": "pods/exec",
        "verbs": ["create"],
        "description": "Can exec into pods (command execution in cluster)",
    },
    {
        "path": "pods_portforward",
        "resource": "pods/portforward",
        "verbs": ["create"],
        "description": "Can port-forward to pods (network access to cluster services)",
    },
    {
        "path": "secrets_access",
        "resource": "secrets",
        "verbs": ["get", "list", "watch"],
        "description": "Can read secrets (includes service account tokens)",
    },
    {
        "path": "service_account_token",
        "resource": "serviceaccounts/token",
        "verbs": ["create"],
        "description": "Can create service account tokens (token theft)",
    },
    {
        "path": "nodes_proxy",
        "resource": "nodes/proxy",
        "verbs": ["*"],
        "description": "Can access Kubelet API via nodes/proxy (node takeover)",
    },
    {
        "path": "daemonset_deploy",
        "resource": "daemonsets",
        "verbs": ["create"],
        "description": "Can create DaemonSets (cluster-wide code execution)",
    },
]

# Environment variable for kubeconfig path
_ENV_KUBECONFIG = ("KUBECONFIG",)

_DEFAULT_KUBECONFIG = os.path.expanduser("~/.kube/config")


@dataclass
class K8sRbacFinding:
    """Structured finding for a single RBAC resource privilege analysis.

    ``evidence`` records only non-sensitive signals: the resource type,
    namespace (if applicable), matched privilege paths, and the rules that
    triggered them. No credentials, no secret tokens are ever placed in a
    finding.
    """

    resource_type: str  # "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"
    resource_name: str
    namespace: str | None = None
    severity: str = "info"
    privilege_paths: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class K8sCredentialError(RuntimeError):
    """Raised when no kubeconfig or in-cluster config is available."""


class K8sRbacChecker:
    """Read-only Kubernetes RBAC privilege escalation checker.

    Configuration comes from ``kubeconfig_path`` (defaults to ~/.kube/config
    or KUBECONFIG env var) or in-cluster service account. The checker
    enumerates all RBAC resources in the cluster and analyzes each for
    potential privilege escalation paths based on hardcoded rules.

    All kubernetes client construction goes through small methods
    (``_api_client``, ``_rbac_api``, ``_get_roles``, etc.) which are the
    seams tests monkeypatch. No network call happens at construction time.
    """

    def __init__(
        self,
        kubeconfig_path: str | None = None,
        in_cluster: bool = False,
    ) -> None:
        if kubernetes is None:
            raise ImportError("kubernetes package is required for K8sRbacChecker")

        self.in_cluster = in_cluster
        self.kubeconfig_path = kubeconfig_path or _first_env(_ENV_KUBECONFIG) or _DEFAULT_KUBECONFIG

        if in_cluster:
            try:
                config.load_incluster_config()
            except Exception as exc:
                raise K8sCredentialError(
                    f"In-cluster config load failed: {exc}. Ensure running inside "
                    "a Kubernetes pod with service account mounted."
                ) from exc
        else:
            if not os.path.exists(self.kubeconfig_path):
                raise K8sCredentialError(
                    f"Kubeconfig not found: {self.kubeconfig_path}. Please provide "
                    "a valid kubeconfig path or run inside a Kubernetes cluster."
                )
            try:
                config.load_kube_config(config_file=self.kubeconfig_path)
            except Exception as exc:
                raise K8sCredentialError(
                    f"Failed to load kubeconfig from {self.kubeconfig_path}: {exc}"
                ) from exc

        self._api_client: kubernetes.client.ApiClient | None = None
        self._rbac_api: kubernetes.client.RbacAuthorizationV1Api | None = None
        self._core_api: kubernetes.client.CoreV1Api | None = None

    # -- kubernetes client construction (mockable seams) --------------------
    @property
    def api_client(self) -> kubernetes.client.ApiClient:
        if self._api_client is None:
            self._api_client = kubernetes.client.ApiClient()
        return self._api_client

    @property
    def rbac_api(self) -> kubernetes.client.RbacAuthorizationV1Api:
        if self._rbac_api is None:
            self._rbac_api = kubernetes.client.RbacAuthorizationV1Api(self.api_client)
        return self._rbac_api

    @property
    def core_api(self) -> kubernetes.client.CoreV1Api:
        if self._core_api is None:
            self._core_api = kubernetes.client.CoreV1Api(self.api_client)
        return self._core_api

    # -- public API ---------------------------------------------------------
    def check_all(self) -> list[K8sRbacFinding]:
        """Check all RBAC resources for privilege escalation paths."""
        findings: list[K8sRbacFinding] = []

        # Check ClusterRoles (cluster-scoped)
        findings.extend(self._check_clusterroles())

        # Check Roles (namespace-scoped)
        findings.extend(self._check_roles())

        # Check ClusterRoleBindings (cluster-scoped)
        findings.extend(self._check_clusterrolebindings())

        # Check RoleBindings (namespace-scoped)
        findings.extend(self._check_rolebindings())

        return findings

    def _check_clusterroles(self) -> list[K8sRbacFinding]:
        """Analyze all ClusterRoles for privilege escalation."""
        findings: list[K8sRbacFinding] = []
        try:
            clusterroles = self.rbac_api.list_cluster_role()
        except Exception as exc:
            findings.append(
                K8sRbacFinding(
                    resource_type="ClusterRole",
                    resource_name="_list_error",
                    error=f"Failed to list ClusterRoles: {type(exc).__name__}: {exc}",
                )
            )
            return findings

        for cr in clusterroles.items:
            finding = self._check_role_like(cr, "ClusterRole", namespace=None)
            findings.append(finding)

        return findings

    def _check_roles(self) -> list[K8sRbacFinding]:
        """Analyze all Roles in all namespaces for privilege escalation."""
        findings: list[K8sRbacFinding] = []
        try:
            namespaces = self.core_api.list_namespace()
        except Exception as exc:
            findings.append(
                K8sRbacFinding(
                    resource_type="Role",
                    resource_name="_list_namespaces_error",
                    error=f"Failed to list namespaces: {type(exc).__name__}: {exc}",
                )
            )
            return findings

        for ns in namespaces.items:
            ns_name = ns.metadata.name
            try:
                roles = self.rbac_api.list_namespaced_role(ns_name)
            except Exception as exc:
                findings.append(
                    K8sRbacFinding(
                        resource_type="Role",
                        resource_name=f"{ns_name}/_list_error",
                        namespace=ns_name,
                        error=f"Failed to list Roles in {ns_name}: {type(exc).__name__}: {exc}",
                    )
                )
                continue

            for role in roles.items:
                finding = self._check_role_like(role, "Role", namespace=ns_name)
                findings.append(finding)

        return findings

    def _check_clusterrolebindings(self) -> list[K8sRbacFinding]:
        """Analyze all ClusterRoleBindings for privilege escalation."""
        findings: list[K8sRbacFinding] = []
        try:
            bindings = self.rbac_api.list_cluster_role_binding()
        except Exception as exc:
            findings.append(
                K8sRbacFinding(
                    resource_type="ClusterRoleBinding",
                    resource_name="_list_error",
                    error=f"Failed to list ClusterRoleBindings: {type(exc).__name__}: {exc}",
                )
            )
            return findings

        for crb in bindings.items:
            finding = self._check_binding_like(crb, "ClusterRoleBinding", namespace=None)
            findings.append(finding)

        return findings

    def _check_rolebindings(self) -> list[K8sRbacFinding]:
        """Analyze all RoleBindings in all namespaces for privilege escalation."""
        findings: list[K8sRbacFinding] = []
        try:
            namespaces = self.core_api.list_namespace()
        except Exception as exc:
            findings.append(
                K8sRbacFinding(
                    resource_type="RoleBinding",
                    resource_name="_list_namespaces_error",
                    error=f"Failed to list namespaces: {type(exc).__name__}: {exc}",
                )
            )
            return findings

        for ns in namespaces.items:
            ns_name = ns.metadata.name
            try:
                bindings = self.rbac_api.list_namespaced_role_binding(ns_name)
            except Exception as exc:
                findings.append(
                    K8sRbacFinding(
                        resource_type="RoleBinding",
                        resource_name=f"{ns_name}/_list_error",
                        namespace=ns_name,
                        error=f"Failed to list RoleBindings in {ns_name}: {type(exc).__name__}: {exc}",
                    )
                )
                continue

            for rb in bindings.items:
                finding = self._check_binding_like(rb, "RoleBinding", namespace=ns_name)
                findings.append(finding)

        return findings

    # -- analysis helpers ----------------------------------------------------
    def _check_role_like(
        self,
        role_obj: Any,
        resource_type: str,
        namespace: str | None = None,
    ) -> K8sRbacFinding:
        """Analyze a Role or ClusterRole for privilege escalation paths."""
        name = role_obj.metadata.name if hasattr(role_obj.metadata, "name") else "unknown"
        finding = K8sRbacFinding(
            resource_type=resource_type,
            resource_name=name,
            namespace=namespace,
        )

        try:
            rules = getattr(role_obj, "rules", [])
            paths = _analyze_role_rules(rules)
            if not paths:
                finding.severity = "info"
            else:
                finding.privilege_paths = paths
                finding.severity = _severity_for_paths(paths, is_cluster_scope=(namespace is None))
                finding.evidence = _build_role_evidence(rules, paths)
        except Exception as exc:
            finding.error = f"{type(exc).__name__}: {exc}"

        return finding

    def _check_binding_like(
        self,
        binding_obj: Any,
        resource_type: str,
        namespace: str | None = None,
    ) -> K8sRbacFinding:
        """Analyze a RoleBinding or ClusterRoleBinding for privilege escalation.

        Bindings themselves don't grant permissions, but they bind a subject
        (user, group, or service account) to a Role/ClusterRole. We flag
        bindings that reference cluster-admin or system:admin roles.
        """
        name = binding_obj.metadata.name if hasattr(binding_obj.metadata, "name") else "unknown"
        finding = K8sRbacFinding(
            resource_type=resource_type,
            resource_name=name,
            namespace=namespace,
        )

        try:
            role_ref = getattr(binding_obj, "role_ref", None)
            subjects = getattr(binding_obj, "subjects", [])

            if role_ref is None:
                finding.severity = "info"
                return finding

            role_name = getattr(role_ref, "name", "")
            role_kind = getattr(role_ref, "kind", "")

            # Flag dangerous role references
            dangerous_roles = {
                "cluster-admin",
                "admin",
                "edit",
                "view",
                "system:admin",
            }

            if role_name.lower() in dangerous_roles:
                finding.privilege_paths = ["rbac_manage"]
                finding.severity = _severity_for_paths(
                    ["rbac_manage"],
                    is_cluster_scope=(namespace is None or role_kind == "ClusterRole"),
                )
                finding.evidence = _build_binding_evidence(role_ref, subjects, dangerous_roles)
            else:
                finding.severity = "info"

        except Exception as exc:
            finding.error = f"{type(exc).__name__}: {exc}"

        return finding


# --------------------------------------------------------------------------- #
# Rule analysis helpers (pure functions, fully unit-testable).
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


def _normalize_resource(resource: str) -> str:
    """Normalize a resource name for matching (handle subresources)."""
    return resource.lower().strip()


def _normalize_verb(verb: str) -> str:
    """Normalize a verb for matching."""
    return verb.lower().strip()


def _matches_rule(
    resource: str,
    verbs: list[str],
    rule_resource: str,
    rule_verbs: list[str],
) -> bool:
    """Check if a (resource, verbs) pair matches a rule."""
    norm_resource = _normalize_resource(resource)
    norm_rule_resource = _normalize_resource(rule_resource)

    # Wildcard resource matches everything
    if norm_rule_resource == "*":
        pass
    # Subresource match: pods/* matches pods/exec
    elif "/" in norm_rule_resource:
        base, sub = norm_rule_resource.split("/", 1)
        if sub == "*":
            # pods/* should match pods/exec, pods/log, etc.
            if not norm_resource.startswith(f"{base}/"):
                return False
        else:
            if norm_resource != norm_rule_resource:
                return False
    # Regular resource match (with optional subresource)
    else:
        if "/" in norm_resource:
            base, _ = norm_resource.split("/", 1)
            if base != norm_rule_resource:
                return False
        else:
            if norm_resource != norm_rule_resource:
                return False

    # Check verbs
    rule_verbs_lower = [_normalize_verb(v) for v in rule_verbs]
    if "*" in rule_verbs_lower:
        return True

    for verb in verbs:
        norm_verb = _normalize_verb(verb)
        if norm_verb in rule_verbs_lower or norm_verb == "*":
            return True

    return False


def _analyze_role_rules(rules: list[Any]) -> list[str]:
    """Analyze Role/ClusterRole rules and return matched privilege paths."""
    matched_paths: set[str] = set()

    for rule in rules:
        if not isinstance(rule, dict):
            # Handle kubernetes client objects
            rule_dict = {
                "resources": _as_list(getattr(rule, "resources", [])),
                "verbs": _as_list(getattr(rule, "verbs", [])),
                "resource_names": _as_list(getattr(rule, "resource_names", [])),
            }
        else:
            rule_dict = rule

        rule_resources = _as_list(rule_dict.get("resources", []))
        rule_verbs = _as_list(rule_dict.get("verbs", []))

        for priv_rule in PRIVILEGE_RULES:
            if _matches_rule(priv_rule["resource"], priv_rule["verbs"], rule_resources[0] if rule_resources else "", rule_verbs):
                matched_paths.add(priv_rule["path"])

    return sorted(matched_paths)


def _severity_for_paths(paths: list[str], is_cluster_scope: bool) -> str:
    """Determine severity based on matched paths and scope."""
    if not paths:
        return "info"

    # Get base severities for all matched paths
    base_severities = [SEVERITY_BY_PATH.get(p, "info") for p in paths]

    # Upgrade to critical for cluster-scoped RBAC management
    if is_cluster_scope and "rbac_manage" in paths:
        return "critical"

    # Upgrade to critical for wildcard permission
    if "wildcard_permission" in paths:
        return "critical"

    # Return the highest severity
    max_rank = max(_SEVERITY_RANK.get(s, 0) for s in base_severities)
    for sev, rank in _SEVERITY_RANK.items():
        if rank == max_rank:
            return sev

    return "info"


def _build_role_evidence(rules: list[Any], paths: list[str]) -> dict[str, Any]:
    """Build evidence for a Role/ClusterRole finding."""
    rules_list: list[dict[str, Any]] = []
    path_descriptions: list[str] = []

    for rule in rules:
        if not isinstance(rule, dict):
            rule_dict = {
                "resources": _as_list(getattr(rule, "resources", [])),
                "verbs": _as_list(getattr(rule, "verbs", [])),
                "resource_names": _as_list(getattr(rule, "resource_names", [])),
            }
        else:
            rule_dict = rule

        rules_list.append({
            "resources": _as_list(rule_dict.get("resources", [])),
            "verbs": _as_list(rule_dict.get("verbs", [])),
        })

    for path in paths:
        for priv_rule in PRIVILEGE_RULES:
            if priv_rule["path"] == path:
                path_descriptions.append(priv_rule["description"])
                break

    return {
        "rules": rules_list,
        "privilege_paths": paths,
        "descriptions": path_descriptions,
    }


def _build_binding_evidence(
    role_ref: Any,
    subjects: list[Any],
    dangerous_roles: set[str],
) -> dict[str, Any]:
    """Build evidence for a RoleBinding/ClusterRoleBinding finding."""
    role_info = {
        "kind": getattr(role_ref, "kind", "unknown"),
        "name": getattr(role_ref, "name", "unknown"),
    }

    subjects_list = []
    for subj in subjects:
        subjects_list.append({
            "kind": getattr(subj, "kind", "unknown"),
            "name": getattr(subj, "name", "unknown"),
            "namespace": getattr(subj, "namespace", None),
        })

    return {
        "role_ref": role_info,
        "subjects": subjects_list,
        "dangerous_role_name": role_info["name"],
        "dangerous_role_kind": role_info["kind"],
    }
