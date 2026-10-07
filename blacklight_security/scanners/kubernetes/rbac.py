from __future__ import annotations

import json
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.kubernetes.cluster import (
    KubectlCLI,
    KubectlCommandError,
)


class KubernetesRBACScanner:
    """Read-only analysis of bound Kubernetes RBAC grants."""

    def __init__(self, target: Any):
        self.target = target
        self.context_name = getattr(target, "context_name", None)
        self.cli = KubectlCLI(self.context_name)

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        try:
            client = self.cli.run(["version", "--client", "-o", "json"])
        except KubectlCommandError as error:
            return [self._availability_info(str(error))]

        if client.returncode != 0:
            return [self._availability_info(client.stderr[:500] or "kubectl client check failed")]

        resources: dict[str, dict[str, Any]] = {}
        for label, args in {
            "clusterroles": ["get", "clusterroles", "-o", "json", "--request-timeout=10s"],
            "roles": ["get", "roles", "--all-namespaces", "-o", "json", "--request-timeout=10s"],
            "clusterrolebindings": [
                "get",
                "clusterrolebindings",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
            "rolebindings": [
                "get",
                "rolebindings",
                "--all-namespaces",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
        }.items():
            payload = self._run_json(args, label)
            if isinstance(payload, Finding):
                findings.append(payload)
                continue
            resources[label] = payload

        required = {"clusterroles", "roles", "clusterrolebindings", "rolebindings"}
        if not required.issubset(resources):
            if findings:
                return findings
            return [self._error("inventory", "RBAC inventory was incomplete")]

        cluster_roles = self._index_cluster_roles(resources["clusterroles"])
        roles = self._index_roles(resources["roles"])

        binding_findings: list[Finding] = []
        for binding in self._items(resources["clusterrolebindings"]):
            binding_findings.extend(
                self._analyze_binding(
                    binding,
                    binding_kind="ClusterRoleBinding",
                    cluster_roles=cluster_roles,
                    roles=roles,
                )
            )

        for binding in self._items(resources["rolebindings"]):
            binding_findings.extend(
                self._analyze_binding(
                    binding,
                    binding_kind="RoleBinding",
                    cluster_roles=cluster_roles,
                    roles=roles,
                )
            )

        if not binding_findings:
            binding_findings.append(
                self._finding(
                    "cluster",
                    "kubernetes.rbac.bound_privilege",
                    Severity.PASS,
                    "No selected dangerous bound RBAC grants were observed",
                    (
                        "Blacklight resolved live RoleBinding and ClusterRoleBinding references "
                        "and found none of the selected dangerous grant patterns."
                    ),
                )
            )

        return [*findings, *binding_findings]

    def _analyze_binding(
        self,
        binding: dict[str, Any],
        *,
        binding_kind: str,
        cluster_roles: dict[str, list[dict[str, Any]]],
        roles: dict[tuple[str, str], list[dict[str, Any]]],
    ) -> list[Finding]:
        metadata = binding.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        namespace = str(metadata.get("namespace") or "cluster")
        name = str(metadata.get("name") or "unknown")
        resource_id = f"{binding_kind}/{namespace}/{name}"

        role_ref = binding.get("roleRef")
        if not isinstance(role_ref, dict):
            return [
                self._error(
                    "binding_role_ref",
                    f"{resource_id} has no usable roleRef",
                    resource_id=resource_id,
                )
            ]

        ref_kind = str(role_ref.get("kind") or "")
        ref_name = str(role_ref.get("name") or "")
        rules: list[dict[str, Any]] | None = None

        if ref_kind == "ClusterRole":
            rules = cluster_roles.get(ref_name)
        elif ref_kind == "Role" and binding_kind == "RoleBinding":
            rules = roles.get((namespace, ref_name))

        if rules is None:
            return [
                self._error(
                    "binding_role_ref",
                    f"Blacklight could not resolve {ref_kind}/{ref_name} for {resource_id}",
                    resource_id=resource_id,
                )
            ]

        subjects = self._subjects(binding)
        evidence_base = {
            "binding": resource_id,
            "role_ref": {"kind": ref_kind, "name": ref_name},
            "subjects": subjects,
        }
        findings: list[Finding] = []

        if ref_kind == "ClusterRole" and ref_name == "cluster-admin":
            broad_system_subjects = [
                subject
                for subject in subjects
                if subject["name"]
                in {
                    "system:anonymous",
                    "system:unauthenticated",
                    "system:authenticated",
                }
            ]
            if broad_system_subjects:
                severity = (
                    Severity.CRITICAL
                    if any(
                        subject["name"] in {"system:anonymous", "system:unauthenticated"}
                        for subject in broad_system_subjects
                    )
                    else Severity.HIGH
                )
                findings.append(
                    self._finding(
                        resource_id,
                        "kubernetes.rbac.cluster_admin_broad_subject",
                        severity,
                        "cluster-admin is bound to a broad built-in identity group",
                        (
                            "A live RBAC binding grants cluster-admin to a broad Kubernetes "
                            "built-in identity subject."
                        ),
                        "Remove the broad cluster-admin binding and grant only the minimum required permissions.",
                        {**evidence_base, "broad_subjects": broad_system_subjects},
                    )
                )
            elif subjects:
                findings.append(
                    self._finding(
                        resource_id,
                        "kubernetes.rbac.cluster_admin_binding",
                        Severity.INFO,
                        "cluster-admin binding was observed",
                        (
                            "Blacklight observed cluster-admin granted to explicit subjects. "
                            "This is high-privilege inventory rather than an automatic vulnerability."
                        ),
                        evidence=evidence_base,
                    )
                )

        dangerous = self._dangerous_rules(rules)
        if dangerous["wildcard"]:
            findings.append(
                self._finding(
                    resource_id,
                    "kubernetes.rbac.bound_wildcard",
                    Severity.HIGH,
                    "Bound RBAC role grants wildcard verbs and resources",
                    (
                        "The resolved live binding grants a rule with both wildcard verbs and "
                        "wildcard resources."
                    ),
                    "Replace wildcard grants with the narrowest required verbs and resources.",
                    {**evidence_base, "rules": dangerous["wildcard"]},
                )
            )

        if dangerous["secret_read"]:
            findings.append(
                self._finding(
                    resource_id,
                    "kubernetes.rbac.secret_read",
                    Severity.HIGH,
                    "Bound RBAC role can read Kubernetes Secrets",
                    (
                        "The resolved live binding grants get/list/watch or wildcard access to "
                        "Secret resources."
                    ),
                    "Restrict Secret read access to only the subjects and namespaces that require it.",
                    {**evidence_base, "rules": dangerous["secret_read"]},
                )
            )

        if dangerous["pod_exec"]:
            findings.append(
                self._finding(
                    resource_id,
                    "kubernetes.rbac.pod_exec",
                    Severity.HIGH,
                    "Bound RBAC role can create pod exec sessions",
                    (
                        "The resolved live binding grants create or wildcard access to the "
                        "pods/exec subresource."
                    ),
                    "Remove pod exec access from subjects that do not explicitly require interactive container access.",
                    {**evidence_base, "rules": dangerous["pod_exec"]},
                )
            )

        if dangerous["impersonate"]:
            findings.append(
                self._finding(
                    resource_id,
                    "kubernetes.rbac.impersonate",
                    Severity.HIGH,
                    "Bound RBAC role grants identity impersonation",
                    (
                        "The resolved live binding grants the Kubernetes impersonate verb to "
                        "users, groups, serviceaccounts, or wildcard resources."
                    ),
                    "Restrict impersonation permissions to tightly controlled administrative identities.",
                    {**evidence_base, "rules": dangerous["impersonate"]},
                )
            )

        return findings

    @staticmethod
    def _dangerous_rules(rules: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        matches = {
            "wildcard": [],
            "secret_read": [],
            "pod_exec": [],
            "impersonate": [],
        }

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            verbs = {str(item).lower() for item in rule.get("verbs", []) if item}
            resources = {str(item).lower() for item in rule.get("resources", []) if item}
            api_groups = {str(item) for item in rule.get("apiGroups", []) if item is not None}

            evidence = {
                "verbs": sorted(verbs),
                "resources": sorted(resources),
                "api_groups": sorted(api_groups),
            }

            if "*" in verbs and "*" in resources:
                matches["wildcard"].append(evidence)

            read_verbs = {"get", "list", "watch", "*"}
            if (verbs & read_verbs) and ("secrets" in resources or "*" in resources):
                if "" in api_groups or "*" in api_groups or not api_groups:
                    matches["secret_read"].append(evidence)

            if ("create" in verbs or "*" in verbs) and (
                "pods/exec" in resources or "*" in resources
            ):
                if "" in api_groups or "*" in api_groups or not api_groups:
                    matches["pod_exec"].append(evidence)

            if ("impersonate" in verbs or "*" in verbs) and (
                resources
                & {
                    "users",
                    "groups",
                    "serviceaccounts",
                    "*",
                }
            ):
                matches["impersonate"].append(evidence)

        return matches

    @staticmethod
    def _subjects(binding: dict[str, Any]) -> list[dict[str, str]]:
        raw = binding.get("subjects")
        if not isinstance(raw, list):
            return []

        subjects: list[dict[str, str]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            subjects.append(
                {
                    "kind": str(item.get("kind") or ""),
                    "name": str(item.get("name") or ""),
                    "namespace": str(item.get("namespace") or ""),
                }
            )
        return subjects

    @staticmethod
    def _index_cluster_roles(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        indexed: dict[str, list[dict[str, Any]]] = {}
        for item in KubernetesRBACScanner._items(payload):
            metadata = item.get("metadata")
            if not isinstance(metadata, dict):
                continue
            name = str(metadata.get("name") or "")
            rules = item.get("rules")
            if name and isinstance(rules, list):
                indexed[name] = [rule for rule in rules if isinstance(rule, dict)]
        return indexed

    @staticmethod
    def _index_roles(payload: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
        indexed: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for item in KubernetesRBACScanner._items(payload):
            metadata = item.get("metadata")
            if not isinstance(metadata, dict):
                continue
            namespace = str(metadata.get("namespace") or "default")
            name = str(metadata.get("name") or "")
            rules = item.get("rules")
            if name and isinstance(rules, list):
                indexed[(namespace, name)] = [
                    rule for rule in rules if isinstance(rule, dict)
                ]
        return indexed

    @staticmethod
    def _items(payload: dict[str, Any]) -> list[dict[str, Any]]:
        items = payload.get("items")
        if not isinstance(items, list):
            return []
        return [item for item in items if isinstance(item, dict)]

    def _run_json(
        self,
        args: list[str],
        stage: str,
    ) -> dict[str, Any] | Finding:
        try:
            result = self.cli.run(args, timeout=20)
        except KubectlCommandError as error:
            return self._error(stage, str(error))

        if result.returncode != 0:
            return self._error(
                stage,
                result.stderr[:500] or f"kubectl {stage} returned a non-zero exit status",
            )

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            return self._error(stage, f"invalid kubectl JSON: {error}")

        if not isinstance(payload, dict):
            return self._error(stage, "kubectl JSON response was not an object")
        return payload

    def _availability_info(self, message: str) -> Finding:
        return self._finding(
            "cluster",
            "kubernetes.rbac.connection",
            Severity.INFO,
            "Kubernetes RBAC inspection is not available",
            "Blacklight could not use kubectl for read-only RBAC inventory.",
            evidence={"reason": message},
        )

    def _error(
        self,
        stage: str,
        message: str,
        *,
        resource_id: str = "cluster",
    ) -> Finding:
        return self._finding(
            resource_id,
            f"kubernetes.rbac.{stage}",
            Severity.ERROR,
            f"Blacklight could not complete Kubernetes RBAC {stage.replace('_', ' ')}",
            message,
            "Verify kubectl RBAC read permissions for the selected context, then retry.",
        )

    @staticmethod
    def _finding(
        resource_id: str,
        check_id: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            provider="kubernetes",
            service="rbac",
            resource_type="kubernetes_rbac_binding",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
