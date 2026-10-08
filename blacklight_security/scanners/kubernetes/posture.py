from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.kubernetes.cluster import (
    KubectlCLI,
    KubectlCommandError,
)


class KubernetesPostureScanner:
    """Read-only live NetworkPolicy and ServiceAccount posture checks."""

    def __init__(self, target: Any):
        self.target = target
        self.context_name = getattr(target, "context_name", None)
        self.cli = KubectlCLI(self.context_name)

    def scan(self) -> list[Finding]:
        try:
            client = self.cli.run(["version", "--client", "-o", "json"])
        except KubectlCommandError as error:
            return [self._availability_info(str(error))]

        if client.returncode != 0:
            return [self._availability_info(client.stderr[:500] or "kubectl client check failed")]

        findings: list[Finding] = []
        inventories: dict[str, dict[str, Any]] = {}

        for name, args in {
            "pods": [
                "get",
                "pods",
                "--all-namespaces",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
            "serviceaccounts": [
                "get",
                "serviceaccounts",
                "--all-namespaces",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
            "networkpolicies": [
                "get",
                "networkpolicies",
                "--all-namespaces",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
        }.items():
            payload = self._run_json(args, name)
            if isinstance(payload, Finding):
                findings.append(payload)
            else:
                inventories[name] = payload

        pods = self._items(inventories.get("pods"))
        service_accounts = self._items(inventories.get("serviceaccounts"))
        network_policies = self._items(inventories.get("networkpolicies"))

        if "pods" in inventories and "serviceaccounts" in inventories:
            findings.extend(
                self._check_service_account_token_usage(pods, service_accounts)
            )
            findings.extend(
                self._check_default_service_account_tokens(pods, service_accounts)
            )

        if "pods" in inventories and "networkpolicies" in inventories:
            findings.extend(
                self._check_namespace_network_policy_coverage(pods, network_policies)
            )

        if "networkpolicies" in inventories:
            findings.extend(self._check_allow_all_network_policies(network_policies))

        if not findings:
            findings.append(
                self._finding(
                    "cluster",
                    "kubernetes.posture.inventory",
                    Severity.PASS,
                    "No selected Kubernetes posture issue was observed",
                    (
                        "Blacklight completed the selected ServiceAccount and NetworkPolicy "
                        "posture checks without finding a targeted issue."
                    ),
                )
            )

        return findings

    def _check_service_account_token_usage(
        self,
        pods: list[dict[str, Any]],
        service_accounts: list[dict[str, Any]],
    ) -> list[Finding]:
        sa_index: dict[tuple[str, str], dict[str, Any]] = {}
        for service_account in service_accounts:
            metadata = self._metadata(service_account)
            namespace = str(metadata.get("namespace") or "default")
            name = str(metadata.get("name") or "")
            if name:
                sa_index[(namespace, name)] = service_account

        usage: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)

        for pod in pods:
            metadata = self._metadata(pod)
            spec = pod.get("spec")
            if not isinstance(spec, dict):
                continue

            namespace = str(metadata.get("namespace") or "default")
            pod_name = str(metadata.get("name") or "unknown")
            service_account_name = str(
                spec.get("serviceAccountName")
                or spec.get("serviceAccount")
                or "default"
            )

            service_account = sa_index.get((namespace, service_account_name), {})
            effective, source = self._effective_token_automount(spec, service_account)
            if not effective:
                continue

            usage[(namespace, service_account_name)].append(
                {
                    "pod": pod_name,
                    "source": source,
                }
            )

        if not usage:
            return [
                self._finding(
                    "cluster",
                    "kubernetes.posture.service_account_token_usage",
                    Severity.PASS,
                    "No live Pod was observed with an effective ServiceAccount token mount",
                    (
                        "Blacklight did not observe a live Pod whose ServiceAccount token "
                        "automount resolves to enabled."
                    ),
                )
            ]

        findings: list[Finding] = []
        for (namespace, service_account_name), pod_records in sorted(usage.items()):
            findings.append(
                self._finding(
                    f"ServiceAccount/{namespace}/{service_account_name}",
                    "kubernetes.posture.service_account_token_usage",
                    Severity.INFO,
                    "Live Pods use a ServiceAccount with API token automount enabled",
                    (
                        "Blacklight observed one or more live Pods using this ServiceAccount "
                        "where automountServiceAccountToken resolves to enabled. This is identity "
                        "inventory for correlation and is not independently scored as a security issue."
                    ),
                    evidence={
                        "namespace": namespace,
                        "service_account": service_account_name,
                        "pods": sorted(pod_records, key=lambda item: item["pod"]),
                        "pod_count": len(pod_records),
                    },
                )
            )
        return findings

    @staticmethod
    def _effective_token_automount(
        pod_spec: dict[str, Any],
        service_account: dict[str, Any],
    ) -> tuple[bool, str]:
        pod_setting = pod_spec.get("automountServiceAccountToken")
        sa_setting = (
            service_account.get("automountServiceAccountToken")
            if isinstance(service_account, dict)
            else None
        )

        if isinstance(pod_setting, bool):
            return pod_setting, "pod"
        if isinstance(sa_setting, bool):
            return sa_setting, "serviceaccount"
        return True, "kubernetes-default"

    def _check_default_service_account_tokens(
        self,
        pods: list[dict[str, Any]],
        service_accounts: list[dict[str, Any]],
    ) -> list[Finding]:
        sa_index: dict[tuple[str, str], dict[str, Any]] = {}
        for service_account in service_accounts:
            metadata = self._metadata(service_account)
            namespace = str(metadata.get("namespace") or "default")
            name = str(metadata.get("name") or "")
            if name:
                sa_index[(namespace, name)] = service_account

        by_namespace: dict[str, list[str]] = defaultdict(list)

        for pod in pods:
            metadata = self._metadata(pod)
            spec = pod.get("spec")
            if not isinstance(spec, dict):
                continue

            namespace = str(metadata.get("namespace") or "default")
            pod_name = str(metadata.get("name") or "unknown")
            service_account_name = str(
                spec.get("serviceAccountName")
                or spec.get("serviceAccount")
                or "default"
            )
            if service_account_name != "default":
                continue

            sa = sa_index.get((namespace, service_account_name), {})
            effective, source = self._effective_token_automount(spec, sa)

            if effective:
                by_namespace[namespace].append(f"{pod_name} ({source})")

        findings: list[Finding] = []
        for namespace, pod_names in sorted(by_namespace.items()):
            findings.append(
                self._finding(
                    f"Namespace/{namespace}",
                    "kubernetes.posture.default_service_account_token",
                    Severity.LOW,
                    "Pods use the default ServiceAccount with API token automount enabled",
                    (
                        "Blacklight observed live Pods using the namespace default ServiceAccount "
                        "where automountServiceAccountToken resolves to enabled. This exposes a "
                        "Kubernetes API credential inside those Pods even when they may not need "
                        "API access."
                    ),
                    (
                        "Use a dedicated least-privilege ServiceAccount and set "
                        "automountServiceAccountToken: false for workloads that do not need the "
                        "Kubernetes API."
                    ),
                    {
                        "namespace": namespace,
                        "pods": sorted(pod_names),
                        "pod_count": len(pod_names),
                    },
                )
            )

        if not findings:
            findings.append(
                self._finding(
                    "cluster",
                    "kubernetes.posture.default_service_account_token",
                    Severity.PASS,
                    "No live Pod was observed using an auto-mounted default ServiceAccount token",
                    (
                        "Blacklight did not observe the selected default-ServiceAccount token "
                        "automount condition in the live Pod inventory."
                    ),
                )
            )
        return findings

    def _check_namespace_network_policy_coverage(
        self,
        pods: list[dict[str, Any]],
        network_policies: list[dict[str, Any]],
    ) -> list[Finding]:
        pod_namespaces = {
            str(self._metadata(pod).get("namespace") or "default")
            for pod in pods
        }
        policy_namespaces = {
            str(self._metadata(policy).get("namespace") or "default")
            for policy in network_policies
        }

        missing = sorted(pod_namespaces - policy_namespaces)
        if not missing:
            return [
                self._finding(
                    "cluster",
                    "kubernetes.posture.namespace_without_networkpolicy",
                    Severity.PASS,
                    "Every namespace with observed Pods has at least one NetworkPolicy",
                    (
                        "This is presence coverage only. It does not prove every Pod is selected "
                        "or that the cluster CNI enforces NetworkPolicy."
                    ),
                )
            ]

        return [
            self._finding(
                f"Namespace/{namespace}",
                "kubernetes.posture.namespace_without_networkpolicy",
                Severity.LOW,
                "Namespace with live Pods has no NetworkPolicy",
                (
                    "Blacklight observed live Pods in this namespace but no NetworkPolicy objects. "
                    "This means Kubernetes NetworkPolicy objects do not restrict traffic in that "
                    "namespace, though external network controls may still exist."
                ),
                (
                    "Define namespace/workload NetworkPolicies when network isolation is required "
                    "and confirm the cluster networking implementation enforces them."
                ),
                {"namespace": namespace},
            )
            for namespace in missing
        ]

    def _check_allow_all_network_policies(
        self,
        network_policies: list[dict[str, Any]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for policy in network_policies:
            metadata = self._metadata(policy)
            spec = policy.get("spec")
            if not isinstance(spec, dict):
                continue

            namespace = str(metadata.get("namespace") or "default")
            name = str(metadata.get("name") or "unknown")
            selector = spec.get("podSelector")
            if selector != {}:
                continue

            policy_types = {
                str(item)
                for item in spec.get("policyTypes", [])
                if item
            }
            if not policy_types:
                if "ingress" in spec:
                    policy_types.add("Ingress")
                if "egress" in spec:
                    policy_types.add("Egress")

            allow_directions: list[str] = []
            ingress = spec.get("ingress")
            if (
                "Ingress" in policy_types
                and isinstance(ingress, list)
                and any(rule == {} for rule in ingress)
            ):
                allow_directions.append("ingress")

            egress = spec.get("egress")
            if (
                "Egress" in policy_types
                and isinstance(egress, list)
                and any(rule == {} for rule in egress)
            ):
                allow_directions.append("egress")

            if not allow_directions:
                continue

            findings.append(
                self._finding(
                    f"NetworkPolicy/{namespace}/{name}",
                    "kubernetes.posture.allow_all_networkpolicy",
                    Severity.MEDIUM,
                    "NetworkPolicy explicitly allows all traffic for an entire namespace",
                    (
                        "The live NetworkPolicy has an empty podSelector and an empty ingress or "
                        "egress rule, which selects all Pods and allows all traffic in the reported "
                        "direction."
                    ),
                    (
                        "Replace broad empty rules with the specific peer and port selectors "
                        "required by workloads."
                    ),
                    {
                        "namespace": namespace,
                        "policy": name,
                        "allow_all_directions": allow_directions,
                    },
                )
            )

        if not findings:
            findings.append(
                self._finding(
                    "cluster",
                    "kubernetes.posture.allow_all_networkpolicy",
                    Severity.PASS,
                    "No namespace-wide allow-all NetworkPolicy was observed",
                    (
                        "Blacklight did not observe an empty podSelector combined with an empty "
                        "ingress/egress rule in the live NetworkPolicy inventory."
                    ),
                )
            )
        return findings

    @staticmethod
    def _metadata(resource: dict[str, Any]) -> dict[str, Any]:
        metadata = resource.get("metadata")
        return metadata if isinstance(metadata, dict) else {}

    @staticmethod
    def _items(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
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
            "kubernetes.posture.connection",
            Severity.INFO,
            "Kubernetes posture inspection is not available",
            (
                "Blacklight could not use kubectl for read-only NetworkPolicy and "
                "ServiceAccount posture inspection."
            ),
            evidence={"reason": message},
        )

    def _error(self, stage: str, message: str) -> Finding:
        return self._finding(
            "cluster",
            f"kubernetes.posture.{stage}",
            Severity.ERROR,
            f"Blacklight could not complete Kubernetes posture {stage.replace('_', ' ')}",
            message,
            "Verify kubectl read permissions for the selected context, then retry.",
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
            service="posture",
            resource_type="kubernetes_live_posture",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
