from __future__ import annotations

import json
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.kubernetes.cluster import (
    KubectlCLI,
    KubectlCommandError,
)


_SYSTEM_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
}
_PSA_ENFORCE_LABEL = "pod-security.kubernetes.io/enforce"
_PSA_ENFORCE_VERSION_LABEL = "pod-security.kubernetes.io/enforce-version"


class KubernetesAdmissionScanner:
    """Read-only Pod Security Admission and admission-webhook posture checks."""

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
            return [
                self._availability_info(
                    client.stderr[:500] or "kubectl client check failed"
                )
            ]

        findings: list[Finding] = []
        inventories: dict[str, dict[str, Any]] = {}

        for name, args in {
            "namespaces": [
                "get",
                "namespaces",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
            "pods": [
                "get",
                "pods",
                "--all-namespaces",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
            "validatingwebhooks": [
                "get",
                "validatingwebhookconfigurations",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
            "mutatingwebhooks": [
                "get",
                "mutatingwebhookconfigurations",
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

        if "namespaces" in inventories and "pods" in inventories:
            findings.extend(
                self._check_pod_security_admission(
                    self._items(inventories["namespaces"]),
                    self._items(inventories["pods"]),
                )
            )

        if "validatingwebhooks" in inventories:
            findings.extend(
                self._check_webhooks(
                    self._items(inventories["validatingwebhooks"]),
                    configuration_kind="ValidatingWebhookConfiguration",
                )
            )

        if "mutatingwebhooks" in inventories:
            findings.extend(
                self._check_webhooks(
                    self._items(inventories["mutatingwebhooks"]),
                    configuration_kind="MutatingWebhookConfiguration",
                )
            )

        if not findings:
            findings.append(
                self._finding(
                    "cluster",
                    "kubernetes.admission.inventory",
                    Severity.PASS,
                    "No selected Kubernetes admission posture issue was observed",
                    (
                        "Blacklight completed the selected Pod Security Admission and "
                        "admission-webhook checks without finding a targeted issue."
                    ),
                )
            )

        return findings

    def _check_pod_security_admission(
        self,
        namespaces: list[dict[str, Any]],
        pods: list[dict[str, Any]],
    ) -> list[Finding]:
        namespaces_with_pods = {
            str(self._metadata(pod).get("namespace") or "default")
            for pod in pods
        }
        namespace_index = {
            str(self._metadata(namespace).get("name") or ""): namespace
            for namespace in namespaces
            if str(self._metadata(namespace).get("name") or "")
        }

        findings: list[Finding] = []
        for namespace_name in sorted(namespaces_with_pods):
            if namespace_name in _SYSTEM_NAMESPACES:
                continue

            namespace = namespace_index.get(namespace_name)
            if namespace is None:
                findings.append(
                    self._error(
                        "namespace_resolution",
                        f"Blacklight could not resolve Namespace/{namespace_name}",
                        resource_id=f"Namespace/{namespace_name}",
                    )
                )
                continue

            metadata = self._metadata(namespace)
            labels = metadata.get("labels")
            if not isinstance(labels, dict):
                labels = {}

            enforce = str(labels.get(_PSA_ENFORCE_LABEL) or "").strip().lower()
            version = str(labels.get(_PSA_ENFORCE_VERSION_LABEL) or "").strip()

            if not enforce:
                findings.append(
                    self._finding(
                        f"Namespace/{namespace_name}",
                        "kubernetes.admission.psa_enforce_missing",
                        Severity.LOW,
                        "Namespace with live Pods has no Pod Security enforce label",
                        (
                            "Blacklight observed live Pods in a non-system namespace without "
                            "the Pod Security Admission enforce label. Other admission controls "
                            "may still enforce equivalent or stronger policy."
                        ),
                        (
                            "Set an intentional Pod Security Admission enforce level or document "
                            "the equivalent admission control used for this namespace."
                        ),
                        {
                            "namespace": namespace_name,
                            "enforce": None,
                            "enforce_version": version or None,
                        },
                    )
                )
                continue

            if enforce == "privileged":
                findings.append(
                    self._finding(
                        f"Namespace/{namespace_name}",
                        "kubernetes.admission.psa_enforce_privileged",
                        Severity.MEDIUM,
                        "Namespace explicitly enforces the privileged Pod Security level",
                        (
                            "The namespace Pod Security Admission enforce label is privileged, "
                            "which does not restrict Pod security settings under the built-in "
                            "Pod Security Standards."
                        ),
                        (
                            "Use baseline or restricted enforcement where workload compatibility "
                            "allows it, and isolate namespaces that intentionally require privileged Pods."
                        ),
                        {
                            "namespace": namespace_name,
                            "enforce": enforce,
                            "enforce_version": version or None,
                        },
                    )
                )
            elif enforce == "baseline":
                findings.append(
                    self._finding(
                        f"Namespace/{namespace_name}",
                        "kubernetes.admission.psa_enforce_baseline",
                        Severity.INFO,
                        "Namespace enforces the baseline Pod Security level",
                        (
                            "Baseline enforcement blocks known privilege escalations while "
                            "remaining less restrictive than the restricted profile."
                        ),
                        evidence={
                            "namespace": namespace_name,
                            "enforce": enforce,
                            "enforce_version": version or None,
                        },
                    )
                )
            elif enforce == "restricted":
                findings.append(
                    self._finding(
                        f"Namespace/{namespace_name}",
                        "kubernetes.admission.psa_enforce_restricted",
                        Severity.PASS,
                        "Namespace enforces the restricted Pod Security level",
                        (
                            "The namespace explicitly enforces the restricted built-in Pod "
                            "Security Standard."
                        ),
                        evidence={
                            "namespace": namespace_name,
                            "enforce": enforce,
                            "enforce_version": version or None,
                        },
                    )
                )
            else:
                findings.append(
                    self._finding(
                        f"Namespace/{namespace_name}",
                        "kubernetes.admission.psa_enforce_unknown",
                        Severity.INFO,
                        "Namespace has an unrecognized Pod Security enforce label",
                        (
                            "Blacklight did not map the observed enforce label to privileged, "
                            "baseline, or restricted and therefore did not infer its security posture."
                        ),
                        evidence={
                            "namespace": namespace_name,
                            "enforce": enforce,
                            "enforce_version": version or None,
                        },
                    )
                )

        if not findings:
            findings.append(
                self._finding(
                    "cluster",
                    "kubernetes.admission.psa",
                    Severity.PASS,
                    "No non-system namespace with live Pods required a Pod Security finding",
                    (
                        "Blacklight did not observe a non-system workload namespace requiring "
                        "one of the selected Pod Security Admission findings."
                    ),
                )
            )
        return findings

    def _check_webhooks(
        self,
        configurations: list[dict[str, Any]],
        *,
        configuration_kind: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for configuration in configurations:
            metadata = self._metadata(configuration)
            config_name = str(metadata.get("name") or "unknown")
            webhooks = configuration.get("webhooks")
            if not isinstance(webhooks, list):
                continue

            for webhook in webhooks:
                if not isinstance(webhook, dict):
                    continue
                webhook_name = str(webhook.get("name") or "unknown")
                failure_policy = str(webhook.get("failurePolicy") or "Fail")
                if failure_policy.lower() != "ignore":
                    continue

                rules = webhook.get("rules")
                if not isinstance(rules, list):
                    rules = []

                broad = any(self._rule_is_broad(rule) for rule in rules if isinstance(rule, dict))
                severity = Severity.MEDIUM if broad else Severity.LOW
                check_id = (
                    "kubernetes.admission.fail_open_broad_webhook"
                    if broad
                    else "kubernetes.admission.fail_open_webhook"
                )
                resource_id = (
                    f"{configuration_kind}/{config_name}/{webhook_name}"
                )

                findings.append(
                    self._finding(
                        resource_id,
                        check_id,
                        severity,
                        (
                            "Broad admission webhook fails open"
                            if broad
                            else "Admission webhook fails open"
                        ),
                        (
                            "The live admission webhook uses failurePolicy=Ignore. If the webhook "
                            "cannot be reached or errors, matching API requests can continue without "
                            "that webhook's decision."
                        ),
                        (
                            "Use failurePolicy=Fail for security-enforcement webhooks when availability "
                            "design permits it, or document the fail-open requirement and compensating controls."
                        ),
                        {
                            "configuration_kind": configuration_kind,
                            "configuration": config_name,
                            "webhook": webhook_name,
                            "failure_policy": failure_policy,
                            "broad_match": broad,
                            "rules": [self._rule_evidence(rule) for rule in rules if isinstance(rule, dict)],
                        },
                    )
                )

        if not findings:
            findings.append(
                self._finding(
                    configuration_kind,
                    "kubernetes.admission.fail_open_webhook",
                    Severity.PASS,
                    f"No fail-open {configuration_kind} webhook was observed",
                    (
                        "Blacklight did not observe failurePolicy=Ignore in the selected live "
                        f"{configuration_kind} inventory."
                    ),
                )
            )
        return findings

    @staticmethod
    def _rule_is_broad(rule: dict[str, Any]) -> bool:
        operations = {str(item) for item in rule.get("operations", []) if item}
        resources = {str(item) for item in rule.get("resources", []) if item}
        api_groups = {str(item) for item in rule.get("apiGroups", []) if item is not None}
        api_versions = {str(item) for item in rule.get("apiVersions", []) if item}

        return (
            "*" in operations
            or "*" in resources
            or "*/*" in resources
            or "*" in api_groups
            or "*" in api_versions
        )

    @staticmethod
    def _rule_evidence(rule: dict[str, Any]) -> dict[str, list[str]]:
        return {
            "operations": sorted(str(item) for item in rule.get("operations", []) if item),
            "resources": sorted(str(item) for item in rule.get("resources", []) if item),
            "api_groups": sorted(str(item) for item in rule.get("apiGroups", []) if item is not None),
            "api_versions": sorted(str(item) for item in rule.get("apiVersions", []) if item),
        }

    @staticmethod
    def _metadata(resource: dict[str, Any]) -> dict[str, Any]:
        metadata = resource.get("metadata")
        return metadata if isinstance(metadata, dict) else {}

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
            "kubernetes.admission.connection",
            Severity.INFO,
            "Kubernetes admission inspection is not available",
            (
                "Blacklight could not use kubectl for read-only Pod Security Admission and "
                "admission-webhook posture inspection."
            ),
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
            f"kubernetes.admission.{stage}",
            Severity.ERROR,
            f"Blacklight could not complete Kubernetes admission {stage.replace('_', ' ')}",
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
            service="admission",
            resource_type="kubernetes_admission_posture",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
