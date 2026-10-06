from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.kubernetes.manifests import KubernetesManifestScanner


@dataclass(frozen=True, slots=True)
class KubectlCommandResult:
    returncode: int
    stdout: str
    stderr: str


class KubectlCommandError(RuntimeError):
    pass


class KubectlCLI:
    def __init__(self, context_name: str | None = None):
        self.context_name = context_name

    def run(self, args: list[str], timeout: int = 15) -> KubectlCommandResult:
        command = ["kubectl"]
        if self.context_name:
            command.extend(["--context", self.context_name])
        command.extend(args)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except FileNotFoundError as error:
            raise KubectlCommandError("kubectl CLI was not found") from error
        except subprocess.TimeoutExpired as error:
            raise KubectlCommandError("kubectl command timed out") from error

        return KubectlCommandResult(
            completed.returncode,
            completed.stdout.strip(),
            completed.stderr.strip(),
        )


class KubernetesClusterScanner(KubernetesManifestScanner):
    """Read-only inspection of live Kubernetes Pods and Service exposure."""

    def __init__(self, target: Any):
        self.target = target
        self.context_name = getattr(target, "context_name", None)
        self.cli = KubectlCLI(self.context_name)

    def scan(self) -> list[Finding]:
        try:
            context = self.cli.run(["config", "current-context"])
        except KubectlCommandError as error:
            return [self._availability_info(str(error))]

        if context.returncode != 0:
            return [
                self._finding(
                    "cluster",
                    "kubernetes.cluster.connection",
                    Severity.INFO,
                    "Kubernetes live-cluster inspection is not available",
                    (
                        "kubectl is available, but Blacklight could not resolve the selected "
                        "Kubernetes context."
                    ),
                    evidence={"stderr": context.stderr[:500]},
                )
            ]

        selected_context = self.context_name or context.stdout.strip() or "unknown"

        pod_result = self._run_json(
            [
                "get",
                "pods",
                "--all-namespaces",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
            "pod_inventory",
        )
        if isinstance(pod_result, Finding):
            return [pod_result]

        findings: list[Finding] = []
        pod_items = pod_result.get("items", [])
        if not isinstance(pod_items, list):
            return [
                self._error(
                    "pod_inventory",
                    "Kubernetes Pod inventory JSON did not contain an items list",
                )
            ]

        if not pod_items:
            findings.append(
                self._finding(
                    "cluster",
                    "kubernetes.cluster.pod_inventory",
                    Severity.INFO,
                    "No live Kubernetes Pods were observed",
                    "kubectl returned an empty all-namespaces Pod inventory.",
                    evidence={"context": selected_context, "pod_count": 0},
                )
            )

        for pod in pod_items:
            if not isinstance(pod, dict):
                continue
            spec = pod.get("spec")
            if not isinstance(spec, dict):
                continue
            resource_id = self._live_resource_id(pod)
            findings.extend(self._check_resource(resource_id, spec))

        service_result = self._run_json(
            [
                "get",
                "services",
                "--all-namespaces",
                "-o",
                "json",
                "--request-timeout=10s",
            ],
            "service_inventory",
        )
        if isinstance(service_result, Finding):
            findings.append(service_result)
        else:
            findings.append(
                self._check_service_exposure(service_result, selected_context)
            )

        return findings

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

    def _check_service_exposure(
        self,
        payload: dict[str, Any],
        context: str,
    ) -> Finding:
        items = payload.get("items", [])
        if not isinstance(items, list):
            return self._error(
                "service_inventory",
                "Kubernetes Service inventory JSON did not contain an items list",
            )

        matches: list[dict[str, Any]] = []
        for service in items:
            if not isinstance(service, dict):
                continue
            metadata = service.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
            spec = service.get("spec")
            if not isinstance(spec, dict):
                spec = {}
            status = service.get("status")
            if not isinstance(status, dict):
                status = {}

            service_type = str(spec.get("type") or "ClusterIP")
            external_ips = spec.get("externalIPs")
            if not isinstance(external_ips, list):
                external_ips = []

            load_balancer = status.get("loadBalancer")
            if not isinstance(load_balancer, dict):
                load_balancer = {}
            ingress = load_balancer.get("ingress")
            if not isinstance(ingress, list):
                ingress = []

            externally_exposed = (
                service_type in {"NodePort", "LoadBalancer"}
                or bool(external_ips)
                or bool(ingress)
            )
            if not externally_exposed:
                continue

            namespace = str(metadata.get("namespace") or "default")
            name = str(metadata.get("name") or "unknown")
            matches.append(
                {
                    "resource": f"Service/{namespace}/{name}",
                    "type": service_type,
                    "external_ips": [str(item) for item in external_ips],
                    "load_balancer_ingress": [
                        {
                            "ip": str(item.get("ip") or ""),
                            "hostname": str(item.get("hostname") or ""),
                        }
                        for item in ingress
                        if isinstance(item, dict)
                    ],
                }
            )

        if matches:
            return self._finding(
                "cluster",
                "kubernetes.cluster.external_service",
                Severity.LOW,
                "Live Kubernetes cluster has Services with external/node exposure",
                (
                    "Blacklight observed NodePort, LoadBalancer, externalIPs, or load-balancer "
                    "ingress configuration. This proves cluster-level exposure configuration, "
                    "not public internet reachability or vulnerability."
                ),
                "Confirm each externally exposed Service is intentional and protected by appropriate network controls.",
                {"context": context, "services": matches},
            )

        return self._pass(
            "cluster",
            "kubernetes.cluster.external_service",
            "No selected externally exposed Kubernetes Service was observed",
        )

    @staticmethod
    def _live_resource_id(pod: dict[str, Any]) -> str:
        metadata = pod.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        namespace = str(metadata.get("namespace") or "default")
        name = str(metadata.get("name") or "unknown")
        return f"Pod/{namespace}/{name}"

    @staticmethod
    def _pass(resource_id: str, check_id: str, title: str) -> Finding:
        return KubernetesClusterScanner._finding(
            resource_id,
            check_id,
            Severity.PASS,
            title,
            title + ".",
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
        normalized_check_id = check_id.replace(
            "kubernetes.manifest.",
            "kubernetes.cluster.",
            1,
        )
        return Finding(
            check_id=normalized_check_id,
            provider="kubernetes",
            service="cluster",
            resource_type="kubernetes_live_resource",
            resource_id=resource_id,
            severity=severity,
            title=title.replace("Kubernetes workload", "Live Kubernetes Pod"),
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )

    def _availability_info(self, message: str) -> Finding:
        return self._finding(
            "cluster",
            "kubernetes.cluster.connection",
            Severity.INFO,
            "Kubernetes live-cluster inspection is not available",
            (
                "Blacklight could not use kubectl. Static Kubernetes manifest scanning remains "
                "available independently."
            ),
            evidence={"reason": message},
        )

    def _error(self, stage: str, message: str) -> Finding:
        return self._finding(
            "cluster",
            f"kubernetes.cluster.{stage}",
            Severity.ERROR,
            f"Blacklight could not complete Kubernetes {stage.replace('_', ' ')}",
            message,
            "Verify kubectl access and read permissions for the selected cluster context, then retry.",
        )
