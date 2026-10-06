from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from blacklight_security.models import Severity
from blacklight_security.scanners.kubernetes.cluster import KubernetesClusterScanner
from blacklight_security.scanners.kubernetes.manifests import KubernetesScanTarget


def _pod(
    name: str = "app",
    namespace: str = "default",
    *,
    privileged: bool = False,
) -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "example/app:1.0",
                    "securityContext": {
                        "privileged": privileged,
                        "runAsUser": 1000,
                        "allowPrivilegeEscalation": False,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                }
            ]
        },
    }


def test_live_cluster_scanner_reuses_workload_checks_and_service_exposure():
    pod = _pod(privileged=True)
    service = {
        "metadata": {"name": "web", "namespace": "default"},
        "spec": {"type": "LoadBalancer", "externalIPs": []},
        "status": {
            "loadBalancer": {
                "ingress": [{"ip": "203.0.113.10"}],
            }
        },
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{"gitVersion":"v1.34.0"}}', ""),
        subprocess.CompletedProcess([], 0, "prod", ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": [pod]}), ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": [service]}), ""),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesClusterScanner(
            KubernetesScanTarget(path=".", context_name=None)
        ).scan()

    by_id = {finding.check_id: finding for finding in findings}
    assert by_id["kubernetes.cluster.privileged_container"].severity is Severity.CRITICAL
    assert by_id["kubernetes.cluster.external_service"].severity is Severity.LOW
    assert by_id["kubernetes.cluster.external_service"].evidence["context"] == "prod"
    assert (
        by_id["kubernetes.cluster.external_service"].evidence["services"][0]["resource"]
        == "Service/default/web"
    )


def test_live_cluster_scanner_respects_explicit_context_and_shell_false():
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{"gitVersion":"v1.34.0"}}', ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": [_pod()]}), ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": []}), ""),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ) as run:
        findings = KubernetesClusterScanner(
            KubernetesScanTarget(path=".", context_name="production")
        ).scan()

    assert findings
    commands = [call.args[0] for call in run.call_args_list]
    assert all(command[:3] == ["kubectl", "--context", "production"] for command in commands)
    assert all(call.kwargs["shell"] is False for call in run.call_args_list)
    assert not any("current-context" in command for command in commands)


def test_live_cluster_scanner_reports_info_when_kubectl_is_missing():
    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=FileNotFoundError,
    ):
        findings = KubernetesClusterScanner(KubernetesScanTarget(path=".")).scan()

    assert len(findings) == 1
    assert findings[0].check_id == "kubernetes.cluster.connection"
    assert findings[0].severity is Severity.INFO


def test_live_cluster_scanner_keeps_service_permission_failure_as_coverage_error():
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{"gitVersion":"v1.34.0"}}', ""),
        subprocess.CompletedProcess([], 0, "prod", ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": [_pod()]}), ""),
        subprocess.CompletedProcess([], 1, "", "forbidden: cannot list services"),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesClusterScanner(KubernetesScanTarget(path=".")).scan()

    assert any(
        finding.check_id == "kubernetes.cluster.service_inventory"
        and finding.severity is Severity.ERROR
        for finding in findings
    )
