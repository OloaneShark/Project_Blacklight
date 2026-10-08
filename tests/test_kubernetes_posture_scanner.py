from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from blacklight_security.models import Severity
from blacklight_security.scanners.kubernetes.manifests import KubernetesScanTarget
from blacklight_security.scanners.kubernetes.posture import KubernetesPostureScanner


def _cp(payload):
    return subprocess.CompletedProcess([], 0, json.dumps(payload), "")


def test_posture_scanner_flags_default_serviceaccount_token_and_missing_networkpolicy():
    pods = {
        "items": [
            {
                "metadata": {"name": "app", "namespace": "team-a"},
                "spec": {"serviceAccountName": "default", "containers": []},
            }
        ]
    }
    service_accounts = {
        "items": [
            {
                "metadata": {"name": "default", "namespace": "team-a"},
            }
        ]
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp(pods),
        _cp(service_accounts),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesPostureScanner(
            KubernetesScanTarget(path=".", context_name="prod")
        ).scan()

    by_id = {}
    for finding in findings:
        by_id.setdefault(finding.check_id, []).append(finding)

    token = by_id["kubernetes.posture.default_service_account_token"][0]
    missing = by_id["kubernetes.posture.namespace_without_networkpolicy"][0]
    assert token.severity is Severity.LOW
    assert token.resource_id == "Namespace/team-a"
    assert token.evidence["pod_count"] == 1
    assert missing.severity is Severity.LOW
    assert missing.resource_id == "Namespace/team-a"


def test_posture_scanner_flags_namespace_wide_allow_all_networkpolicy():
    policy = {
        "metadata": {"name": "allow-everything", "namespace": "team-a"},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{}],
            "egress": [{}],
        },
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp({"items": []}),
        _cp({"items": []}),
        _cp({"items": [policy]}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesPostureScanner(KubernetesScanTarget(path=".")).scan()

    finding = next(
        item
        for item in findings
        if item.check_id == "kubernetes.posture.allow_all_networkpolicy"
    )
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["allow_all_directions"] == ["ingress", "egress"]


def test_posture_scanner_passes_default_sa_token_when_pod_disables_automount():
    pods = {
        "items": [
            {
                "metadata": {"name": "app", "namespace": "team-a"},
                "spec": {
                    "serviceAccountName": "default",
                    "automountServiceAccountToken": False,
                    "containers": [],
                },
            }
        ]
    }
    service_accounts = {
        "items": [
            {
                "metadata": {"name": "default", "namespace": "team-a"},
            }
        ]
    }
    policy = {
        "metadata": {"name": "deny-all", "namespace": "team-a"},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp(pods),
        _cp(service_accounts),
        _cp({"items": [policy]}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesPostureScanner(KubernetesScanTarget(path=".")).scan()

    by_id = {finding.check_id: finding for finding in findings}
    assert (
        by_id["kubernetes.posture.default_service_account_token"].severity
        is Severity.PASS
    )
    assert (
        by_id["kubernetes.posture.namespace_without_networkpolicy"].severity
        is Severity.PASS
    )
    assert (
        by_id["kubernetes.posture.allow_all_networkpolicy"].severity
        is Severity.PASS
    )


def test_posture_scanner_keeps_partial_permission_gap_and_other_results():
    pods = {
        "items": [
            {
                "metadata": {"name": "app", "namespace": "team-a"},
                "spec": {"serviceAccountName": "default", "containers": []},
            }
        ]
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp(pods),
        subprocess.CompletedProcess(
            [],
            1,
            "",
            "forbidden: cannot list serviceaccounts",
        ),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesPostureScanner(KubernetesScanTarget(path=".")).scan()

    assert any(
        finding.check_id == "kubernetes.posture.serviceaccounts"
        and finding.severity is Severity.ERROR
        for finding in findings
    )
    assert any(
        finding.check_id == "kubernetes.posture.namespace_without_networkpolicy"
        and finding.severity is Severity.LOW
        for finding in findings
    )


def test_posture_scanner_inventories_custom_serviceaccount_token_usage():
    pods = {
        "items": [
            {
                "metadata": {"name": "api", "namespace": "team-a"},
                "spec": {
                    "serviceAccountName": "deployer",
                    "containers": [],
                },
            }
        ]
    }
    service_accounts = {
        "items": [
            {
                "metadata": {"name": "deployer", "namespace": "team-a"},
            }
        ]
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp(pods),
        _cp(service_accounts),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesPostureScanner(KubernetesScanTarget(path=".")).scan()

    finding = next(
        item
        for item in findings
        if item.check_id == "kubernetes.posture.service_account_token_usage"
        and item.resource_id == "ServiceAccount/team-a/deployer"
    )
    assert finding.severity is Severity.INFO
    assert finding.evidence["service_account"] == "deployer"
    assert finding.evidence["pod_count"] == 1


def test_posture_scanner_does_not_inventory_disabled_custom_serviceaccount_token():
    pods = {
        "items": [
            {
                "metadata": {"name": "api", "namespace": "team-a"},
                "spec": {
                    "serviceAccountName": "deployer",
                    "automountServiceAccountToken": False,
                    "containers": [],
                },
            }
        ]
    }
    service_accounts = {
        "items": [
            {
                "metadata": {"name": "deployer", "namespace": "team-a"},
            }
        ]
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp(pods),
        _cp(service_accounts),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesPostureScanner(KubernetesScanTarget(path=".")).scan()

    token_findings = [
        item
        for item in findings
        if item.check_id == "kubernetes.posture.service_account_token_usage"
    ]
    assert len(token_findings) == 1
    assert token_findings[0].severity is Severity.PASS
