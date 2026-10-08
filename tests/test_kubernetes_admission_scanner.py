from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from blacklight_security.models import Severity
from blacklight_security.scanners.kubernetes.admission import KubernetesAdmissionScanner
from blacklight_security.scanners.kubernetes.manifests import KubernetesScanTarget


def _cp(payload):
    return subprocess.CompletedProcess([], 0, json.dumps(payload), "")


def test_admission_scanner_reports_psa_levels_and_skips_system_namespace_noise():
    namespaces = {
        "items": [
            {
                "metadata": {
                    "name": "team-a",
                    "labels": {"pod-security.kubernetes.io/enforce": "privileged"},
                }
            },
            {
                "metadata": {
                    "name": "team-b",
                    "labels": {"pod-security.kubernetes.io/enforce": "restricted"},
                }
            },
            {"metadata": {"name": "team-c", "labels": {}}},
            {"metadata": {"name": "kube-system", "labels": {}}},
        ]
    }
    pods = {
        "items": [
            {"metadata": {"name": "a", "namespace": "team-a"}},
            {"metadata": {"name": "b", "namespace": "team-b"}},
            {"metadata": {"name": "c", "namespace": "team-c"}},
            {"metadata": {"name": "sys", "namespace": "kube-system"}},
        ]
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp(namespaces),
        _cp(pods),
        _cp({"items": []}),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesAdmissionScanner(KubernetesScanTarget(path=".")).scan()

    by_resource = {finding.resource_id: finding for finding in findings if finding.resource_id.startswith("Namespace/")}
    assert by_resource["Namespace/team-a"].severity is Severity.MEDIUM
    assert by_resource["Namespace/team-b"].severity is Severity.PASS
    assert by_resource["Namespace/team-c"].severity is Severity.LOW
    assert "Namespace/kube-system" not in by_resource


def test_admission_scanner_flags_broad_fail_open_webhook_as_medium():
    validating = {
        "items": [
            {
                "metadata": {"name": "policy"},
                "webhooks": [
                    {
                        "name": "policy.example.com",
                        "failurePolicy": "Ignore",
                        "rules": [
                            {
                                "operations": ["*"],
                                "apiGroups": ["*"],
                                "apiVersions": ["*"],
                                "resources": ["*"],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp({"items": []}),
        _cp({"items": []}),
        _cp(validating),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesAdmissionScanner(KubernetesScanTarget(path=".")).scan()

    finding = next(
        item
        for item in findings
        if item.check_id == "kubernetes.admission.fail_open_broad_webhook"
    )
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["broad_match"] is True


def test_admission_scanner_flags_narrow_fail_open_webhook_as_low():
    mutating = {
        "items": [
            {
                "metadata": {"name": "injector"},
                "webhooks": [
                    {
                        "name": "injector.example.com",
                        "failurePolicy": "Ignore",
                        "rules": [
                            {
                                "operations": ["CREATE"],
                                "apiGroups": [""],
                                "apiVersions": ["v1"],
                                "resources": ["pods"],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp({"items": []}),
        _cp({"items": []}),
        _cp({"items": []}),
        _cp(mutating),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesAdmissionScanner(KubernetesScanTarget(path=".")).scan()

    finding = next(
        item
        for item in findings
        if item.check_id == "kubernetes.admission.fail_open_webhook"
        and item.severity is Severity.LOW
    )
    assert finding.evidence["broad_match"] is False


def test_admission_scanner_keeps_partial_permission_gap_and_other_results():
    namespaces = {
        "items": [{"metadata": {"name": "team-a", "labels": {}}}]
    }
    pods = {
        "items": [{"metadata": {"name": "a", "namespace": "team-a"}}]
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp(namespaces),
        _cp(pods),
        subprocess.CompletedProcess([], 1, "", "forbidden: cannot list validating webhooks"),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesAdmissionScanner(KubernetesScanTarget(path=".")).scan()

    assert any(
        finding.check_id == "kubernetes.admission.validatingwebhooks"
        and finding.severity is Severity.ERROR
        for finding in findings
    )
    assert any(
        finding.check_id == "kubernetes.admission.psa_enforce_missing"
        and finding.severity is Severity.LOW
        for finding in findings
    )
