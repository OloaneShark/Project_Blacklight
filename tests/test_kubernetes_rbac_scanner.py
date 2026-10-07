from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from blacklight_security.models import Severity
from blacklight_security.scanners.kubernetes.manifests import KubernetesScanTarget
from blacklight_security.scanners.kubernetes.rbac import KubernetesRBACScanner


def _cp(payload):
    return subprocess.CompletedProcess([], 0, json.dumps(payload), "")


def test_rbac_scanner_flags_dangerous_permissions_only_when_bound():
    cluster_roles = {
        "items": [
            {
                "metadata": {"name": "dangerous"},
                "rules": [
                    {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
                    {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
                    {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]},
                    {"apiGroups": [""], "resources": ["users"], "verbs": ["impersonate"]},
                ],
            },
            {
                "metadata": {"name": "unused-dangerous"},
                "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
            },
        ]
    }
    cluster_role_bindings = {
        "items": [
            {
                "metadata": {"name": "dangerous-binding"},
                "roleRef": {"kind": "ClusterRole", "name": "dangerous"},
                "subjects": [{"kind": "User", "name": "alice"}],
            }
        ]
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp(cluster_roles),
        _cp({"items": []}),
        _cp(cluster_role_bindings),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesRBACScanner(
            KubernetesScanTarget(path=".", context_name="prod")
        ).scan()

    by_id = {finding.check_id: finding for finding in findings}
    assert by_id["kubernetes.rbac.bound_wildcard"].severity is Severity.HIGH
    assert by_id["kubernetes.rbac.secret_read"].severity is Severity.HIGH
    assert by_id["kubernetes.rbac.pod_exec"].severity is Severity.HIGH
    assert by_id["kubernetes.rbac.impersonate"].severity is Severity.HIGH
    assert all("unused-dangerous" not in finding.resource_id for finding in findings)


def test_rbac_scanner_flags_cluster_admin_to_unauthenticated_as_critical():
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp({"items": [{"metadata": {"name": "cluster-admin"}, "rules": []}]}),
        _cp({"items": []}),
        _cp(
            {
                "items": [
                    {
                        "metadata": {"name": "bad-admin"},
                        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                        "subjects": [{"kind": "Group", "name": "system:unauthenticated"}],
                    }
                ]
            }
        ),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesRBACScanner(KubernetesScanTarget(path=".")).scan()

    finding = next(
        item
        for item in findings
        if item.check_id == "kubernetes.rbac.cluster_admin_broad_subject"
    )
    assert finding.severity is Severity.CRITICAL


def test_rbac_scanner_reports_pass_when_no_selected_dangerous_bound_grants_exist():
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp(
            {
                "items": [
                    {
                        "metadata": {"name": "reader"},
                        "rules": [
                            {
                                "apiGroups": [""],
                                "resources": ["pods"],
                                "verbs": ["get", "list"],
                            }
                        ],
                    }
                ]
            }
        ),
        _cp({"items": []}),
        _cp(
            {
                "items": [
                    {
                        "metadata": {"name": "reader-binding"},
                        "roleRef": {"kind": "ClusterRole", "name": "reader"},
                        "subjects": [{"kind": "User", "name": "bob"}],
                    }
                ]
            }
        ),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesRBACScanner(KubernetesScanTarget(path=".")).scan()

    assert len(findings) == 1
    assert findings[0].check_id == "kubernetes.rbac.bound_privilege"
    assert findings[0].severity is Severity.PASS


def test_rbac_scanner_keeps_read_permission_failure_as_coverage_error():
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{}}', ""),
        _cp({"items": []}),
        subprocess.CompletedProcess([], 1, "", "forbidden: cannot list roles"),
        _cp({"items": []}),
        _cp({"items": []}),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        findings = KubernetesRBACScanner(KubernetesScanTarget(path=".")).scan()

    assert any(
        finding.check_id == "kubernetes.rbac.roles"
        and finding.severity is Severity.ERROR
        for finding in findings
    )
