import json
import subprocess
from unittest.mock import patch

from blacklight_security.cli import main


def test_kubernetes_cli_reports_provider_and_can_gate(tmp_path, capsys):
    (tmp_path / "pod.yaml").write_text(
        """
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
spec:
  containers:
    - name: app
      image: alpine:3.21
      securityContext:
        runAsUser: 0
""".strip(),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            "kubernetes",
            "--path",
            str(tmp_path),
            "--fail-on",
            "high",
        ]
    )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Provider: kubernetes" in output.out


def test_k8s_alias_works(tmp_path):
    (tmp_path / "pod.yml").write_text(
        """
apiVersion: v1
kind: Pod
metadata:
  name: safe
spec:
  containers:
    - name: app
      image: alpine:3.21
      securityContext:
        runAsUser: 1000
""".strip(),
        encoding="utf-8",
    )

    assert main(["scan", "k8s", "--path", str(tmp_path)]) == 0


def test_kubernetes_missing_manifest_returns_two(tmp_path):
    assert main(["scan", "kubernetes", "--path", str(tmp_path)]) == 2


def test_kubernetes_cli_can_run_live_cluster_scanner_and_gate_privileged_pod(capsys):
    pod = {
        "metadata": {"name": "root-pod", "namespace": "default"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "alpine:3.21",
                    "securityContext": {"privileged": True},
                }
            ]
        },
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{"gitVersion":"v1.34.0"}}', ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": [pod]}), ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": []}), ""),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ) as run:
        exit_code = main(
            [
                "scan",
                "kubernetes",
                "--service",
                "cluster",
                "--context",
                "production",
                "--fail-on",
                "critical",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Scanners: cluster" in output.out
    assert "privileged container" in output.out.lower()
    assert all(call.kwargs["shell"] is False for call in run.call_args_list)


def test_kubernetes_cli_default_remains_static_manifest_scan(tmp_path):
    (tmp_path / "pod.yaml").write_text(
        """
apiVersion: v1
kind: Pod
metadata:
  name: safe
spec:
  containers:
    - name: app
      image: alpine:3.21
      securityContext:
        runAsUser: 1000
""".strip(),
        encoding="utf-8",
    )

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run"
    ) as kubectl_run:
        exit_code = main(["scan", "kubernetes", "--path", str(tmp_path)])

    assert exit_code == 0
    kubectl_run.assert_not_called()


def test_kubernetes_cluster_json_context_records_selected_context(capsys):
    responses = [
        subprocess.CompletedProcess([], 0, '{"clientVersion":{"gitVersion":"v1.34.0"}}', ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": []}), ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": []}), ""),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ):
        exit_code = main(
            [
                "scan",
                "kubernetes",
                "--service",
                "cluster",
                "--context",
                "production",
                "--format",
                "json",
            ]
        )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["scan"]["context"]["profile"] == "production"


def test_kubernetes_cli_can_run_rbac_scanner_and_gate_wildcard_binding(capsys):
    cluster_roles = {
        "items": [
            {
                "metadata": {"name": "dangerous"},
                "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
            }
        ]
    }
    bindings = {
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
        subprocess.CompletedProcess([], 0, json.dumps(cluster_roles), ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": []}), ""),
        subprocess.CompletedProcess([], 0, json.dumps(bindings), ""),
        subprocess.CompletedProcess([], 0, json.dumps({"items": []}), ""),
    ]

    with patch(
        "blacklight_security.scanners.kubernetes.cluster.subprocess.run",
        side_effect=responses,
    ) as run:
        exit_code = main(
            [
                "scan",
                "kubernetes",
                "--service",
                "rbac",
                "--context",
                "production",
                "--fail-on",
                "high",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Scanners: rbac" in output.out
    assert "wildcard verbs and resources" in output.out
    assert all(call.kwargs["shell"] is False for call in run.call_args_list)
