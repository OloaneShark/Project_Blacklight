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
