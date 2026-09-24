from blacklight_security.desktop.controller import DesktopScanRequest, run_scan, write_report
from blacklight_security.models import Severity


def test_desktop_docker_scan_uses_shared_blacklight_engine(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:latest\nUSER root\n",
        encoding="utf-8",
    )

    outcome = run_scan(
        DesktopScanRequest(
            provider="docker",
            path=tmp_path,
            fail_on="high",
            require_full_coverage=True,
        )
    )

    assert outcome.result.provider == "docker"
    assert outcome.result.coverage.status == "FULL"
    assert outcome.policy.enabled is True
    assert outcome.policy.passed is False
    assert outcome.coverage_gate.enabled is True
    assert outcome.coverage_gate.passed is True
    assert any(
        finding.check_id == "docker.dockerfile.root_user"
        and finding.severity is Severity.HIGH
        for finding in outcome.result.findings
    )


def test_desktop_kubernetes_scan_and_report_export(tmp_path):
    manifest = tmp_path / "pod.yaml"
    manifest.write_text(
        """
apiVersion: v1
kind: Pod
metadata:
  name: sample
spec:
  containers:
    - name: app
      image: alpine:3.21
      securityContext:
        runAsUser: 1000
""".strip(),
        encoding="utf-8",
    )

    outcome = run_scan(
        DesktopScanRequest(
            provider="kubernetes",
            path=tmp_path,
        )
    )

    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"

    write_report(outcome, "json", json_path)
    write_report(outcome, "html", html_path)

    assert '"provider": "kubernetes"' in json_path.read_text(encoding="utf-8")
    assert "Project Blacklight" in html_path.read_text(encoding="utf-8")


def test_desktop_report_rejects_unknown_format(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:3.21\nUSER 1000\n",
        encoding="utf-8",
    )
    outcome = run_scan(DesktopScanRequest(provider="docker", path=tmp_path))

    try:
        write_report(outcome, "pdf", tmp_path / "report.pdf")  # type: ignore[arg-type]
    except ValueError as error:
        assert "Unsupported desktop report format" in str(error)
    else:
        raise AssertionError("Expected unsupported desktop report format to fail")
