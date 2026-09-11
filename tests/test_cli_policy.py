from types import SimpleNamespace
from unittest.mock import patch

from blacklight_security.cli import main
from blacklight_security.models import Finding, Severity


def _finding(severity: Severity) -> Finding:
    return Finding(
        check_id="test.finding",
        provider="aws",
        service="test",
        resource_type="resource",
        resource_id="example",
        severity=severity,
        title="Test finding",
        description="Test finding.",
    )


def test_cli_returns_one_when_fail_on_threshold_is_hit():
    result = SimpleNamespace(findings=[_finding(Severity.HIGH)])

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(["scan", "aws", "--fail-on", "high"])

    assert exit_code == 1


def test_cli_returns_zero_when_threshold_is_not_hit():
    result = SimpleNamespace(findings=[_finding(Severity.MEDIUM)])

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(["scan", "aws", "--fail-on", "high"])

    assert exit_code == 0


def test_cli_without_gate_preserves_normal_success_exit():
    result = SimpleNamespace(findings=[_finding(Severity.CRITICAL)])

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(["scan", "aws"])

    assert exit_code == 0
