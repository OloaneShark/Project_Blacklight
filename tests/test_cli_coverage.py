from types import SimpleNamespace
from unittest.mock import patch

from blacklight_security.cli import main
from blacklight_security.coverage import assess_coverage
from blacklight_security.models import Finding, Severity


def _result(status: str, coverage, findings=None):
    return SimpleNamespace(
        findings=findings or [],
        status=status,
        coverage=coverage,
    )


def _high_finding() -> Finding:
    return Finding(
        check_id="test.high",
        provider="aws",
        service="s3",
        resource_type="resource",
        resource_id="example",
        severity=Severity.HIGH,
        title="High finding",
        description="Test high-severity finding.",
    )


def test_cli_returns_two_when_all_selected_scanners_fail():
    result = _result("FAILED", assess_coverage(["s3"], {"s3": 1}))

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(["scan", "aws"])

    assert exit_code == 2


def test_cli_keeps_partial_coverage_as_success_without_coverage_gate():
    result = _result(
        "PARTIAL",
        assess_coverage(["s3", "iam"], {"iam": 1}),
    )

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(["scan", "aws"])

    assert exit_code == 0


def test_cli_require_full_coverage_fails_partial_scan():
    result = _result(
        "PARTIAL",
        assess_coverage(["s3", "iam"], {"iam": 1}),
    )

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(["scan", "aws", "--require-full-coverage"])

    assert exit_code == 2


def test_cli_require_full_coverage_passes_full_scan():
    result = _result("COMPLETE", assess_coverage(["s3", "iam"], {}))

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(["scan", "aws", "--require-full-coverage"])

    assert exit_code == 0


def test_coverage_gate_failure_takes_precedence_over_security_gate_failure():
    result = _result(
        "PARTIAL",
        assess_coverage(["s3", "iam"], {"iam": 1}),
        [_high_finding()],
    )

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(
            [
                "scan",
                "aws",
                "--fail-on",
                "high",
                "--require-full-coverage",
            ]
        )

    assert exit_code == 2
