from types import SimpleNamespace
from unittest.mock import patch

from blacklight_security.cli import main


def test_cli_returns_two_when_all_selected_scanners_fail():
    result = SimpleNamespace(findings=[], status="FAILED")

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(["scan", "aws"])

    assert exit_code == 2


def test_cli_keeps_partial_coverage_as_success_without_security_gate_failure():
    result = SimpleNamespace(findings=[], status="PARTIAL")

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=result),
        patch("blacklight_security.cli.render_console", return_value="report"),
    ):
        exit_code = main(["scan", "aws"])

    assert exit_code == 0
