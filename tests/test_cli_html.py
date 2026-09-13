from types import SimpleNamespace
from unittest.mock import patch

from blacklight_security.cli import main
from blacklight_security.models import Finding, Severity


def _result():
    finding = Finding(
        check_id="test.finding",
        provider="aws",
        service="test",
        resource_type="resource",
        resource_id="example",
        severity=Severity.PASS,
        title="Healthy",
        description="Healthy test resource.",
    )
    return SimpleNamespace(findings=[finding])


def test_html_output_requires_output_path():
    exit_code = main(["scan", "aws", "--format", "html"])

    assert exit_code == 2


def test_cli_writes_html_report(tmp_path):
    output = tmp_path / "blacklight-report.html"

    with (
        patch("blacklight_security.cli.boto3.Session"),
        patch("blacklight_security.cli.ScanRunner.run", return_value=_result()),
        patch("blacklight_security.cli.render_html", return_value="<!doctype html><html></html>"),
    ):
        exit_code = main(
            [
                "scan",
                "aws",
                "--format",
                "html",
                "--output",
                str(output),
            ]
        )

    assert exit_code == 0
    assert output.read_text(encoding="utf-8") == "<!doctype html><html></html>\n"
