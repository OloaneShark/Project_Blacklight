from unittest.mock import patch

from blacklight_security.models import Finding, Severity
from blacklight_security.registry import ScannerSpec
from blacklight_security.runner import ScanRunner


class FakeSession:
    region_name = "us-east-1"


class HealthyScanner:
    def __init__(self, session):
        self.session = session

    def scan(self):
        return [
            Finding(
                check_id="test.healthy",
                provider="aws",
                service="test",
                resource_type="resource",
                resource_id="example",
                severity=Severity.PASS,
                title="Healthy",
                description="Test resource passed.",
            )
        ]


class ErrorScanner:
    def __init__(self, session):
        self.session = session

    def scan(self):
        return [
            Finding(
                check_id="test.error",
                provider="aws",
                service="test",
                resource_type="resource",
                resource_id="example",
                severity=Severity.ERROR,
                title="Could not inspect resource",
                description="Test inspection failed.",
            )
        ]


def test_runner_collects_metadata_and_findings():
    specs = [ScannerSpec("aws", "healthy", HealthyScanner)]

    with patch("blacklight_security.runner.scanner_specs", return_value=specs):
        result = ScanRunner("aws", FakeSession()).run("all")

    assert result.status == "COMPLETE"
    assert result.region == "us-east-1"
    assert result.scanners == ["healthy"]
    assert len(result.findings) == 1
    assert result.metadata_dict()["scanner_count"] == 1


def test_runner_marks_scan_partial_when_scanner_returns_error():
    specs = [ScannerSpec("aws", "broken", ErrorScanner)]

    with patch("blacklight_security.runner.scanner_specs", return_value=specs):
        result = ScanRunner("aws", FakeSession()).run("all")

    assert result.status == "PARTIAL"
