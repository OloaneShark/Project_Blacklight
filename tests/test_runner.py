from unittest.mock import patch

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity
from blacklight_security.registry import ScannerSpec
from blacklight_security.runner import ScanRunner
from blacklight_security.scan_context import ScanContext


class FakeSession:
    region_name = "us-east-1"
    profile_name = "blacklight-audit"


CONTEXT = ScanContext(
    provider="aws",
    region="us-east-1",
    profile="blacklight-audit",
    identity_status="RESOLVED",
    account_id="123456789012",
    principal_arn="arn:aws:sts::123456789012:assumed-role/BlacklightAudit/session",
    user_id="AROATEST:session",
    partition="aws",
)


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


class RaisingScanner:
    def __init__(self, session):
        self.session = session

    def scan(self):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "DescribeThings",
        )


def test_runner_collects_context_metadata_and_findings():
    specs = [ScannerSpec("aws", "healthy", HealthyScanner)]

    with (
        patch("blacklight_security.runner.scanner_specs", return_value=specs),
        patch("blacklight_security.runner.resolve_scan_context", return_value=CONTEXT),
    ):
        result = ScanRunner("aws", FakeSession()).run("all")

    metadata = result.metadata_dict()
    assert result.status == "COMPLETE"
    assert result.region == "us-east-1"
    assert result.scanners == ["healthy"]
    assert len(result.findings) == 1
    assert metadata["scanner_count"] == 1
    assert metadata["context"]["profile"] == "blacklight-audit"
    assert metadata["context"]["identity"]["account_id"] == "123456789012"
    assert metadata["context"]["identity"]["partition"] == "aws"
    assert metadata["coverage"]["status"] == "FULL"
    assert metadata["coverage"]["risk_confidence"] == "HIGH"
    assert metadata["coverage"]["complete_scanner_percent"] == 100.0


def test_runner_marks_scan_failed_when_only_scanner_returns_error():
    specs = [ScannerSpec("aws", "broken", ErrorScanner)]

    with (
        patch("blacklight_security.runner.scanner_specs", return_value=specs),
        patch("blacklight_security.runner.resolve_scan_context", return_value=CONTEXT),
    ):
        result = ScanRunner("aws", FakeSession()).run("all")

    assert result.status == "FAILED"
    assert result.coverage.status == "LIMITED"
    assert result.coverage.risk_confidence == "LOW"
    assert result.coverage.affected_scanners == ("broken",)


def test_runner_converts_client_error_to_coverage_gap_and_continues():
    specs = [
        ScannerSpec("aws", "broken", RaisingScanner),
        ScannerSpec("aws", "healthy", HealthyScanner),
    ]

    with (
        patch("blacklight_security.runner.scanner_specs", return_value=specs),
        patch("blacklight_security.runner.resolve_scan_context", return_value=CONTEXT),
    ):
        result = ScanRunner("aws", FakeSession()).run("all")

    assert result.status == "PARTIAL"
    assert len(result.findings) == 2
    assert result.findings[0].severity is Severity.ERROR
    assert result.findings[0].check_id == "aws.broken.scanner_execution"
    assert result.findings[0].evidence["provider_error_code"] == "AccessDenied"
    assert result.findings[1].severity is Severity.PASS
    assert result.coverage.status == "PARTIAL"
    assert result.coverage.risk_confidence == "REDUCED"
    assert result.coverage.complete_scanner_count == 1
    assert result.coverage.affected_scanner_count == 1
    assert result.coverage.complete_scanner_percent == 50.0
    assert result.coverage.error_finding_count == 1
