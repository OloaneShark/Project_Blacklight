import json
from datetime import datetime, timezone

from blacklight_security.models import Finding, Severity
from blacklight_security.reporting import render_console, render_json
from blacklight_security.runner import ScanResult
from blacklight_security.scan_context import ScanContext


def _result() -> ScanResult:
    now = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)
    context = ScanContext(
        provider="aws",
        region="us-gov-west-1",
        profile="audit-profile",
        identity_status="RESOLVED",
        account_id="123456789012",
        principal_arn="arn:aws-us-gov:sts::123456789012:assumed-role/Audit/session",
        user_id="AROATEST:session",
        partition="aws-us-gov",
    )
    finding = Finding(
        check_id="test.pass",
        provider="aws",
        service="test",
        resource_type="account",
        resource_id="example",
        severity=Severity.PASS,
        title="Healthy",
        description="Test resource passed.",
    )
    return ScanResult(
        provider="aws",
        requested_service="all",
        region=context.region,
        scanners=["test"],
        findings=[finding],
        started_at=now,
        completed_at=now,
        context=context,
    )


def test_console_report_includes_resolved_identity_context():
    rendered = render_console(_result())

    assert "Profile: audit-profile" in rendered
    assert "Account: 123456789012" in rendered
    assert "Partition: aws-us-gov" in rendered
    assert "Principal: arn:aws-us-gov:sts::123456789012:assumed-role/Audit/session" in rendered
    assert "Identity: RESOLVED" in rendered


def test_json_report_uses_schema_four_and_nested_identity_context():
    payload = json.loads(render_json(_result()))

    assert payload["schema_version"] == "4"
    assert payload["scan"]["context"]["profile"] == "audit-profile"
    identity = payload["scan"]["context"]["identity"]
    assert identity["account_id"] == "123456789012"
    assert identity["partition"] == "aws-us-gov"
    assert identity["status"] == "RESOLVED"
