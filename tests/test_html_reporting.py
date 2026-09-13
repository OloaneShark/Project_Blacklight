from datetime import datetime, timedelta, timezone

from blacklight_security.html_reporting import render_html
from blacklight_security.models import Finding, Severity
from blacklight_security.policy import evaluate_policy
from blacklight_security.runner import ScanResult


def _result() -> ScanResult:
    started = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)
    findings = [
        Finding(
            check_id="test.public",
            provider="aws",
            service="s3",
            resource_type="bucket",
            resource_id="bucket-<unsafe>",
            severity=Severity.HIGH,
            title="Public <script>alert('x')</script>",
            description="Resource has public access & needs review.",
            remediation="Disable <public> access.",
            evidence={"policy": "<unsafe>&value"},
        ),
        Finding(
            check_id="test.pass",
            provider="aws",
            service="iam",
            resource_type="account",
            resource_id="root",
            severity=Severity.PASS,
            title="Root MFA enabled",
            description="Root MFA is enabled.",
        ),
    ]
    return ScanResult(
        provider="aws",
        requested_service="all",
        region="us-east-1",
        scanners=["s3", "iam"],
        findings=findings,
        started_at=started,
        completed_at=started + timedelta(milliseconds=125),
    )


def test_html_report_contains_scan_risk_policy_and_findings():
    result = _result()
    policy = evaluate_policy(result.findings, "high")

    report = render_html(result, policy)

    assert report.startswith("<!doctype html>")
    assert "Project Blacklight" in report
    assert "CI/CD Security Gate" in report
    assert "FAIL" in report
    assert "us-east-1" in report
    assert "s3, iam" in report
    assert "125 ms" in report
    assert "test.public" in report
    assert "Root MFA enabled" in report


def test_html_report_escapes_finding_and_evidence_values():
    report = render_html(_result())

    assert "<script>alert('x')</script>" not in report
    assert "Public &lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in report
    assert "bucket-&lt;unsafe&gt;" in report
    assert "&lt;unsafe&gt;&amp;value" in report
