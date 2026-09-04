from blacklight_security.models import Finding, Severity
from blacklight_security.risk import assess_risk


def finding(check_id, service, resource_id, severity):
    return Finding(
        check_id=check_id,
        provider="aws",
        service=service,
        resource_type="test",
        resource_id=resource_id,
        severity=severity,
        title="test",
        description="test",
    )


def test_public_unencrypted_rds_adds_explainable_correlation():
    findings = [
        finding("aws.rds.public_access", "rds", "db-1", Severity.CRITICAL),
        finding("aws.rds.storage_encryption", "rds", "db-1", Severity.HIGH),
    ]

    assessment = assess_risk(findings)

    assert assessment.base_score == 60
    assert assessment.score == 80
    assert assessment.level == "CRITICAL"
    assert assessment.correlations[0].rule_id == "aws.rds.public_and_unencrypted"


def test_cloudtrail_gap_correlates_with_critical_findings():
    findings = [
        finding("aws.cloudtrail.logging", "cloudtrail", "trail-1", Severity.HIGH),
        finding("aws.ec2.security_group_all_ingress", "ec2", "sg-1", Severity.CRITICAL),
    ]

    assessment = assess_risk(findings)

    assert any(
        item.rule_id == "aws.critical_findings_with_cloudtrail_gap"
        for item in assessment.correlations
    )
