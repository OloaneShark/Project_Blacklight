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


def correlation_ids(assessment):
    return {item.rule_id for item in assessment.correlations}


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


def test_cloudtrail_logging_gap_correlates_with_critical_findings():
    findings = [
        finding("aws.cloudtrail.logging", "cloudtrail", "trail-1", Severity.HIGH),
        finding("aws.ec2.security_group_all_ingress", "ec2", "sg-1", Severity.CRITICAL),
    ]

    assessment = assess_risk(findings)

    assert "aws.critical_findings_with_cloudtrail_gap" in correlation_ids(assessment)


def test_missing_cloudtrail_also_counts_as_visibility_gap():
    findings = [
        finding("aws.cloudtrail.trail_present", "cloudtrail", "aws-account", Severity.HIGH),
        finding("aws.ec2.security_group_all_ingress", "ec2", "sg-1", Severity.CRITICAL),
    ]

    assessment = assess_risk(findings)

    assert "aws.critical_findings_with_cloudtrail_gap" in correlation_ids(assessment)


def test_public_s3_policy_without_full_block_public_access_correlates():
    findings = [
        finding("aws.s3.public_policy", "s3", "bucket-a", Severity.CRITICAL),
        finding("aws.s3.public_access_block", "s3", "bucket-a", Severity.HIGH),
    ]

    assessment = assess_risk(findings)

    assert (
        "aws.s3.public_policy_without_full_public_access_block"
        in correlation_ids(assessment)
    )


def test_same_resource_rules_do_not_cross_between_buckets():
    findings = [
        finding("aws.s3.public_policy", "s3", "bucket-a", Severity.CRITICAL),
        finding("aws.s3.public_access_block", "s3", "bucket-b", Severity.HIGH),
    ]

    assessment = assess_risk(findings)

    assert (
        "aws.s3.public_policy_without_full_public_access_block"
        not in correlation_ids(assessment)
    )


def test_root_mfa_and_cloudtrail_gap_correlate():
    findings = [
        finding("aws.iam.root_mfa", "iam", "root", Severity.HIGH),
        finding("aws.cloudtrail.trail_present", "cloudtrail", "aws-account", Severity.HIGH),
    ]

    assessment = assess_risk(findings)

    assert "aws.root_mfa_with_cloudtrail_gap" in correlation_ids(assessment)


def test_regional_public_exposure_and_guardduty_gap_correlate():
    findings = [
        finding("aws.lambda.function_url_auth", "lambda", "public-fn", Severity.HIGH),
        finding(
            "aws.guardduty.detector_enabled",
            "guardduty",
            "us-east-1",
            Severity.HIGH,
        ),
    ]

    assessment = assess_risk(findings)

    assert (
        "aws.regional_public_exposure_with_guardduty_gap"
        in correlation_ids(assessment)
    )


def test_s3_public_policy_does_not_use_regional_guardduty_correlation():
    findings = [
        finding("aws.s3.public_policy", "s3", "bucket-a", Severity.CRITICAL),
        finding(
            "aws.guardduty.detector_enabled",
            "guardduty",
            "us-east-1",
            Severity.HIGH,
        ),
    ]

    assessment = assess_risk(findings)

    assert (
        "aws.regional_public_exposure_with_guardduty_gap"
        not in correlation_ids(assessment)
    )


def test_broad_iam_role_permissions_and_trust_correlate():
    findings = [
        finding("aws.iam.role_wildcard_policy", "iam", "deploy-role", Severity.HIGH),
        finding("aws.iam.role_trust_wildcard", "iam", "deploy-role", Severity.HIGH),
    ]

    assessment = assess_risk(findings)

    assert "aws.iam.broad_role_permissions_and_trust" in correlation_ids(assessment)


def test_iam_role_trust_does_not_correlate_across_different_roles():
    findings = [
        finding("aws.iam.role_wildcard_policy", "iam", "role-a", Severity.HIGH),
        finding("aws.iam.role_trust_wildcard", "iam", "role-b", Severity.HIGH),
    ]

    assessment = assess_risk(findings)

    assert "aws.iam.broad_role_permissions_and_trust" not in correlation_ids(assessment)
