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


def test_server_empty_password_and_pam_nullok_correlate():
    findings = [
        Finding(
            check_id="server.auth.empty_password_accounts",
            provider="server",
            service="auth",
            resource_type="linux_server",
            resource_id="audit@server.example:22",
            severity=Severity.HIGH,
            title="test",
            description="test",
        ),
        Finding(
            check_id="server.auth.pam_null_passwords",
            provider="server",
            service="auth",
            resource_type="linux_server",
            resource_id="audit@server.example:22",
            severity=Severity.HIGH,
            title="test",
            description="test",
        ),
    ]

    assessment = assess_risk(findings)

    assert "server.auth.empty_password_with_pam_nullok" in correlation_ids(assessment)
    assert assessment.base_score == 40
    assert assessment.score == 60


def runtime_finding(provider, check_id, service, resource_id, severity):
    return Finding(
        check_id=check_id,
        provider=provider,
        service=service,
        resource_type="test",
        resource_id=resource_id,
        severity=severity,
        title="test",
        description="test",
    )


def test_privileged_docker_socket_container_correlates():
    findings = [
        runtime_finding(
            "docker",
            "docker.daemon.privileged",
            "daemon",
            "container/app/abc123",
            Severity.CRITICAL,
        ),
        runtime_finding(
            "docker",
            "docker.daemon.docker_socket_mount",
            "daemon",
            "container/app/abc123",
            Severity.CRITICAL,
        ),
    ]

    assessment = assess_risk(findings)

    assert "docker.daemon.privileged_with_docker_socket" in correlation_ids(assessment)


def test_privileged_published_docker_container_correlates():
    findings = [
        runtime_finding(
            "docker",
            "docker.daemon.privileged",
            "daemon",
            "container/app/abc123",
            Severity.CRITICAL,
        ),
        runtime_finding(
            "docker",
            "docker.daemon.nonloopback_publish",
            "daemon",
            "container/app/abc123",
            Severity.LOW,
        ),
    ]

    assessment = assess_risk(findings)

    assert (
        "docker.daemon.privileged_with_nonloopback_publish"
        in correlation_ids(assessment)
    )


def test_docker_runtime_correlation_does_not_cross_containers():
    findings = [
        runtime_finding(
            "docker",
            "docker.daemon.privileged",
            "daemon",
            "container/app/abc123",
            Severity.CRITICAL,
        ),
        runtime_finding(
            "docker",
            "docker.daemon.nonloopback_publish",
            "daemon",
            "container/web/def456",
            Severity.LOW,
        ),
    ]

    assessment = assess_risk(findings)

    assert (
        "docker.daemon.privileged_with_nonloopback_publish"
        not in correlation_ids(assessment)
    )


def test_privileged_kubernetes_hostpath_pod_correlates():
    findings = [
        runtime_finding(
            "kubernetes",
            "kubernetes.cluster.privileged_container",
            "cluster",
            "Pod/default/app",
            Severity.CRITICAL,
        ),
        runtime_finding(
            "kubernetes",
            "kubernetes.cluster.host_path",
            "cluster",
            "Pod/default/app",
            Severity.HIGH,
        ),
    ]

    assessment = assess_risk(findings)

    assert "kubernetes.cluster.privileged_with_host_path" in correlation_ids(assessment)


def test_privileged_kubernetes_hostport_pod_correlates():
    findings = [
        runtime_finding(
            "kubernetes",
            "kubernetes.cluster.privileged_container",
            "cluster",
            "Pod/default/app",
            Severity.CRITICAL,
        ),
        runtime_finding(
            "kubernetes",
            "kubernetes.cluster.host_port",
            "cluster",
            "Pod/default/app",
            Severity.MEDIUM,
        ),
    ]

    assessment = assess_risk(findings)

    assert "kubernetes.cluster.privileged_with_host_port" in correlation_ids(assessment)


def test_kubernetes_runtime_correlation_does_not_cross_pods():
    findings = [
        runtime_finding(
            "kubernetes",
            "kubernetes.cluster.privileged_container",
            "cluster",
            "Pod/default/app",
            Severity.CRITICAL,
        ),
        runtime_finding(
            "kubernetes",
            "kubernetes.cluster.host_path",
            "cluster",
            "Pod/default/other",
            Severity.HIGH,
        ),
    ]

    assessment = assess_risk(findings)

    assert "kubernetes.cluster.privileged_with_host_path" not in correlation_ids(
        assessment
    )


def test_root_docker_container_with_writable_sensitive_mount_correlates():
    findings = [
        runtime_finding(
            "docker",
            "docker.daemon.root_user",
            "daemon",
            "container/app/abc123",
            Severity.HIGH,
        ),
        Finding(
            check_id="docker.daemon.sensitive_host_mount",
            provider="docker",
            service="daemon",
            resource_type="docker_container",
            resource_id="container/app/abc123",
            severity=Severity.HIGH,
            title="test",
            description="test",
            evidence={
                "writable_mounts": [
                    {
                        "source": "/etc",
                        "destination": "/host-etc",
                        "read_write": True,
                    }
                ]
            },
        ),
    ]

    assessment = assess_risk(findings)

    assert (
        "docker.daemon.root_with_writable_sensitive_host_mount"
        in correlation_ids(assessment)
    )


def test_root_docker_container_with_readonly_sensitive_mount_does_not_correlate():
    findings = [
        runtime_finding(
            "docker",
            "docker.daemon.root_user",
            "daemon",
            "container/app/abc123",
            Severity.HIGH,
        ),
        Finding(
            check_id="docker.daemon.sensitive_host_mount",
            provider="docker",
            service="daemon",
            resource_type="docker_container",
            resource_id="container/app/abc123",
            severity=Severity.MEDIUM,
            title="test",
            description="test",
            evidence={"writable_mounts": []},
        ),
    ]

    assessment = assess_risk(findings)

    assert (
        "docker.daemon.root_with_writable_sensitive_host_mount"
        not in correlation_ids(assessment)
    )
