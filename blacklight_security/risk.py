from __future__ import annotations

from dataclasses import dataclass, field

from blacklight_security.models import Finding, Severity


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}

CLOUDTRAIL_VISIBILITY_GAP_CHECKS = {
    "aws.cloudtrail.trail_present",
    "aws.cloudtrail.logging",
}

REGIONAL_PUBLIC_EXPOSURE_CHECKS = {
    "aws.ec2.security_group_all_ingress",
    "aws.ec2.security_group_public_sensitive_port",
    "aws.rds.public_access",
    "aws.lambda.function_url_auth",
}


@dataclass(frozen=True, slots=True)
class Correlation:
    rule_id: str
    points: int
    reason: str
    resources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    level: str
    base_score: int
    correlations: tuple[Correlation, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "base_score": self.base_score,
            "correlations": [
                {
                    "rule_id": item.rule_id,
                    "points": item.points,
                    "reason": item.reason,
                    "resources": list(item.resources),
                }
                for item in self.correlations
            ],
        }


def _level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "CLEAR"


def _same_resource_checks(
    findings: list[Finding],
) -> dict[tuple[str, str, str], set[str]]:
    grouped: dict[tuple[str, str, str], set[str]] = {}
    for finding in findings:
        key = (finding.provider, finding.service, finding.resource_id)
        grouped.setdefault(key, set()).add(finding.check_id)
    return grouped


def assess_risk(findings: list[Finding]) -> RiskAssessment:
    actionable = [finding for finding in findings if finding.severity in SEVERITY_WEIGHTS]
    base_score = min(100, sum(SEVERITY_WEIGHTS[finding.severity] for finding in actionable))
    correlations: list[Correlation] = []

    by_resource = _same_resource_checks(actionable)
    for (provider, service, resource_id), checks in by_resource.items():
        if provider != "aws":
            continue

        if service == "rds" and {
            "aws.rds.public_access",
            "aws.rds.storage_encryption",
        }.issubset(checks):
            correlations.append(
                Correlation(
                    "aws.rds.public_and_unencrypted",
                    20,
                    "The same RDS instance is publicly accessible and lacks storage encryption.",
                    (resource_id,),
                )
            )

        if service == "s3" and {
            "aws.s3.public_policy",
            "aws.s3.access_logging",
        }.issubset(checks):
            correlations.append(
                Correlation(
                    "aws.s3.public_without_access_logging",
                    10,
                    "The same S3 bucket has a public policy finding and lacks server access logging.",
                    (resource_id,),
                )
            )

        if service == "s3" and {
            "aws.s3.public_policy",
            "aws.s3.public_access_block",
        }.issubset(checks):
            correlations.append(
                Correlation(
                    "aws.s3.public_policy_without_full_public_access_block",
                    15,
                    "The same S3 bucket is public while bucket-level Block Public Access is not fully enabled.",
                    (resource_id,),
                )
            )

        if service == "iam" and {
            "aws.iam.role_wildcard_policy",
            "aws.iam.role_trust_wildcard",
        }.issubset(checks):
            correlations.append(
                Correlation(
                    "aws.iam.broad_role_permissions_and_trust",
                    20,
                    (
                        "The same IAM role has an unconditional wildcard identity-policy grant "
                        "and an unconditional wildcard trust principal."
                    ),
                    (resource_id,),
                )
            )

    cloudtrail_gaps = [
        finding
        for finding in actionable
        if finding.check_id in CLOUDTRAIL_VISIBILITY_GAP_CHECKS
        and finding.severity in {Severity.HIGH, Severity.CRITICAL}
    ]

    critical_elsewhere = [
        finding
        for finding in actionable
        if finding.severity is Severity.CRITICAL and finding.service != "cloudtrail"
    ]
    if cloudtrail_gaps and critical_elsewhere:
        resources = tuple(sorted({finding.resource_id for finding in critical_elsewhere}))
        correlations.append(
            Correlation(
                "aws.critical_findings_with_cloudtrail_gap",
                15,
                "Critical findings exist while CloudTrail audit visibility has a high-severity gap, reducing forensic coverage.",
                resources,
            )
        )

    root_mfa_gap = any(
        finding.check_id == "aws.iam.root_mfa"
        and finding.severity in {Severity.HIGH, Severity.CRITICAL}
        for finding in actionable
    )
    if root_mfa_gap and cloudtrail_gaps:
        resources = tuple(
            sorted(
                {"root"}
                | {finding.resource_id for finding in cloudtrail_gaps}
            )
        )
        correlations.append(
            Correlation(
                "aws.root_mfa_with_cloudtrail_gap",
                15,
                "Root MFA is not enabled while CloudTrail audit visibility also has a high-severity gap.",
                resources,
            )
        )

    guardduty_gaps = [
        finding
        for finding in actionable
        if finding.check_id == "aws.guardduty.detector_enabled"
        and finding.severity in {Severity.HIGH, Severity.CRITICAL}
    ]
    regional_public_exposures = [
        finding
        for finding in actionable
        if finding.check_id in REGIONAL_PUBLIC_EXPOSURE_CHECKS
        and finding.severity in {Severity.HIGH, Severity.CRITICAL}
    ]
    if guardduty_gaps and regional_public_exposures:
        resources = tuple(
            sorted({finding.resource_id for finding in regional_public_exposures})
        )
        correlations.append(
            Correlation(
                "aws.regional_public_exposure_with_guardduty_gap",
                15,
                "Internet-exposed regional AWS resources exist while GuardDuty threat detection is not enabled in the scanned region.",
                resources,
            )
        )

    score = min(100, base_score + sum(item.points for item in correlations))
    return RiskAssessment(score, _level(score), base_score, tuple(correlations))
