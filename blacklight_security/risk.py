from __future__ import annotations

from dataclasses import dataclass, field

from blacklight_security.models import Finding, Severity


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
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


def assess_risk(findings: list[Finding]) -> RiskAssessment:
    actionable = [f for f in findings if f.severity in SEVERITY_WEIGHTS]
    base_score = min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in actionable))
    correlations: list[Correlation] = []

    by_resource: dict[str, set[str]] = {}
    for finding in actionable:
        by_resource.setdefault(finding.resource_id, set()).add(finding.check_id)

    for resource_id, checks in by_resource.items():
        if {"aws.rds.public_access", "aws.rds.storage_encryption"}.issubset(checks):
            correlations.append(
                Correlation(
                    "aws.rds.public_and_unencrypted",
                    20,
                    "The same RDS instance is publicly accessible and lacks storage encryption.",
                    (resource_id,),
                )
            )
        if {"aws.s3.public_policy", "aws.s3.access_logging"}.issubset(checks):
            correlations.append(
                Correlation(
                    "aws.s3.public_without_access_logging",
                    10,
                    "The same S3 bucket has a public policy finding and lacks server access logging.",
                    (resource_id,),
                )
            )

    cloudtrail_gap = any(
        f.check_id == "aws.cloudtrail.logging" and f.severity is Severity.HIGH
        for f in actionable
    )
    critical_elsewhere = [
        f for f in actionable if f.severity is Severity.CRITICAL and f.service != "cloudtrail"
    ]
    if cloudtrail_gap and critical_elsewhere:
        resources = tuple(sorted({f.resource_id for f in critical_elsewhere}))
        correlations.append(
            Correlation(
                "aws.critical_findings_with_cloudtrail_gap",
                15,
                "Critical findings exist while a CloudTrail trail is not actively logging, reducing forensic visibility.",
                resources,
            )
        )

    score = min(100, base_score + sum(item.points for item in correlations))
    return RiskAssessment(score, _level(score), base_score, tuple(correlations))
