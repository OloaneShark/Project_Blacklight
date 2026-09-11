from __future__ import annotations

from dataclasses import dataclass

from blacklight_security.models import Finding, Severity


SECURITY_SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """Result of applying an optional CI/CD severity threshold to findings."""

    enabled: bool
    fail_on: str | None
    passed: bool
    triggered_count: int
    highest_severity: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "fail_on": self.fail_on,
            "passed": self.passed,
            "triggered_count": self.triggered_count,
            "highest_severity": self.highest_severity,
        }


def evaluate_policy(findings: list[Finding], fail_on: str | None = None) -> PolicyResult:
    security_findings = [
        finding for finding in findings if finding.severity in SECURITY_SEVERITY_RANK
    ]

    highest = max(
        (security_findings),
        key=lambda finding: SECURITY_SEVERITY_RANK[finding.severity],
        default=None,
    )
    highest_severity = highest.severity.value if highest else None

    if fail_on is None:
        return PolicyResult(
            enabled=False,
            fail_on=None,
            passed=True,
            triggered_count=0,
            highest_severity=highest_severity,
        )

    threshold = Severity(fail_on.upper())
    threshold_rank = SECURITY_SEVERITY_RANK[threshold]
    triggered = [
        finding
        for finding in security_findings
        if SECURITY_SEVERITY_RANK[finding.severity] >= threshold_rank
    ]

    return PolicyResult(
        enabled=True,
        fail_on=threshold.value,
        passed=not triggered,
        triggered_count=len(triggered),
        highest_severity=highest_severity,
    )
