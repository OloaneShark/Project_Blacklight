from blacklight_security.models import Finding, Severity
from blacklight_security.policy import evaluate_policy


def _finding(severity: Severity, name: str) -> Finding:
    return Finding(
        check_id=f"test.{name}",
        provider="aws",
        service="test",
        resource_type="resource",
        resource_id=name,
        severity=severity,
        title=name,
        description="Test finding.",
    )


def test_high_threshold_fails_on_high_and_critical_findings():
    findings = [
        _finding(Severity.MEDIUM, "medium"),
        _finding(Severity.HIGH, "high"),
        _finding(Severity.CRITICAL, "critical"),
    ]

    policy = evaluate_policy(findings, "high")

    assert policy.enabled is True
    assert policy.passed is False
    assert policy.fail_on == "HIGH"
    assert policy.triggered_count == 2
    assert policy.highest_severity == "CRITICAL"


def test_critical_threshold_passes_when_high_is_highest_finding():
    findings = [_finding(Severity.HIGH, "high")]

    policy = evaluate_policy(findings, "critical")

    assert policy.passed is True
    assert policy.triggered_count == 0
    assert policy.highest_severity == "HIGH"


def test_non_security_statuses_do_not_trigger_gate():
    findings = [
        _finding(Severity.PASS, "pass"),
        _finding(Severity.INFO, "info"),
        _finding(Severity.ERROR, "error"),
    ]

    policy = evaluate_policy(findings, "low")

    assert policy.passed is True
    assert policy.triggered_count == 0
    assert policy.highest_severity is None


def test_gate_is_disabled_when_no_threshold_is_requested():
    policy = evaluate_policy([_finding(Severity.CRITICAL, "critical")])

    assert policy.enabled is False
    assert policy.passed is True
    assert policy.fail_on is None
    assert policy.triggered_count == 0
    assert policy.highest_severity == "CRITICAL"
