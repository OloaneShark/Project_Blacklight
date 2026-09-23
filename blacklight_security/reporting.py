from __future__ import annotations

import json
from collections import Counter
from typing import TYPE_CHECKING

from blacklight_security.models import Finding, Severity
from blacklight_security.risk import assess_risk

if TYPE_CHECKING:
    from blacklight_security.coverage import CoverageGateResult
    from blacklight_security.policy import PolicyResult
    from blacklight_security.runner import ScanResult


DISPLAY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.ERROR,
    Severity.INFO,
    Severity.PASS,
]


def _findings(value: list[Finding] | ScanResult) -> list[Finding]:
    return value.findings if hasattr(value, "findings") else value


def render_console(
    value: list[Finding] | ScanResult,
    policy: PolicyResult | None = None,
    coverage_gate: CoverageGateResult | None = None,
) -> str:
    findings = _findings(value)
    counts = Counter(finding.severity for finding in findings)
    assessment = assess_risk(findings)
    lines = ["Project Blacklight", "==================", ""]

    if hasattr(value, "metadata_dict"):
        metadata = value.metadata_dict()
        context = metadata.get("context", {})
        identity = context.get("identity", {}) if isinstance(context, dict) else {}
        coverage = metadata.get("coverage", {})
        affected_scanners = coverage.get("affected_scanners", [])
        lines.extend(
            [
                f"Status: {metadata['status']}",
                f"Provider: {metadata['provider']}",
            ]
        )
        if metadata["provider"] == "aws":
            lines.extend(
                [
                    f"Region: {metadata['region'] or 'default/unspecified'}",
                    f"Profile: {context.get('profile') or 'default/credential chain'}",
                    f"Account: {identity.get('account_id') or 'unavailable'}",
                    f"Partition: {identity.get('partition') or 'unavailable'}",
                    f"Principal: {identity.get('principal_arn') or 'unavailable'}",
                    f"Identity: {identity.get('status') or 'UNAVAILABLE'}",
                ]
            )
        lines.extend(
            [
                f"Scanners: {', '.join(metadata['scanners']) or 'none'}",
                f"Duration: {metadata['duration_ms']} ms",
                (
                    f"Coverage: {coverage.get('status', 'UNKNOWN')} "
                    f"({coverage.get('complete_scanner_count', 0)}/"
                    f"{coverage.get('scanner_count', 0)} scanners fully evaluated, "
                    f"{coverage.get('complete_scanner_percent', 0.0)}%)"
                ),
                f"Risk confidence: {coverage.get('risk_confidence', 'UNKNOWN')}",
            ]
        )
        if affected_scanners:
            lines.append(
                "Coverage gaps: "
                f"{', '.join(affected_scanners)} "
                f"({coverage.get('error_finding_count', 0)} ERROR finding(s))"
            )
        if coverage.get("message"):
            lines.append(f"Coverage note: {coverage['message']}")
        if coverage_gate and coverage_gate.enabled:
            gate_status = "PASS" if coverage_gate.passed else "FAIL"
            lines.append(
                f"Coverage gate: {gate_status} "
                f"(require {coverage_gate.required_status}, actual {coverage_gate.actual_status})"
            )
        if metadata["provider"] == "aws" and identity.get("error"):
            lines.append(f"Identity error: {identity['error']}")
        lines.append("")

    if not findings:
        lines.append("No resources were returned by the selected scanner.")
        if policy and policy.enabled:
            lines.extend(["", f"Security gate: PASS (fail on {policy.fail_on} or above)"])
        return "\n".join(lines)

    lines.extend(
        [
            f"Risk: {assessment.level} ({assessment.score}/100)",
            f"Base finding score: {assessment.base_score}/100",
        ]
    )

    if policy and policy.enabled:
        gate_status = "PASS" if policy.passed else "FAIL"
        lines.extend(
            [
                f"Security gate: {gate_status} (fail on {policy.fail_on} or above)",
                f"Gate matches: {policy.triggered_count}",
            ]
        )

    lines.extend(["", "Scan summary"])
    for severity in DISPLAY_ORDER:
        if counts[severity]:
            lines.append(f"  {severity.value:<8} {counts[severity]}")

    if assessment.correlations:
        lines.extend(["", "Correlations"])
        for item in assessment.correlations:
            lines.append(f"  +{item.points} {item.rule_id}: {item.reason}")

    actionable = [
        finding
        for finding in findings
        if finding.severity not in {Severity.PASS, Severity.INFO}
    ]

    if actionable:
        lines.extend(["", "Findings"])
        for finding in actionable:
            lines.extend(
                [
                    f"[{finding.severity.value}] {finding.title}",
                    f"  Resource: {finding.resource_id}",
                    f"  Check:    {finding.check_id}",
                    f"  Detail:   {finding.description}",
                ]
            )
            if finding.remediation:
                lines.append(f"  Fix:      {finding.remediation}")
            lines.append("")
    else:
        lines.extend(["", "No actionable findings were detected by the selected checks."])

    return "\n".join(lines).rstrip()


def render_json(
    value: list[Finding] | ScanResult,
    policy: PolicyResult | None = None,
    coverage_gate: CoverageGateResult | None = None,
) -> str:
    findings = _findings(value)
    if hasattr(value, "metadata_dict") and coverage_gate is not None:
        schema_version = "6"
    elif hasattr(value, "metadata_dict"):
        schema_version = "5"
    elif policy is not None:
        schema_version = "3"
    else:
        schema_version = "1"

    payload = {
        "tool": "project-blacklight",
        "schema_version": schema_version,
        "risk": assess_risk(findings).to_dict(),
        "findings": [finding.to_dict() for finding in findings],
    }
    if hasattr(value, "metadata_dict"):
        payload["scan"] = value.metadata_dict()
    if policy is not None:
        payload["policy"] = policy.to_dict()
    if coverage_gate is not None:
        payload["coverage_gate"] = coverage_gate.to_dict()
    return json.dumps(payload, indent=2)
