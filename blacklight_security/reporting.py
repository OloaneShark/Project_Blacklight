from __future__ import annotations

import json
from collections import Counter

from blacklight_security.models import Finding, Severity
from blacklight_security.risk import assess_risk


DISPLAY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.ERROR,
    Severity.INFO,
    Severity.PASS,
]


def render_console(findings: list[Finding]) -> str:
    counts = Counter(finding.severity for finding in findings)
    assessment = assess_risk(findings)
    lines = ["Project Blacklight", "==================", ""]

    if not findings:
        lines.append("No resources were returned by the selected scanner.")
        return "\n".join(lines)

    lines.extend(
        [
            f"Risk: {assessment.level} ({assessment.score}/100)",
            f"Base finding score: {assessment.base_score}/100",
            "",
            "Scan summary",
        ]
    )
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


def render_json(findings: list[Finding]) -> str:
    payload = {
        "tool": "project-blacklight",
        "schema_version": "1",
        "risk": assess_risk(findings).to_dict(),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2)
