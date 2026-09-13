from __future__ import annotations

import json
from collections import Counter
from html import escape
from typing import TYPE_CHECKING

from blacklight_security.models import Finding, Severity
from blacklight_security.risk import assess_risk

if TYPE_CHECKING:
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


def _text(value: object) -> str:
    return escape(str(value), quote=True)


def _finding_card(finding: Finding) -> str:
    evidence = escape(
        json.dumps(finding.evidence, indent=2, sort_keys=True, default=str),
        quote=False,
    )
    remediation = (
        f'<div class="detail"><strong>Remediation</strong><p>{_text(finding.remediation)}</p></div>'
        if finding.remediation
        else ""
    )
    return f"""
    <article class="finding severity-{finding.severity.value.lower()}">
      <div class="finding-head">
        <span class="badge">{_text(finding.severity.value)}</span>
        <div>
          <h3>{_text(finding.title)}</h3>
          <div class="finding-meta">{_text(finding.service)} · {_text(finding.resource_type)}</div>
        </div>
      </div>
      <dl class="facts">
        <div><dt>Resource</dt><dd>{_text(finding.resource_id)}</dd></div>
        <div><dt>Check ID</dt><dd>{_text(finding.check_id)}</dd></div>
      </dl>
      <div class="detail"><strong>Detail</strong><p>{_text(finding.description)}</p></div>
      {remediation}
      <details>
        <summary>Evidence</summary>
        <pre>{evidence}</pre>
      </details>
    </article>
    """


def render_html(
    value: list[Finding] | ScanResult,
    policy: PolicyResult | None = None,
) -> str:
    """Render a self-contained, escaped HTML security report."""

    findings = _findings(value)
    assessment = assess_risk(findings)
    counts = Counter(finding.severity for finding in findings)

    if hasattr(value, "metadata_dict"):
        metadata = value.metadata_dict()
    else:
        metadata = {
            "status": "COMPLETE",
            "provider": findings[0].provider if findings else "unknown",
            "region": None,
            "scanners": sorted({finding.service for finding in findings}),
            "scanner_count": len({finding.service for finding in findings}),
            "finding_count": len(findings),
            "started_at": None,
            "completed_at": None,
            "duration_ms": None,
        }

    summary_cards = "".join(
        f"""
        <div class="metric severity-{severity.value.lower()}">
          <span>{_text(severity.value)}</span>
          <strong>{counts[severity]}</strong>
        </div>
        """
        for severity in DISPLAY_ORDER
    )

    if policy and policy.enabled:
        gate_status = "PASS" if policy.passed else "FAIL"
        gate_class = "gate-pass" if policy.passed else "gate-fail"
        policy_section = f"""
        <section class="panel">
          <div class="section-title"><h2>CI/CD Security Gate</h2></div>
          <div class="gate {gate_class}">
            <strong>{gate_status}</strong>
            <span>Fail on {_text(policy.fail_on)} or above · {_text(policy.triggered_count)} matching finding(s)</span>
          </div>
        </section>
        """
    else:
        policy_section = ""

    correlations = ""
    if assessment.correlations:
        correlation_rows = "".join(
            f"""
            <tr>
              <td>{_text(item.rule_id)}</td>
              <td>+{_text(item.points)}</td>
              <td>{_text(item.reason)}</td>
            </tr>
            """
            for item in assessment.correlations
        )
        correlations = f"""
        <section class="panel">
          <div class="section-title"><h2>Risk Correlations</h2></div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Rule</th><th>Points</th><th>Reason</th></tr></thead>
              <tbody>{correlation_rows}</tbody>
            </table>
          </div>
        </section>
        """

    finding_cards = "".join(_finding_card(finding) for finding in findings)
    if not finding_cards:
        finding_cards = '<div class="empty">No findings were returned by the selected scanners.</div>'

    scanners = ", ".join(metadata.get("scanners", [])) or "none"
    completed_at = metadata.get("completed_at") or "unknown"
    duration = metadata.get("duration_ms")
    duration_text = f"{duration} ms" if duration is not None else "unknown"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Project Blacklight Security Report</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0b0e11;
      --panel: #12171c;
      --panel-2: #171d23;
      --border: #303841;
      --text: #edf2f6;
      --muted: #9aa7b2;
      --critical: #ff5b5b;
      --high: #ff9860;
      --medium: #f3c969;
      --low: #7fc8ff;
      --pass: #79d69a;
      --info: #9fb7cf;
      --error: #c99cff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); font-family: Consolas, "Courier New", monospace; line-height: 1.5; }}
    main {{ width: min(1180px, calc(100% - 32px)); margin: 32px auto 64px; }}
    header {{ border: 1px solid var(--border); padding: 24px; background: var(--panel); }}
    h1, h2, h3, p {{ margin-top: 0; }}
    h1 {{ margin-bottom: 6px; font-size: 28px; letter-spacing: .03em; }}
    h2 {{ margin: 0; font-size: 18px; }}
    h3 {{ margin: 0 0 4px; font-size: 16px; }}
    .eyebrow {{ color: var(--muted); text-transform: uppercase; font-size: 12px; letter-spacing: .12em; }}
    .risk-line {{ display: flex; gap: 16px; align-items: baseline; margin-top: 18px; flex-wrap: wrap; }}
    .risk-score {{ font-size: 34px; font-weight: 700; }}
    .risk-level {{ border: 1px solid var(--border); padding: 4px 8px; background: var(--panel-2); }}
    .panel {{ margin-top: 18px; border: 1px solid var(--border); background: var(--panel); }}
    .section-title {{ padding: 14px 16px; border-bottom: 1px solid var(--border); }}
    .metadata {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 0; }}
    .metadata div {{ padding: 14px 16px; border-right: 1px solid var(--border); border-bottom: 1px solid var(--border); }}
    .metadata span, .metric span, dt, .finding-meta {{ display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; padding: 12px; }}
    .metric {{ border: 1px solid var(--border); padding: 12px; background: var(--panel-2); }}
    .metric strong {{ display: block; margin-top: 4px; font-size: 24px; }}
    .gate {{ margin: 16px; border: 1px solid var(--border); padding: 14px 16px; display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }}
    .gate strong {{ font-size: 20px; }}
    .gate-pass {{ border-left: 4px solid var(--pass); }}
    .gate-fail {{ border-left: 4px solid var(--critical); }}
    .findings {{ display: grid; gap: 12px; padding: 12px; }}
    .finding {{ border: 1px solid var(--border); border-left-width: 4px; padding: 16px; background: var(--panel-2); }}
    .finding-head {{ display: flex; gap: 12px; align-items: flex-start; }}
    .badge {{ border: 1px solid currentColor; padding: 3px 7px; font-size: 12px; font-weight: 700; }}
    .severity-critical {{ border-left-color: var(--critical); }} .severity-critical .badge {{ color: var(--critical); }}
    .severity-high {{ border-left-color: var(--high); }} .severity-high .badge {{ color: var(--high); }}
    .severity-medium {{ border-left-color: var(--medium); }} .severity-medium .badge {{ color: var(--medium); }}
    .severity-low {{ border-left-color: var(--low); }} .severity-low .badge {{ color: var(--low); }}
    .severity-pass {{ border-left-color: var(--pass); }} .severity-pass .badge {{ color: var(--pass); }}
    .severity-info {{ border-left-color: var(--info); }} .severity-info .badge {{ color: var(--info); }}
    .severity-error {{ border-left-color: var(--error); }} .severity-error .badge {{ color: var(--error); }}
    .facts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 8px 16px; margin: 16px 0; }}
    .facts div {{ min-width: 0; }}
    dd {{ margin: 2px 0 0; overflow-wrap: anywhere; }}
    .detail {{ margin-top: 10px; }} .detail p {{ margin: 4px 0 0; color: #d8e0e6; }}
    details {{ margin-top: 14px; }} summary {{ cursor: pointer; color: var(--muted); }}
    pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #080a0d; border: 1px solid var(--border); padding: 12px; }}
    .table-wrap {{ overflow-x: auto; }} table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .empty {{ padding: 18px; color: var(--muted); }}
    footer {{ color: var(--muted); margin-top: 18px; font-size: 12px; }}
    @media print {{
      :root {{ color-scheme: light; --bg: #fff; --panel: #fff; --panel-2: #fff; --border: #bbb; --text: #111; --muted: #555; }}
      body {{ background: #fff; }} main {{ width: 100%; margin: 0; }} .finding, .panel, header {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
<main>
  <header>
    <div class="eyebrow">Deterministic cloud security assessment</div>
    <h1>Project Blacklight</h1>
    <div>Security Report</div>
    <div class="risk-line">
      <span class="risk-score">{_text(assessment.score)}/100</span>
      <span class="risk-level">Risk: {_text(assessment.level)}</span>
      <span class="risk-level">Base: {_text(assessment.base_score)}/100</span>
    </div>
  </header>

  <section class="panel">
    <div class="section-title"><h2>Scan Context</h2></div>
    <div class="metadata">
      <div><span>Status</span>{_text(metadata.get('status', 'unknown'))}</div>
      <div><span>Provider</span>{_text(metadata.get('provider', 'unknown'))}</div>
      <div><span>Region</span>{_text(metadata.get('region') or 'default/unspecified')}</div>
      <div><span>Scanners</span>{_text(scanners)}</div>
      <div><span>Findings</span>{_text(metadata.get('finding_count', len(findings)))}</div>
      <div><span>Duration</span>{_text(duration_text)}</div>
      <div><span>Completed</span>{_text(completed_at)}</div>
    </div>
  </section>

  <section class="panel">
    <div class="section-title"><h2>Severity Summary</h2></div>
    <div class="metrics">{summary_cards}</div>
  </section>

  {policy_section}
  {correlations}

  <section class="panel">
    <div class="section-title"><h2>Findings</h2></div>
    <div class="findings">{finding_cards}</div>
  </section>

  <footer>Generated by Project Blacklight. Detection and policy decisions are based on explicit scanner evidence and deterministic rules.</footer>
</main>
</body>
</html>
"""
