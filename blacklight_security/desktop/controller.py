from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import boto3

from blacklight_security.coverage import CoverageGateResult, evaluate_coverage_gate
from blacklight_security.html_reporting import render_html
from blacklight_security.policy import PolicyResult, evaluate_policy
from blacklight_security.reporting import render_json
from blacklight_security.runner import ScanResult, ScanRunner
from blacklight_security.scanners.docker import DockerScanTarget
from blacklight_security.scanners.kubernetes import KubernetesScanTarget


ProviderName = Literal["aws", "docker", "kubernetes"]


@dataclass(frozen=True, slots=True)
class DesktopScanRequest:
    provider: ProviderName
    service: str = "all"
    path: Path | None = None
    profile: str | None = None
    region: str | None = None
    fail_on: str | None = None
    require_full_coverage: bool = False


@dataclass(frozen=True, slots=True)
class DesktopScanOutcome:
    request: DesktopScanRequest
    result: ScanResult
    policy: PolicyResult
    coverage_gate: CoverageGateResult

    def render_json(self) -> str:
        return render_json(self.result, self.policy, self.coverage_gate)

    def render_html(self) -> str:
        return render_html(self.result, self.policy, self.coverage_gate)


def run_scan(request: DesktopScanRequest) -> DesktopScanOutcome:
    if request.provider == "aws":
        session = boto3.Session(profile_name=request.profile, region_name=request.region)
        result = ScanRunner("aws", session).run(request.service)
    elif request.provider == "docker":
        target = DockerScanTarget(request.path or Path("."))
        result = ScanRunner("docker", target).run(request.service)
    elif request.provider == "kubernetes":
        target = KubernetesScanTarget(request.path or Path("."))
        result = ScanRunner("kubernetes", target).run(request.service)
    else:
        raise ValueError(f"Unsupported desktop scan provider: {request.provider}")

    policy = evaluate_policy(result.findings, request.fail_on)
    coverage_gate = evaluate_coverage_gate(result.coverage, request.require_full_coverage)
    return DesktopScanOutcome(request, result, policy, coverage_gate)


def write_report(
    outcome: DesktopScanOutcome,
    output_format: Literal["json", "html"],
    path: Path,
) -> None:
    if output_format == "json":
        rendered = outcome.render_json()
    elif output_format == "html":
        rendered = outcome.render_html()
    else:
        raise ValueError(f"Unsupported desktop report format: {output_format}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered + "\n", encoding="utf-8")
