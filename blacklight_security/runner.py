from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from blacklight_security.coverage import CoverageAssessment, assess_coverage
from blacklight_security.models import Finding, Severity
from blacklight_security.registry import scanner_specs
from blacklight_security.scan_context import ScanContext, resolve_scan_context


@dataclass(slots=True)
class ScanResult:
    """One completed Blacklight scan with execution metadata and findings."""

    provider: str
    requested_service: str
    region: str | None
    scanners: list[str]
    findings: list[Finding]
    started_at: datetime
    completed_at: datetime
    context: ScanContext | None = None
    scanner_error_counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.scanner_error_counts:
            return

        inferred: dict[str, int] = {}
        for finding in self.findings:
            if finding.severity is not Severity.ERROR:
                continue
            if finding.service in self.scanners:
                scanner = finding.service
            elif len(self.scanners) == 1:
                scanner = self.scanners[0]
            else:
                continue
            inferred[scanner] = inferred.get(scanner, 0) + 1
        self.scanner_error_counts.update(inferred)

    @property
    def duration_ms(self) -> int:
        return max(0, int((self.completed_at - self.started_at).total_seconds() * 1000))

    @property
    def coverage(self) -> CoverageAssessment:
        return assess_coverage(self.scanners, self.scanner_error_counts)

    @property
    def status(self) -> str:
        if self.coverage.status == "LIMITED":
            return "FAILED"
        if self.coverage.status == "PARTIAL":
            return "PARTIAL"
        return "COMPLETE"

    def metadata_dict(self) -> dict[str, Any]:
        context = (
            self.context.to_dict()
            if self.context is not None
            else {
                "provider": self.provider,
                "region": self.region,
                "profile": None,
                "identity": {
                    "status": "UNAVAILABLE",
                    "account_id": None,
                    "principal_arn": None,
                    "user_id": None,
                    "partition": None,
                    "error": None,
                },
            }
        )
        return {
            "status": self.status,
            "provider": self.provider,
            "requested_service": self.requested_service,
            "region": self.region,
            "context": context,
            "coverage": self.coverage.to_dict(),
            "scanners": self.scanners,
            "scanner_count": len(self.scanners),
            "finding_count": len(self.findings),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_ms": self.duration_ms,
        }


class ScanRunner:
    """Coordinate registered scanners and return one normalized scan result."""

    def __init__(self, provider: str, session: Any):
        self.provider = provider.strip().lower()
        self.session = session

    def run(self, selected: str = "all") -> ScanResult:
        started_at = datetime.now(timezone.utc)
        context = resolve_scan_context(self.provider, self.session)
        specs = scanner_specs(self.provider, selected)
        findings: list[Finding] = []
        executed: list[str] = []
        scanner_error_counts: dict[str, int] = {}

        for spec in specs:
            try:
                scanner_findings = spec.scanner_cls(self.session).scan()
            except ClientError as error:
                scanner_findings = [self._scanner_client_error(spec.name, error)]

            findings.extend(scanner_findings)
            executed.append(spec.name)
            error_count = sum(
                finding.severity is Severity.ERROR for finding in scanner_findings
            )
            if error_count:
                scanner_error_counts[spec.name] = error_count

        completed_at = datetime.now(timezone.utc)
        return ScanResult(
            provider=self.provider,
            requested_service=selected,
            region=context.region,
            scanners=executed,
            findings=findings,
            started_at=started_at,
            completed_at=completed_at,
            context=context,
            scanner_error_counts=scanner_error_counts,
        )

    def _scanner_client_error(self, scanner_name: str, error: ClientError) -> Finding:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        return Finding(
            check_id=f"{self.provider}.{scanner_name}.scanner_execution",
            provider=self.provider,
            service=scanner_name,
            resource_type=f"{self.provider}_scanner",
            resource_id=scanner_name,
            severity=Severity.ERROR,
            title=f"Blacklight could not complete the {scanner_name} scanner",
            description=(
                f"The provider returned {code} before the {scanner_name} scanner could "
                "complete its selected checks."
            ),
            remediation=(
                "Verify the scanning identity has the required read permissions and retry "
                "the affected scanner."
            ),
            evidence={"provider_error_code": code, "scanner": scanner_name},
        )
