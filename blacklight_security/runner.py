from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.registry import scanner_specs


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

    @property
    def duration_ms(self) -> int:
        return max(0, int((self.completed_at - self.started_at).total_seconds() * 1000))

    @property
    def status(self) -> str:
        if any(finding.severity is Severity.ERROR for finding in self.findings):
            return "PARTIAL"
        return "COMPLETE"

    def metadata_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "provider": self.provider,
            "requested_service": self.requested_service,
            "region": self.region,
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
        specs = scanner_specs(self.provider, selected)
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []
        executed: list[str] = []

        for spec in specs:
            findings.extend(spec.scanner_cls(self.session).scan())
            executed.append(spec.name)

        completed_at = datetime.now(timezone.utc)
        return ScanResult(
            provider=self.provider,
            requested_service=selected,
            region=getattr(self.session, "region_name", None),
            scanners=executed,
            findings=findings,
            started_at=started_at,
            completed_at=completed_at,
        )
