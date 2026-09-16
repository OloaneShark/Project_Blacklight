from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CoverageAssessment:
    """Describe how completely the selected scanners were evaluated.

    Coverage is deliberately separate from security risk. Scanner errors do not
    add risk points, but they reduce confidence that the observed risk score is
    representative of the whole selected scan scope.
    """

    status: str
    risk_confidence: str
    scanner_count: int
    complete_scanner_count: int
    affected_scanner_count: int
    complete_scanner_percent: float
    error_finding_count: int
    affected_scanners: tuple[str, ...]
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "risk_confidence": self.risk_confidence,
            "scanner_count": self.scanner_count,
            "complete_scanner_count": self.complete_scanner_count,
            "affected_scanner_count": self.affected_scanner_count,
            "complete_scanner_percent": self.complete_scanner_percent,
            "error_finding_count": self.error_finding_count,
            "affected_scanners": list(self.affected_scanners),
            "message": self.message,
        }


def assess_coverage(
    scanners: list[str],
    scanner_error_counts: dict[str, int] | None = None,
) -> CoverageAssessment:
    """Assess scanner completion without changing the security-risk score."""

    scanner_error_counts = scanner_error_counts or {}
    selected = tuple(dict.fromkeys(scanners))
    total = len(selected)

    affected = tuple(
        scanner
        for scanner in selected
        if scanner_error_counts.get(scanner, 0) > 0
    )
    affected_count = len(affected)
    complete_count = total - affected_count
    error_count = sum(max(0, scanner_error_counts.get(scanner, 0)) for scanner in selected)

    if total == 0:
        return CoverageAssessment(
            status="UNKNOWN",
            risk_confidence="UNKNOWN",
            scanner_count=0,
            complete_scanner_count=0,
            affected_scanner_count=0,
            complete_scanner_percent=0.0,
            error_finding_count=0,
            affected_scanners=(),
            message="No scanners were executed, so scan coverage could not be assessed.",
        )

    percent = round((complete_count / total) * 100, 1)

    if affected_count == 0:
        status = "FULL"
        confidence = "HIGH"
        message = "All selected scanners completed without ERROR findings."
    elif complete_count == 0:
        status = "LIMITED"
        confidence = "LOW"
        message = (
            "Every selected scanner returned one or more ERROR findings. "
            "The observed risk score may substantially understate actual risk."
        )
    else:
        status = "PARTIAL"
        confidence = "REDUCED"
        message = (
            "One or more selected scanners returned ERROR findings. "
            "The risk score only reflects successfully evaluated evidence and may understate risk "
            "in affected services."
        )

    return CoverageAssessment(
        status=status,
        risk_confidence=confidence,
        scanner_count=total,
        complete_scanner_count=complete_count,
        affected_scanner_count=affected_count,
        complete_scanner_percent=percent,
        error_finding_count=error_count,
        affected_scanners=affected,
        message=message,
    )
