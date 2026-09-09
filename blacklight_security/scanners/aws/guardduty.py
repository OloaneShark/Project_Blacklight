from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity


class GuardDutyScanner:
    """Check whether Amazon GuardDuty detection is enabled in the selected region."""

    def __init__(self, session: Any):
        self.guardduty = session.client("guardduty")
        self.region = session.region_name or "unknown-region"

    def scan(self) -> list[Finding]:
        try:
            detector_ids = self.guardduty.list_detectors().get("DetectorIds", [])
        except ClientError as error:
            return [self._error(error)]

        if not detector_ids:
            return [
                Finding(
                    check_id="aws.guardduty.detector_enabled",
                    provider="aws",
                    service="guardduty",
                    resource_type="aws_region",
                    resource_id=self.region,
                    severity=Severity.HIGH,
                    title="GuardDuty is not enabled in this region",
                    description=(
                        "Blacklight found no GuardDuty detector in the selected AWS region, "
                        "reducing managed threat-detection coverage."
                    ),
                    remediation="Enable Amazon GuardDuty in this region if threat detection is required.",
                    evidence={"region": self.region, "detector_count": 0},
                )
            ]

        findings: list[Finding] = []
        for detector_id in detector_ids:
            try:
                detector = self.guardduty.get_detector(DetectorId=detector_id)
            except ClientError as error:
                findings.append(self._error(error, detector_id))
                continue

            status = detector.get("Status", "UNKNOWN")
            enabled = status == "ENABLED"
            findings.append(
                Finding(
                    check_id="aws.guardduty.detector_enabled",
                    provider="aws",
                    service="guardduty",
                    resource_type="aws_guardduty_detector",
                    resource_id=detector_id,
                    severity=Severity.PASS if enabled else Severity.HIGH,
                    title=(
                        "GuardDuty detector is enabled"
                        if enabled
                        else "GuardDuty detector is not enabled"
                    ),
                    description=(
                        f"GuardDuty detector {detector_id} reports status {status} "
                        f"in {self.region}."
                    ),
                    remediation=(
                        ""
                        if enabled
                        else "Enable the GuardDuty detector to restore managed threat-detection coverage."
                    ),
                    evidence={"region": self.region, "status": status},
                )
            )

        return findings

    def _error(self, error: ClientError, resource_id: str | None = None) -> Finding:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        return Finding(
            check_id="aws.guardduty.detector_enabled",
            provider="aws",
            service="guardduty",
            resource_type="aws_guardduty_detector",
            resource_id=resource_id or self.region,
            severity=Severity.ERROR,
            title="Blacklight could not evaluate GuardDuty",
            description=f"AWS returned {code} while Blacklight checked GuardDuty configuration.",
            remediation="Verify the scanning identity has GuardDuty read permissions.",
            evidence={"aws_error_code": code, "region": self.region},
        )
