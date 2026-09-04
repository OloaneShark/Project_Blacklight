from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity


class CloudTrailScanner:
    """Deterministic AWS CloudTrail visibility checks."""

    def __init__(self, session: Any):
        self.cloudtrail = session.client("cloudtrail")

    def scan(self) -> list[Finding]:
        try:
            trails = self.cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
        except ClientError as error:
            return [self._error("aws-account", "aws.cloudtrail.describe", error)]

        if not trails:
            return [
                self._finding(
                    "aws-account",
                    "aws.cloudtrail.trail_present",
                    Severity.HIGH,
                    "No CloudTrail trail was found",
                    "Blacklight did not find a configured CloudTrail trail in the selected account/region context.",
                    "Configure CloudTrail logging appropriate to the account's audit requirements.",
                )
            ]

        findings: list[Finding] = []
        for trail in trails:
            name = trail.get("Name") or trail.get("TrailARN", "unknown-trail")
            arn = trail.get("TrailARN", name)
            is_multi_region = bool(trail.get("IsMultiRegionTrail", False))

            try:
                status = self.cloudtrail.get_trail_status(Name=arn)
            except ClientError as error:
                findings.append(self._error(name, "aws.cloudtrail.logging", error))
                continue

            if status.get("IsLogging"):
                findings.append(
                    self._finding(
                        name,
                        "aws.cloudtrail.logging",
                        Severity.PASS,
                        "CloudTrail trail is actively logging",
                        f"CloudTrail reports {name} is currently logging.",
                        evidence={"is_logging": True},
                    )
                )
            else:
                findings.append(
                    self._finding(
                        name,
                        "aws.cloudtrail.logging",
                        Severity.HIGH,
                        "CloudTrail trail is not actively logging",
                        f"CloudTrail reports {name} is not currently logging.",
                        "Start logging for the trail and investigate unexpected logging interruptions.",
                        {"is_logging": False},
                    )
                )

            if is_multi_region:
                findings.append(
                    self._finding(
                        name,
                        "aws.cloudtrail.multi_region",
                        Severity.PASS,
                        "CloudTrail trail is multi-region",
                        "The trail is configured to record activity across AWS regions.",
                        evidence={"is_multi_region": True},
                    )
                )
            else:
                findings.append(
                    self._finding(
                        name,
                        "aws.cloudtrail.multi_region",
                        Severity.MEDIUM,
                        "CloudTrail trail is not multi-region",
                        "The trail is not configured as a multi-region trail.",
                        "Consider a multi-region trail when account-wide visibility is required.",
                        {"is_multi_region": False},
                    )
                )

        return findings

    def _finding(self, resource_id, check_id, severity, title, description, remediation="", evidence=None):
        return Finding(
            check_id=check_id,
            provider="aws",
            service="cloudtrail",
            resource_type="aws_cloudtrail_trail",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )

    def _error(self, resource_id: str, check_id: str, error: ClientError) -> Finding:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        return self._finding(
            resource_id,
            check_id,
            Severity.ERROR,
            "Blacklight could not complete this CloudTrail check",
            f"AWS returned {code} while evaluating CloudTrail.",
            "Verify the caller has the read permissions required for this check.",
            {"aws_error_code": code},
        )
