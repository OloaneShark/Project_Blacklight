from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity


class IAMScanner:
    """Deterministic AWS IAM account and access-key checks."""

    def __init__(self, session: Any, stale_days: int = 90):
        self.iam = session.client("iam")
        self.stale_days = stale_days

    def scan(self) -> list[Finding]:
        findings = [self._check_root_mfa()]

        try:
            user_pages = self.iam.get_paginator("list_users").paginate()
            users = [user for page in user_pages for user in page.get("Users", [])]
        except ClientError as error:
            findings.append(self._error("aws-account", "aws.iam.list_users", error))
            return findings

        if not users:
            findings.append(
                self._finding(
                    resource_id="aws-account",
                    check_id="aws.iam.access_keys",
                    severity=Severity.INFO,
                    title="No IAM users were returned",
                    description="There are no IAM users for Blacklight to evaluate for long-lived access keys.",
                )
            )
            return findings

        for user in users:
            username = user["UserName"]
            findings.extend(self._check_user_access_keys(username))

        return findings

    def _finding(
        self,
        resource_id: str,
        check_id: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            provider="aws",
            service="iam",
            resource_type="aws_iam_identity",
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
            "Blacklight could not complete this IAM check",
            f"AWS returned {code} while evaluating IAM configuration.",
            "Verify the caller has the read permissions required for this check.",
            {"aws_error_code": code},
        )

    def _check_root_mfa(self) -> Finding:
        check_id = "aws.iam.root_mfa"
        try:
            summary = self.iam.get_account_summary().get("SummaryMap", {})
            enabled = bool(summary.get("AccountMFAEnabled"))
            if enabled:
                return self._finding(
                    "root",
                    check_id,
                    Severity.PASS,
                    "Root account MFA is enabled",
                    "AWS account summary reports MFA enabled for the root user.",
                    evidence={"enabled": True},
                )
            return self._finding(
                "root",
                check_id,
                Severity.HIGH,
                "Root account MFA is not enabled",
                "AWS account summary does not report MFA enabled for the root user.",
                "Enable MFA for the AWS account root user and avoid routine root-user activity.",
                {"enabled": False},
            )
        except ClientError as error:
            return self._error("root", check_id, error)

    def _check_user_access_keys(self, username: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            pages = self.iam.get_paginator("list_access_keys").paginate(UserName=username)
            access_keys = [key for page in pages for key in page.get("AccessKeyMetadata", [])]
        except ClientError as error:
            return [self._error(username, "aws.iam.access_keys", error)]

        for key in access_keys:
            if key.get("Status") != "Active":
                continue

            key_id = key["AccessKeyId"]
            key_suffix = key_id[-4:]
            created = key["CreateDate"]
            age_days = (datetime.now(timezone.utc) - created).days

            if age_days > self.stale_days:
                findings.append(
                    self._finding(
                        username,
                        "aws.iam.access_key_age",
                        Severity.MEDIUM,
                        "IAM access key exceeds the configured age threshold",
                        f"An active access key for {username} is {age_days} days old.",
                        "Review whether the long-lived key is still required and rotate or remove it according to your credential policy.",
                        {"access_key_suffix": key_suffix, "age_days": age_days, "threshold_days": self.stale_days},
                    )
                )
            else:
                findings.append(
                    self._finding(
                        username,
                        "aws.iam.access_key_age",
                        Severity.PASS,
                        "IAM access key is within the configured age threshold",
                        f"An active access key for {username} is {age_days} days old.",
                        evidence={"access_key_suffix": key_suffix, "age_days": age_days, "threshold_days": self.stale_days},
                    )
                )

            try:
                usage = self.iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {})
            except ClientError as error:
                findings.append(self._error(username, "aws.iam.access_key_last_used", error))
                continue

            last_used = usage.get("LastUsedDate")
            if last_used is None:
                findings.append(
                    self._finding(
                        username,
                        "aws.iam.access_key_last_used",
                        Severity.MEDIUM,
                        "IAM access key has never been used",
                        f"AWS reports no recorded use for an active access key belonging to {username}.",
                        "Remove unused long-lived credentials after confirming they are not required.",
                        {"access_key_suffix": key_suffix, "last_used": None},
                    )
                )
                continue

            unused_days = (datetime.now(timezone.utc) - last_used).days
            if unused_days > self.stale_days:
                findings.append(
                    self._finding(
                        username,
                        "aws.iam.access_key_last_used",
                        Severity.MEDIUM,
                        "IAM access key has not been used recently",
                        f"An active access key for {username} has not been used in {unused_days} days.",
                        "Review and remove inactive long-lived credentials that are no longer required.",
                        {"access_key_suffix": key_suffix, "unused_days": unused_days, "threshold_days": self.stale_days},
                    )
                )
            else:
                findings.append(
                    self._finding(
                        username,
                        "aws.iam.access_key_last_used",
                        Severity.PASS,
                        "IAM access key has recent recorded use",
                        f"AWS reports use of the access key within the last {self.stale_days} days.",
                        evidence={"access_key_suffix": key_suffix, "unused_days": unused_days, "threshold_days": self.stale_days},
                    )
                )

        return findings
