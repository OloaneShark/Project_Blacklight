from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity


class IAMScanner:
    """Deterministic AWS IAM account, credential, and direct user-policy checks."""

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
                    description=(
                        "There are no IAM users for Blacklight to evaluate for long-lived "
                        "access keys or direct user policies."
                    ),
                )
            )
            return findings

        for user in users:
            username = user["UserName"]
            findings.extend(self._check_user_access_keys(username))
            findings.extend(self._check_user_policies(username))

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
                        (
                            "Review whether the long-lived key is still required and rotate or "
                            "remove it according to your credential policy."
                        ),
                        {
                            "access_key_suffix": key_suffix,
                            "age_days": age_days,
                            "threshold_days": self.stale_days,
                        },
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
                        evidence={
                            "access_key_suffix": key_suffix,
                            "age_days": age_days,
                            "threshold_days": self.stale_days,
                        },
                    )
                )

            try:
                usage = self.iam.get_access_key_last_used(AccessKeyId=key_id).get(
                    "AccessKeyLastUsed",
                    {},
                )
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
                        (
                            "AWS reports no recorded use for an active access key belonging to "
                            f"{username}."
                        ),
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
                        (
                            f"An active access key for {username} has not been used in "
                            f"{unused_days} days."
                        ),
                        "Review and remove inactive long-lived credentials that are no longer required.",
                        {
                            "access_key_suffix": key_suffix,
                            "unused_days": unused_days,
                            "threshold_days": self.stale_days,
                        },
                    )
                )
            else:
                findings.append(
                    self._finding(
                        username,
                        "aws.iam.access_key_last_used",
                        Severity.PASS,
                        "IAM access key has recent recorded use",
                        (
                            "AWS reports use of the access key within the last "
                            f"{self.stale_days} days."
                        ),
                        evidence={
                            "access_key_suffix": key_suffix,
                            "unused_days": unused_days,
                            "threshold_days": self.stale_days,
                        },
                    )
                )

        return findings

    def _check_user_policies(self, username: str) -> list[Finding]:
        """Inspect policies attached directly to one IAM user.

        This deliberately reports the policy statement that exists, not the
        identity's final effective permissions. Permissions boundaries, SCPs,
        explicit denies, and other IAM evaluation layers may further restrict
        what the user can actually do.
        """

        check_id = "aws.iam.user_wildcard_policy"
        error_check_id = "aws.iam.user_policy_analysis"
        findings: list[Finding] = []
        matches: list[dict[str, Any]] = []
        had_errors = False

        try:
            pages = self.iam.get_paginator("list_user_policies").paginate(UserName=username)
            inline_names = [
                name
                for page in pages
                for name in page.get("PolicyNames", [])
            ]
        except ClientError as error:
            findings.append(self._error(username, error_check_id, error))
            inline_names = []
            had_errors = True

        for policy_name in inline_names:
            try:
                response = self.iam.get_user_policy(
                    UserName=username,
                    PolicyName=policy_name,
                )
            except ClientError as error:
                findings.append(self._error(username, error_check_id, error))
                had_errors = True
                continue

            statement_indexes = self._unrestricted_statement_indexes(
                response.get("PolicyDocument")
            )
            if statement_indexes is None:
                findings.append(self._policy_document_error(username, policy_name, "inline"))
                had_errors = True
                continue
            if statement_indexes:
                matches.append(
                    {
                        "policy_name": policy_name,
                        "policy_type": "inline",
                        "policy_arn": None,
                        "statement_indexes": statement_indexes,
                    }
                )

        try:
            pages = self.iam.get_paginator("list_attached_user_policies").paginate(
                UserName=username
            )
            attached_policies = [
                policy
                for page in pages
                for policy in page.get("AttachedPolicies", [])
            ]
        except ClientError as error:
            findings.append(self._error(username, error_check_id, error))
            attached_policies = []
            had_errors = True

        for policy in attached_policies:
            policy_arn = policy.get("PolicyArn")
            policy_name = policy.get("PolicyName") or policy_arn or "unknown-policy"
            if not policy_arn:
                findings.append(
                    self._policy_document_error(username, str(policy_name), "managed")
                )
                had_errors = True
                continue

            try:
                policy_metadata = self.iam.get_policy(PolicyArn=policy_arn).get("Policy", {})
                version_id = policy_metadata.get("DefaultVersionId")
                if not version_id:
                    findings.append(
                        self._policy_document_error(username, str(policy_name), "managed")
                    )
                    had_errors = True
                    continue
                version = self.iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id,
                ).get("PolicyVersion", {})
            except ClientError as error:
                findings.append(self._error(username, error_check_id, error))
                had_errors = True
                continue

            statement_indexes = self._unrestricted_statement_indexes(version.get("Document"))
            if statement_indexes is None:
                findings.append(
                    self._policy_document_error(username, str(policy_name), "managed")
                )
                had_errors = True
                continue
            if statement_indexes:
                matches.append(
                    {
                        "policy_name": policy_name,
                        "policy_type": "managed",
                        "policy_arn": policy_arn,
                        "statement_indexes": statement_indexes,
                    }
                )

        if matches:
            findings.append(
                self._finding(
                    username,
                    check_id,
                    Severity.HIGH,
                    "IAM user has an unconditional wildcard Allow statement",
                    (
                        f"One or more policies attached directly to {username} allow Action '*' "
                        "on Resource '*' without a Condition. This is an administrator-style "
                        "identity-policy grant, although effective permissions can still be "
                        "restricted by other IAM evaluation layers."
                    ),
                    (
                        "Replace broad wildcard permissions with the specific actions and resources "
                        "the user requires. Prefer roles and short-lived credentials where practical."
                    ),
                    {
                        "matched_policy_count": len(matches),
                        "matched_policies": matches,
                        "effective_permissions_not_evaluated": True,
                    },
                )
            )
        elif not had_errors:
            findings.append(
                self._finding(
                    username,
                    check_id,
                    Severity.PASS,
                    "No unconditional wildcard Allow was found in direct user policies",
                    (
                        "Blacklight did not find an unconditioned Action '*' and Resource '*' "
                        "Allow statement in the inline or managed policies attached directly to "
                        f"{username}."
                    ),
                    evidence={"matched_policy_count": 0},
                )
            )

        return findings

    def _policy_document_error(
        self,
        username: str,
        policy_name: str,
        policy_type: str,
    ) -> Finding:
        return self._finding(
            username,
            "aws.iam.user_policy_analysis",
            Severity.ERROR,
            "Blacklight could not parse an IAM user policy document",
            (
                f"Blacklight could not normalize the {policy_type} policy {policy_name} into a "
                "JSON policy document for deterministic analysis."
            ),
            "Review the policy document and retry the IAM scanner.",
            {"policy_name": policy_name, "policy_type": policy_type},
        )

    @staticmethod
    def _unrestricted_statement_indexes(document: Any) -> list[int] | None:
        policy = IAMScanner._normalize_policy_document(document)
        if policy is None:
            return None

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return None

        matched: list[int] = []
        for index, statement in enumerate(statements):
            if not isinstance(statement, dict):
                continue
            if statement.get("Effect") != "Allow":
                continue
            if statement.get("Condition"):
                continue

            actions = IAMScanner._string_values(statement.get("Action"))
            resources = IAMScanner._string_values(statement.get("Resource"))
            if "*" in actions and "*" in resources:
                matched.append(index)

        return matched

    @staticmethod
    def _normalize_policy_document(document: Any) -> dict[str, Any] | None:
        if isinstance(document, dict):
            return document
        if not isinstance(document, str):
            return None

        for candidate in (document, unquote(document)):
            try:
                parsed = json.loads(candidate)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    @staticmethod
    def _string_values(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [item for item in value if isinstance(item, str)]
        return []
