from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity


class S3Scanner:
    """Deterministic AWS S3 security checks.

    The scanner asks AWS APIs for configuration state and emits normalized findings.
    No AI model is involved in deciding whether a check passes or fails.
    """

    def __init__(self, session: Any):
        self.s3 = session.client("s3")

    def scan(self) -> list[Finding]:
        response = self.s3.list_buckets()
        findings: list[Finding] = []

        for bucket in response.get("Buckets", []):
            name = bucket["Name"]
            findings.extend(
                [
                    self._check_public_access_block(name),
                    self._check_encryption(name),
                    self._check_versioning(name),
                    self._check_logging(name),
                    self._check_public_policy(name),
                ]
            )

        return findings

    def _finding(
        self,
        bucket: str,
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
            service="s3",
            resource_type="aws_s3_bucket",
            resource_id=bucket,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )

    def _error(self, bucket: str, check_id: str, error: ClientError) -> Finding:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        return self._finding(
            bucket,
            check_id,
            Severity.ERROR,
            "Blacklight could not complete this check",
            f"AWS returned {code} while evaluating {bucket}.",
            "Verify the caller has the read permissions required for this check.",
            {"aws_error_code": code},
        )

    def _check_public_access_block(self, bucket: str) -> Finding:
        check_id = "aws.s3.public_access_block"
        try:
            config = self.s3.get_public_access_block(Bucket=bucket)[
                "PublicAccessBlockConfiguration"
            ]
            settings = {
                key: bool(config.get(key))
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            }
            if all(settings.values()):
                return self._finding(
                    bucket,
                    check_id,
                    Severity.PASS,
                    "S3 Block Public Access is fully enabled",
                    "All four bucket-level Block Public Access controls are enabled.",
                    evidence=settings,
                )

            return self._finding(
                bucket,
                check_id,
                Severity.HIGH,
                "S3 Block Public Access is only partially enabled",
                "One or more bucket-level Block Public Access controls are disabled.",
                "Enable all four S3 Block Public Access controls unless public access is explicitly required.",
                settings,
            )
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code == "NoSuchPublicAccessBlockConfiguration":
                return self._finding(
                    bucket,
                    check_id,
                    Severity.CRITICAL,
                    "S3 Block Public Access is not configured",
                    "The bucket has no bucket-level Block Public Access configuration.",
                    "Enable all four S3 Block Public Access controls unless public access is explicitly required.",
                )
            return self._error(bucket, check_id, error)

    def _check_encryption(self, bucket: str) -> Finding:
        check_id = "aws.s3.default_encryption"
        try:
            rules = self.s3.get_bucket_encryption(Bucket=bucket)[
                "ServerSideEncryptionConfiguration"
            ]["Rules"]
            defaults = [
                rule.get("ApplyServerSideEncryptionByDefault", {}) for rule in rules
            ]
            algorithms = sorted(
                {
                    item.get("SSEAlgorithm")
                    for item in defaults
                    if item.get("SSEAlgorithm")
                }
            )
            return self._finding(
                bucket,
                check_id,
                Severity.PASS,
                "Default S3 encryption is configured",
                "AWS reports default server-side encryption for this bucket.",
                evidence={"algorithms": algorithms},
            )
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                return self._finding(
                    bucket,
                    check_id,
                    Severity.MEDIUM,
                    "Default S3 encryption configuration was not found",
                    "Blacklight could not confirm a bucket encryption configuration.",
                    "Configure default server-side encryption for the bucket.",
                )
            return self._error(bucket, check_id, error)

    def _check_versioning(self, bucket: str) -> Finding:
        check_id = "aws.s3.versioning"
        try:
            status = self.s3.get_bucket_versioning(Bucket=bucket).get("Status")
            if status == "Enabled":
                return self._finding(
                    bucket,
                    check_id,
                    Severity.PASS,
                    "S3 versioning is enabled",
                    "Object versioning can help recovery from accidental deletion or overwrite.",
                    evidence={"status": status},
                )
            return self._finding(
                bucket,
                check_id,
                Severity.MEDIUM,
                "S3 versioning is not enabled",
                f"The bucket versioning state is {status or 'NotConfigured'}.",
                "Enable S3 Versioning when recovery requirements justify it.",
                {"status": status or "NotConfigured"},
            )
        except ClientError as error:
            return self._error(bucket, check_id, error)

    def _check_logging(self, bucket: str) -> Finding:
        check_id = "aws.s3.access_logging"
        try:
            enabled = bool(self.s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled"))
            if enabled:
                return self._finding(
                    bucket,
                    check_id,
                    Severity.PASS,
                    "S3 server access logging is enabled",
                    "The bucket has an S3 server access logging destination configured.",
                )
            return self._finding(
                bucket,
                check_id,
                Severity.MEDIUM,
                "S3 server access logging is not enabled",
                "The bucket does not have S3 server access logging configured.",
                "Enable S3 server access logging or use CloudTrail data events when object-level visibility is required.",
            )
        except ClientError as error:
            return self._error(bucket, check_id, error)

    def _check_public_policy(self, bucket: str) -> Finding:
        check_id = "aws.s3.public_policy"
        try:
            is_public = bool(
                self.s3.get_bucket_policy_status(Bucket=bucket)
                .get("PolicyStatus", {})
                .get("IsPublic", False)
            )
            if is_public:
                return self._finding(
                    bucket,
                    check_id,
                    Severity.CRITICAL,
                    "S3 bucket policy is public",
                    "AWS evaluates the bucket policy as public.",
                    "Review the bucket policy and remove unintended public access.",
                    {"is_public": True},
                )
            return self._finding(
                bucket,
                check_id,
                Severity.PASS,
                "S3 bucket policy is not public",
                "AWS does not evaluate the bucket policy as public.",
                evidence={"is_public": False},
            )
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code in {"NoSuchBucketPolicy", "NoSuchPolicy"}:
                return self._finding(
                    bucket,
                    check_id,
                    Severity.PASS,
                    "No S3 bucket policy is configured",
                    "No bucket policy was found, so this check found no public bucket policy.",
                )
            return self._error(bucket, check_id, error)
