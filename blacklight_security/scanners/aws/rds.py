from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity


class RDSScanner:
    """Deterministic RDS exposure and storage-encryption checks."""

    def __init__(self, session: Any):
        self.rds = session.client("rds")

    def scan(self) -> list[Finding]:
        try:
            pages = self.rds.get_paginator("describe_db_instances").paginate()
            instances = [db for page in pages for db in page.get("DBInstances", [])]
        except ClientError as error:
            return [self._error("aws-account", error)]

        if not instances:
            return [
                self._finding(
                    "aws-account",
                    "aws.rds.instances",
                    Severity.INFO,
                    "No RDS database instances were returned",
                    "There are no RDS DB instances for Blacklight to evaluate in this region.",
                )
            ]

        findings: list[Finding] = []
        for db in instances:
            db_id = db["DBInstanceIdentifier"]

            if db.get("PubliclyAccessible", False):
                findings.append(
                    self._finding(
                        db_id,
                        "aws.rds.public_access",
                        Severity.CRITICAL,
                        "RDS instance is publicly accessible",
                        f"{db_id} is configured as publicly accessible.",
                        "Place the database in private network paths unless public reachability is explicitly required and tightly controlled.",
                        {"publicly_accessible": True},
                    )
                )
            else:
                findings.append(
                    self._finding(
                        db_id,
                        "aws.rds.public_access",
                        Severity.PASS,
                        "RDS instance is not publicly accessible",
                        f"{db_id} is not configured as publicly accessible.",
                        evidence={"publicly_accessible": False},
                    )
                )

            if db.get("StorageEncrypted", False):
                findings.append(
                    self._finding(
                        db_id,
                        "aws.rds.storage_encryption",
                        Severity.PASS,
                        "RDS storage encryption is enabled",
                        f"{db_id} reports encrypted storage.",
                        evidence={"storage_encrypted": True},
                    )
                )
            else:
                findings.append(
                    self._finding(
                        db_id,
                        "aws.rds.storage_encryption",
                        Severity.HIGH,
                        "RDS storage encryption is not enabled",
                        f"{db_id} does not report encrypted storage.",
                        "Use encrypted RDS storage for workloads that require encryption at rest; migration may require snapshot/copy workflows depending on engine and configuration.",
                        {"storage_encrypted": False},
                    )
                )

        return findings

    def _finding(self, resource_id, check_id, severity, title, description, remediation="", evidence=None):
        return Finding(
            check_id=check_id,
            provider="aws",
            service="rds",
            resource_type="aws_rds_db_instance",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )

    def _error(self, resource_id: str, error: ClientError) -> Finding:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        return self._finding(
            resource_id,
            "aws.rds.instances",
            Severity.ERROR,
            "Blacklight could not inspect RDS instances",
            f"AWS returned {code} while evaluating RDS.",
            "Verify the caller can run rds:DescribeDBInstances.",
            {"aws_error_code": code},
        )
