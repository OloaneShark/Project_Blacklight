from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity


PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {
    22: ("SSH", Severity.CRITICAL),
    3389: ("RDP", Severity.CRITICAL),
    3306: ("MySQL", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
}


class EC2Scanner:
    """Deterministic EC2 security-group exposure checks."""

    def __init__(self, session: Any):
        self.ec2 = session.client("ec2")

    def scan(self) -> list[Finding]:
        try:
            groups = self.ec2.describe_security_groups().get("SecurityGroups", [])
        except ClientError as error:
            return [self._error("aws-account", error)]

        findings: list[Finding] = []
        for group in groups:
            group_id = group.get("GroupId", "unknown")
            group_name = group.get("GroupName", group_id)
            group_findings = self._scan_group(group_id, group_name, group.get("IpPermissions", []))
            if group_findings:
                findings.extend(group_findings)
            else:
                findings.append(
                    self._finding(
                        group_id,
                        "aws.ec2.security_group_public_sensitive_ports",
                        Severity.PASS,
                        "No publicly exposed sensitive ports were detected",
                        f"Blacklight did not find unrestricted ingress to its sensitive-port set on {group_name}.",
                        evidence={"group_name": group_name},
                    )
                )

        return findings

    def _scan_group(self, group_id: str, group_name: str, permissions: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int | None]] = set()

        for permission in permissions:
            public_ranges = {
                item.get("CidrIp") for item in permission.get("IpRanges", []) if item.get("CidrIp") in PUBLIC_CIDRS
            }
            public_ranges.update(
                item.get("CidrIpv6") for item in permission.get("Ipv6Ranges", []) if item.get("CidrIpv6") in PUBLIC_CIDRS
            )
            if not public_ranges:
                continue

            if permission.get("IpProtocol") == "-1":
                key = ("all", None)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self._finding(
                            group_id,
                            "aws.ec2.security_group_all_ingress",
                            Severity.CRITICAL,
                            "Security group allows all inbound traffic from the internet",
                            f"{group_name} permits all protocols/ports from an unrestricted public CIDR.",
                            "Restrict inbound rules to the minimum required protocols, ports, and trusted source ranges.",
                            {"group_name": group_name, "public_cidrs": sorted(public_ranges)},
                        )
                    )
                continue

            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            if from_port is None or to_port is None:
                continue

            for port, (label, severity) in SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    key = ("port", port)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self._finding(
                            group_id,
                            "aws.ec2.security_group_public_sensitive_port",
                            severity,
                            f"Security group exposes {label} ({port}) to the internet",
                            f"{group_name} permits inbound {label} traffic from an unrestricted public CIDR.",
                            "Restrict the rule to trusted source networks or remove the public ingress path.",
                            {"group_name": group_name, "port": port, "service": label, "public_cidrs": sorted(public_ranges)},
                        )
                    )

        return findings

    def _finding(self, resource_id, check_id, severity, title, description, remediation="", evidence=None):
        return Finding(
            check_id=check_id,
            provider="aws",
            service="ec2",
            resource_type="aws_ec2_security_group",
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
            "aws.ec2.security_groups",
            Severity.ERROR,
            "Blacklight could not inspect EC2 security groups",
            f"AWS returned {code} while evaluating EC2 security groups.",
            "Verify the caller can run ec2:DescribeSecurityGroups.",
            {"aws_error_code": code},
        )
