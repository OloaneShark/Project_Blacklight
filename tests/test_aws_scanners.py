from datetime import datetime, timedelta, timezone

from blacklight_security.models import Severity
from blacklight_security.scanners.aws import CloudTrailScanner, EC2Scanner, IAMScanner, RDSScanner


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return self.pages


class FakeSession:
    def __init__(self, clients):
        self.clients = clients

    def client(self, service_name):
        return self.clients[service_name]


class FakeIAM:
    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 0}}

    def get_paginator(self, name):
        if name == "list_users":
            return FakePaginator([[{"Users": [{"UserName": "builder"}]}][0]])
        if name == "list_access_keys":
            old = datetime.now(timezone.utc) - timedelta(days=120)
            return FakePaginator([{"AccessKeyMetadata": [{"AccessKeyId": "AKIAEXAMPLE1234", "CreateDate": old, "Status": "Active"}]}])
        raise AssertionError(name)

    def get_access_key_last_used(self, AccessKeyId):
        return {"AccessKeyLastUsed": {}}


class FakeCloudTrail:
    def describe_trails(self, includeShadowTrails=False):
        return {"trailList": [{"Name": "audit", "TrailARN": "arn:trail:audit", "IsMultiRegionTrail": False}]}

    def get_trail_status(self, Name):
        return {"IsLogging": False}


class FakeEC2:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "public-admin",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                        }
                    ],
                }
            ]
        }


class FakeRDS:
    def get_paginator(self, name):
        assert name == "describe_db_instances"
        return FakePaginator(
            [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "prod-db",
                            "PubliclyAccessible": True,
                            "StorageEncrypted": False,
                        }
                    ]
                }
            ]
        )


def test_iam_scanner_flags_root_mfa_and_stale_key():
    findings = IAMScanner(FakeSession({"iam": FakeIAM()})).scan()
    severities = {finding.check_id: finding.severity for finding in findings}

    assert severities["aws.iam.root_mfa"] is Severity.HIGH
    assert severities["aws.iam.access_key_age"] is Severity.MEDIUM
    assert severities["aws.iam.access_key_last_used"] is Severity.MEDIUM


def test_cloudtrail_scanner_flags_stopped_single_region_trail():
    findings = CloudTrailScanner(FakeSession({"cloudtrail": FakeCloudTrail()})).scan()
    severities = {finding.check_id: finding.severity for finding in findings}

    assert severities["aws.cloudtrail.logging"] is Severity.HIGH
    assert severities["aws.cloudtrail.multi_region"] is Severity.MEDIUM


def test_ec2_scanner_flags_public_ssh():
    findings = EC2Scanner(FakeSession({"ec2": FakeEC2()})).scan()

    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].evidence["port"] == 22


def test_rds_scanner_flags_public_unencrypted_database():
    findings = RDSScanner(FakeSession({"rds": FakeRDS()})).scan()
    severities = {finding.check_id: finding.severity for finding in findings}

    assert severities["aws.rds.public_access"] is Severity.CRITICAL
    assert severities["aws.rds.storage_encryption"] is Severity.HIGH
