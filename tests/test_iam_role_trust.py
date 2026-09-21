from blacklight_security.models import Severity
from blacklight_security.scanners.aws.iam import IAMScanner


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return self.pages


class FakeSession:
    def __init__(self, iam):
        self.iam = iam

    def client(self, service_name):
        assert service_name == "iam"
        return self.iam


class TrustIAM:
    def __init__(self, trust_document):
        self.trust_document = trust_document

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1}}

    def get_paginator(self, name):
        if name == "list_users":
            return FakePaginator([{"Users": []}])
        if name == "list_groups":
            return FakePaginator([{"Groups": []}])
        if name == "list_roles":
            return FakePaginator([{"Roles": [{"RoleName": "deploy-role"}]}])
        if name == "list_role_policies":
            return FakePaginator([{"PolicyNames": []}])
        if name == "list_attached_role_policies":
            return FakePaginator([{"AttachedPolicies": []}])
        raise AssertionError(name)

    def get_role(self, RoleName):
        assert RoleName == "deploy-role"
        return {
            "Role": {
                "RoleName": RoleName,
                "AssumeRolePolicyDocument": self.trust_document,
            }
        }


def _trust_findings(document):
    return [
        finding
        for finding in IAMScanner(FakeSession(TrustIAM(document))).scan()
        if finding.check_id == "aws.iam.role_trust_wildcard"
    ]


def test_unconditional_wildcard_principal_is_high():
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = _trust_findings(document)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.resource_id == "deploy-role"
    assert finding.evidence["statement_indexes"] == [0]
    assert finding.evidence["assume_actions"] == ["sts:AssumeRole"]


def test_wildcard_principal_with_condition_is_not_flagged_as_unconditional():
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "expected-external-id",
                    }
                },
            }
        ],
    }

    findings = _trust_findings(document)

    assert len(findings) == 1
    assert findings[0].severity is Severity.PASS


def test_specific_service_principal_passes():
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = _trust_findings(document)

    assert len(findings) == 1
    assert findings[0].severity is Severity.PASS


def test_wildcard_principal_with_wildcard_action_is_high():
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["*", "arn:aws:iam::123456789012:root"]},
                "Action": "*",
            }
        ],
    }

    findings = _trust_findings(document)

    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence["assume_actions"] == ["*"]


def test_invalid_role_trust_policy_is_error():
    findings = _trust_findings("%not-valid-json")

    assert len(findings) == 1
    assert findings[0].severity is Severity.ERROR
