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


def _wildcard_policy(condition=None):
    statement = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
    }
    if condition is not None:
        statement["Condition"] = condition
    return {
        "Version": "2012-10-17",
        "Statement": [statement],
    }


def _narrow_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/example:*",
            }
        ],
    }


class RoleGroupIAM:
    def __init__(self, group_document, role_document):
        self.group_document = group_document
        self.role_document = role_document

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1}}

    def get_paginator(self, name):
        if name == "list_users":
            return FakePaginator([{"Users": []}])
        if name == "list_groups":
            return FakePaginator([{"Groups": [{"GroupName": "admins"}]}])
        if name == "list_group_policies":
            return FakePaginator([{"PolicyNames": ["GroupInline"]}])
        if name == "list_attached_group_policies":
            return FakePaginator([{"AttachedPolicies": []}])
        if name == "list_roles":
            return FakePaginator([{"Roles": [{"RoleName": "deployment-role"}]}])
        if name == "list_role_policies":
            return FakePaginator([{"PolicyNames": []}])
        if name == "list_attached_role_policies":
            return FakePaginator(
                [
                    {
                        "AttachedPolicies": [
                            {
                                "PolicyName": "DeploymentManaged",
                                "PolicyArn": (
                                    "arn:aws:iam::123456789012:policy/DeploymentManaged"
                                ),
                            }
                        ]
                    }
                ]
            )
        raise AssertionError(name)


    def get_role(self, RoleName):
        assert RoleName == "deployment-role"
        return {
            "Role": {
                "RoleName": RoleName,
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
            }
        }

    def get_group_policy(self, GroupName, PolicyName):
        assert GroupName == "admins"
        assert PolicyName == "GroupInline"
        return {"PolicyDocument": self.group_document}

    def get_policy(self, PolicyArn):
        assert PolicyArn == "arn:aws:iam::123456789012:policy/DeploymentManaged"
        return {"Policy": {"DefaultVersionId": "v4"}}

    def get_policy_version(self, PolicyArn, VersionId):
        assert PolicyArn == "arn:aws:iam::123456789012:policy/DeploymentManaged"
        assert VersionId == "v4"
        return {"PolicyVersion": {"Document": self.role_document}}


def _identity_policy_findings(iam):
    return [
        finding
        for finding in IAMScanner(FakeSession(iam)).scan()
        if finding.check_id
        in {
            "aws.iam.group_wildcard_policy",
            "aws.iam.group_policy_analysis",
            "aws.iam.role_wildcard_policy",
            "aws.iam.role_policy_analysis",
        }
    ]


def test_no_users_does_not_prevent_group_and_role_policy_analysis():
    findings = _identity_policy_findings(
        RoleGroupIAM(
            group_document=_wildcard_policy(),
            role_document=_wildcard_policy(),
        )
    )
    by_check = {finding.check_id: finding for finding in findings}

    group = by_check["aws.iam.group_wildcard_policy"]
    assert group.severity is Severity.HIGH
    assert group.resource_id == "admins"
    assert group.evidence["identity_type"] == "group"
    assert group.evidence["matched_policies"][0]["policy_type"] == "inline"

    role = by_check["aws.iam.role_wildcard_policy"]
    assert role.severity is Severity.HIGH
    assert role.resource_id == "deployment-role"
    assert role.evidence["identity_type"] == "role"
    assert role.evidence["matched_policies"][0]["policy_type"] == "managed"


def test_conditioned_group_wildcard_and_narrow_role_policy_pass():
    group_document = _wildcard_policy(
        {
            "StringEquals": {
                "aws:RequestedRegion": "us-east-1",
            }
        }
    )
    findings = _identity_policy_findings(
        RoleGroupIAM(
            group_document=group_document,
            role_document=_narrow_policy(),
        )
    )
    by_check = {finding.check_id: finding for finding in findings}

    assert by_check["aws.iam.group_wildcard_policy"].severity is Severity.PASS
    assert by_check["aws.iam.role_wildcard_policy"].severity is Severity.PASS


def test_role_policy_parse_failure_is_reported_as_error():
    findings = _identity_policy_findings(
        RoleGroupIAM(
            group_document=_narrow_policy(),
            role_document="%not-valid-json",
        )
    )
    by_check = {finding.check_id: finding for finding in findings}

    assert by_check["aws.iam.group_wildcard_policy"].severity is Severity.PASS
    assert by_check["aws.iam.role_policy_analysis"].severity is Severity.ERROR
    assert by_check["aws.iam.role_policy_analysis"].evidence["identity_type"] == "role"
