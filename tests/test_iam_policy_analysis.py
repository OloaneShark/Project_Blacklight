import json
from urllib.parse import quote

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


class PolicyIAM:
    def __init__(self, inline_document=None, managed_document=None):
        self.inline_document = inline_document
        self.managed_document = managed_document

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1}}

    def get_paginator(self, name):
        if name == "list_users":
            return FakePaginator([{"Users": [{"UserName": "builder"}]}])
        if name == "list_access_keys":
            return FakePaginator([{"AccessKeyMetadata": []}])
        if name == "list_user_policies":
            names = ["InlinePolicy"] if self.inline_document is not None else []
            return FakePaginator([{"PolicyNames": names}])
        if name == "list_attached_user_policies":
            policies = []
            if self.managed_document is not None:
                policies.append(
                    {
                        "PolicyName": "ManagedPolicy",
                        "PolicyArn": "arn:aws:iam::123456789012:policy/ManagedPolicy",
                    }
                )
            return FakePaginator([{"AttachedPolicies": policies}])
        raise AssertionError(name)

    def get_user_policy(self, UserName, PolicyName):
        assert UserName == "builder"
        assert PolicyName == "InlinePolicy"
        return {"PolicyDocument": self.inline_document}

    def get_policy(self, PolicyArn):
        assert PolicyArn == "arn:aws:iam::123456789012:policy/ManagedPolicy"
        return {"Policy": {"DefaultVersionId": "v3"}}

    def get_policy_version(self, PolicyArn, VersionId):
        assert PolicyArn == "arn:aws:iam::123456789012:policy/ManagedPolicy"
        assert VersionId == "v3"
        return {"PolicyVersion": {"Document": self.managed_document}}


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


def _policy_findings(iam):
    return [
        finding
        for finding in IAMScanner(FakeSession(iam)).scan()
        if finding.check_id in {
            "aws.iam.user_wildcard_policy",
            "aws.iam.user_policy_analysis",
        }
    ]


def test_inline_url_encoded_wildcard_policy_is_flagged():
    encoded = quote(json.dumps(_wildcard_policy()), safe="")
    findings = _policy_findings(PolicyIAM(inline_document=encoded))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "aws.iam.user_wildcard_policy"
    assert finding.severity is Severity.HIGH
    assert finding.resource_id == "builder"
    assert finding.evidence["matched_policy_count"] == 1
    assert finding.evidence["matched_policies"][0]["policy_type"] == "inline"
    assert finding.evidence["matched_policies"][0]["statement_indexes"] == [0]


def test_attached_managed_wildcard_policy_is_flagged():
    findings = _policy_findings(PolicyIAM(managed_document=_wildcard_policy()))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    matched = finding.evidence["matched_policies"][0]
    assert matched["policy_type"] == "managed"
    assert matched["policy_arn"] == "arn:aws:iam::123456789012:policy/ManagedPolicy"


def test_conditioned_wildcard_allow_is_not_reported_as_unconditional():
    document = _wildcard_policy(
        {
            "StringEquals": {
                "aws:RequestedRegion": "us-east-1",
            }
        }
    )
    findings = _policy_findings(PolicyIAM(inline_document=document))

    assert len(findings) == 1
    assert findings[0].severity is Severity.PASS
    assert findings[0].evidence["matched_policy_count"] == 0


def test_narrow_policy_passes_wildcard_check():
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::example/*",
            }
        ],
    }
    findings = _policy_findings(PolicyIAM(inline_document=document))

    assert len(findings) == 1
    assert findings[0].severity is Severity.PASS


def test_unparseable_policy_document_reduces_iam_coverage():
    findings = _policy_findings(PolicyIAM(inline_document="%not-valid-json"))

    assert len(findings) == 1
    assert findings[0].check_id == "aws.iam.user_policy_analysis"
    assert findings[0].severity is Severity.ERROR
    assert findings[0].evidence["policy_name"] == "InlinePolicy"
