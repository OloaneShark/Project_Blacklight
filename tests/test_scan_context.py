from botocore.exceptions import ClientError

from blacklight_security.scan_context import resolve_scan_context


class FakeSTS:
    def get_caller_identity(self):
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/BlacklightAudit/session",
            "UserId": "AROATEST:session",
        }


class FakeSession:
    region_name = "us-east-1"
    profile_name = "blacklight-audit"

    def client(self, service_name):
        assert service_name == "sts"
        return FakeSTS()


class FailingSTS:
    def get_caller_identity(self):
        raise ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": "STS unavailable"}},
            "GetCallerIdentity",
        )


class FailingSession(FakeSession):
    def client(self, service_name):
        assert service_name == "sts"
        return FailingSTS()


def test_resolve_aws_context_collects_account_principal_and_partition():
    context = resolve_scan_context("aws", FakeSession())

    assert context.identity_status == "RESOLVED"
    assert context.region == "us-east-1"
    assert context.profile == "blacklight-audit"
    assert context.account_id == "123456789012"
    assert context.partition == "aws"
    assert context.user_id == "AROATEST:session"
    assert context.principal_arn.endswith("assumed-role/BlacklightAudit/session")


def test_resolve_aws_context_is_best_effort_when_sts_fails():
    context = resolve_scan_context("aws", FailingSession())

    assert context.identity_status == "UNAVAILABLE"
    assert context.account_id is None
    assert context.principal_arn is None
    assert "ServiceUnavailable" in context.identity_error


def test_non_aws_context_does_not_request_sts_identity():
    context = resolve_scan_context("example-cloud", FakeSession())

    assert context.provider == "example-cloud"
    assert context.identity_status == "NOT_APPLICABLE"
    assert context.account_id is None
