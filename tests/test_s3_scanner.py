from botocore.exceptions import ClientError

from blacklight_security.models import Severity
from blacklight_security.scanners.aws import S3Scanner


class FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        assert service_name == "s3"
        return self._client


class FakeS3:
    def list_buckets(self):
        return {"Buckets": [{"Name": "example-bucket"}]}

    def get_public_access_block(self, Bucket):
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_encryption(self, Bucket):
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        }

    def get_bucket_versioning(self, Bucket):
        return {}

    def get_bucket_logging(self, Bucket):
        return {}

    def get_bucket_policy_status(self, Bucket):
        raise ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "No policy"}},
            "GetBucketPolicyStatus",
        )


def test_s3_scanner_emits_normalized_findings():
    findings = S3Scanner(FakeSession(FakeS3())).scan()

    by_check = {finding.check_id: finding for finding in findings}

    assert len(findings) == 5
    assert by_check["aws.s3.public_access_block"].severity is Severity.PASS
    assert by_check["aws.s3.default_encryption"].severity is Severity.PASS
    assert by_check["aws.s3.versioning"].severity is Severity.MEDIUM
    assert by_check["aws.s3.access_logging"].severity is Severity.MEDIUM
    assert by_check["aws.s3.public_policy"].severity is Severity.PASS
