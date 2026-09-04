# AWS Permissions for Project Blacklight

Project Blacklight is designed to scan AWS environments in read-only mode. The built-in AWS scanners do not need permission to create, modify, or delete AWS resources.

## Recommended approach

Create a dedicated IAM user or role for Blacklight and attach the example policy in:

```text
examples/aws/blacklight-readonly-policy.json
```

The policy grants only the API actions currently required by Blacklight's S3, IAM, CloudTrail, EC2, and RDS scanners.

## Current required actions

### Amazon S3

- `s3:ListAllMyBuckets`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetEncryptionConfiguration`
- `s3:GetBucketVersioning`
- `s3:GetBucketLogging`
- `s3:GetBucketPolicyStatus`

### AWS IAM

- `iam:GetAccountSummary`
- `iam:ListUsers`
- `iam:ListAccessKeys`
- `iam:GetAccessKeyLastUsed`

### AWS CloudTrail

- `cloudtrail:DescribeTrails`
- `cloudtrail:GetTrailStatus`

### Amazon EC2

- `ec2:DescribeSecurityGroups`

### Amazon RDS

- `rds:DescribeDBInstances`

## Why `Resource: "*"` appears in the policy

Several AWS list/describe/account-level actions do not support useful resource-level scoping, and Blacklight must discover resources before it can inspect them. The policy therefore uses `Resource: "*"` while limiting the `Action` list to read-only calls Blacklight currently makes.

This is not the same as granting administrator access: the policy does not include create, update, delete, attach, put, start, stop, or other mutation permissions.

## AWS profile example

After creating credentials for the dedicated scanning identity, configure a local profile:

```bash
aws configure --profile blacklight-audit
```

Then run:

```bash
blacklight scan aws --profile blacklight-audit
```

## Important

The example policy must be updated when new scanners begin calling additional AWS APIs. Contributors adding AWS checks should document every new required permission as part of the same pull request.
