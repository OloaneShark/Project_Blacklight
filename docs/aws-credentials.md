# AWS Credentials

Project Blacklight does **not** need AWS keys stored inside the repository and does **not** automatically load a project `.env` file.

Blacklight uses boto3's normal AWS credential provider chain. The cleanest setup is to give Blacklight a dedicated AWS profile outside the project folder.

## Recommended: AWS CLI profile

Create a dedicated least-privilege Blacklight identity in AWS and attach the permissions from:

```text
examples/aws/blacklight-readonly-policy.json
```

Then configure a local profile:

```bash
aws configure --profile blacklight-audit
```

The AWS CLI prompts for:

```text
AWS Access Key ID
AWS Secret Access Key
Default region name
Default output format
```

A normal setup might use:

```text
Default region name: us-east-1
Default output format: json
```

The credentials are stored by the AWS tooling outside the Blacklight repository.

Typical locations:

```text
Windows:
%USERPROFILE%\.aws\credentials
%USERPROFILE%\.aws\config

macOS / Linux:
~/.aws/credentials
~/.aws/config
```

Run Blacklight with that profile:

```bash
blacklight scan aws --profile blacklight-audit
```

You can verify the profile before scanning:

```bash
aws sts get-caller-identity --profile blacklight-audit
```

## Better for organizations: AWS IAM Identity Center / SSO

If the AWS account uses IAM Identity Center, avoid long-lived access keys entirely.

Configure a profile:

```bash
aws configure sso --profile blacklight-audit
```

Log in:

```bash
aws sso login --profile blacklight-audit
```

Then run:

```bash
blacklight scan aws --profile blacklight-audit
```

Boto3 reads the resulting AWS profile/session information through the normal credential chain.

## Temporary environment variables

Temporary credentials can also be supplied through environment variables.

PowerShell:

```powershell
$env:AWS_ACCESS_KEY_ID="..."
$env:AWS_SECRET_ACCESS_KEY="..."
$env:AWS_SESSION_TOKEN="..."   # only when temporary credentials include one
$env:AWS_DEFAULT_REGION="us-east-1"

blacklight scan aws
```

macOS / Linux:

```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."   # only when applicable
export AWS_DEFAULT_REGION="us-east-1"

blacklight scan aws
```

When the shell closes, those shell-scoped variables can be discarded.

## IAM roles on AWS infrastructure

If Blacklight runs on AWS infrastructure such as EC2 with an attached IAM role, boto3 can use that role automatically.

In that case, no access key or secret key needs to be typed into Blacklight at all:

```bash
blacklight scan aws
```

The attached role should still be limited to the read-only actions Blacklight needs.

## Should I put AWS keys in a .env file?

Prefer **no**.

Blacklight currently does not call `python-dotenv` or automatically read a project `.env` file, so creating:

```text
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

inside `Project_Blacklight/.env` would not make Blacklight load those values by itself.

The repository ignores `.env`, but keeping long-lived AWS credentials inside a project directory is still unnecessary risk.

Use one of these instead, in this order when practical:

1. AWS IAM Identity Center / SSO
2. an attached IAM role or other temporary workload credentials
3. a dedicated local AWS CLI profile
4. temporary environment variables

Avoid committing credentials, placing them in source files, or pasting them into command-line arguments.

## Permissions

Credential storage and permissions are separate.

The credentials answer:

> "Who is Blacklight connecting as?"

The IAM policy answers:

> "What is Blacklight allowed to read?"

See:

- `examples/aws/blacklight-readonly-policy.json`
- `docs/aws-permissions.md`

The built-in scanners are designed around read-only inspection. Do not give Blacklight AdministratorAccess just to make the scan work.
