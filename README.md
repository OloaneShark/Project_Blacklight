# Project Blacklight

**Project Blacklight is an open-source cloud security scanning and risk-visibility toolkit.**

Blacklight is being built to reveal security weaknesses that are easy to miss in normal cloud configuration noise. The core scanner is deterministic: provider APIs and explicit security checks decide what is wrong. AI may be added later as an optional analyst layer for correlation, prioritization, explanation, and remediation assistance, but Blacklight does not require AI to detect security problems.

> Status: **early alpha / active migration from CloudGuard**

## Why Blacklight

The original CloudGuard project began as a Flask-based AWS security dashboard. It already performed real checks against S3, IAM, CloudTrail, EC2, and RDS. Project Blacklight is the next stage: turning that work into a reusable open-source security tool that other people can install, run, fork, extend, and contribute to.

The old Flask dashboard files are temporarily retained while working security checks are migrated into the new package architecture.

## Current alpha capabilities

Blacklight currently scans:

### Amazon S3
- Block Public Access configuration
- Default server-side encryption
- Versioning
- Server access logging
- AWS-evaluated public bucket policy status

### AWS IAM
- Root account MFA visibility
- Active access-key age
- Active access-key last-used activity

### AWS CloudTrail
- Trail presence
- Active logging state
- Multi-region configuration

### Amazon EC2
- Security groups with unrestricted all-port ingress
- Public exposure of sensitive administration/database ports including SSH, RDP, MySQL, PostgreSQL, Redis, MongoDB, and Elasticsearch

### Amazon RDS
- Public database accessibility
- Storage encryption

Every result is normalized into a structured finding with a stable check ID, severity, evidence, and remediation guidance.

## Install from source

PyPI publishing is planned but is **not live yet**. For now, install from the repository:

```bash
git clone https://github.com/OloaneShark/cloudguard.git
cd cloudguard
python -m venv .venv
```

Activate the virtual environment, then:

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## AWS credentials

Blacklight uses the normal `boto3`/AWS credential chain. It does not require credentials to be hard-coded into the project.

For example, configure an AWS CLI profile and then run Blacklight with that profile:

```bash
aws configure --profile my-security-audit
blacklight scan aws --profile my-security-audit
```

Use a least-privilege/read-only scanning identity whenever possible.

## Usage

Scan the supported AWS services:

```bash
blacklight scan aws
```

Scan one service:

```bash
blacklight scan aws --service iam
blacklight scan aws --service s3
blacklight scan aws --service cloudtrail
blacklight scan aws --service ec2
blacklight scan aws --service rds
```

Generate structured JSON:

```bash
blacklight scan aws --format json --output reports/aws-scan.json
```

## Architecture direction

```text
blacklight_security/
├── cli.py
├── models.py
├── reporting.py
└── scanners/
    └── aws/
        ├── s3.py
        ├── iam.py
        ├── cloudtrail.py
        ├── ec2.py
        └── rds.py
```

The scanner layer collects evidence and determines findings. Reporting consumes normalized findings. Future correlation and AI-assisted analysis will sit **after** detection rather than replacing it.

## Roadmap

Next priorities:

- Shared scanner/check registration so contributors can add modules without editing CLI internals
- Read-only least-privilege IAM policy/documentation for Blacklight scans
- Deterministic risk scoring and finding correlation
- Additional AWS services and deeper checks
- HTML reports
- PyPI publishing
- Versioned GitHub releases
- Standalone executables
- Docker distribution
- Docker and Kubernetes security scanners
- Optional pluggable AI analyst integrations

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) before reporting vulnerabilities or working with credentials.

## License

MIT. See [LICENSE](LICENSE).
