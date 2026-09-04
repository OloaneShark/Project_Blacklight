# Project Blacklight

**Project Blacklight is an open-source cloud security scanning and risk-visibility toolkit.**

Blacklight reveals security weaknesses that are easy to miss in normal cloud configuration noise. Detection is deterministic: provider APIs and explicit security checks decide what is wrong. AI may be added later as an optional analyst layer for correlation, prioritization, explanation, and remediation assistance, but Blacklight does not require AI to detect security problems.

> Status: **early alpha / active migration from CloudGuard**

## Current capabilities

Blacklight currently scans Amazon S3, AWS IAM, CloudTrail, EC2 security groups, and Amazon RDS. Findings use stable check IDs, severities, evidence, and remediation guidance.

Blacklight now also performs deterministic risk assessment. Severity weights create a base score, then explicit correlation rules can raise risk when related findings form a more dangerous combination. Every correlation has a rule ID and reason; there is no opaque AI-generated security score.

## Install from source

PyPI publishing is planned but is **not live yet**.

```bash
git clone https://github.com/OloaneShark/Project_Blacklight.git
cd Project_Blacklight
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

Blacklight uses the standard boto3/AWS credential chain. Do not hard-code credentials into the project. Prefer a least-privilege/read-only scanning identity.

```bash
aws configure --profile my-security-audit
blacklight scan aws --profile my-security-audit
```

## Usage

Scan all supported AWS services:

```bash
blacklight scan aws
```

Scan one service:

```bash
blacklight scan aws --service s3
blacklight scan aws --service iam
blacklight scan aws --service cloudtrail
blacklight scan aws --service ec2
blacklight scan aws --service rds
```

Generate JSON:

```bash
blacklight scan aws --format json --output reports/aws-scan.json
```

## Architecture

```text
blacklight_security/
├── cli.py
├── models.py
├── registry.py
├── reporting.py
├── risk.py
└── scanners/
    └── aws/
        ├── s3.py
        ├── iam.py
        ├── cloudtrail.py
        ├── ec2.py
        └── rds.py
```

The scanner layer collects evidence and determines findings. The registry decouples scanner selection from the CLI. The risk engine consumes normalized findings after detection. Future AI-assisted analysis will sit after these deterministic layers rather than replacing them.

## Roadmap

Next priorities:

- Read-only least-privilege IAM policy/documentation for Blacklight scans
- Deeper AWS checks and additional AWS services
- More deterministic correlation rules with test coverage
- Contributor-facing scanner registration documentation
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
