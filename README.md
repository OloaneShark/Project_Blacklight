# Project Blacklight

**Project Blacklight is an open-source cloud security scanning and risk-visibility toolkit.**

Blacklight reveals security weaknesses that are easy to miss in normal cloud configuration noise. Detection is deterministic: provider APIs and explicit security checks decide what is wrong. AI may be added later as an optional analyst layer for correlation, prioritization, explanation, and remediation assistance, but Blacklight does not require AI to detect security problems.

> Status: **early alpha / active development**

## Current capabilities

Blacklight currently scans Amazon S3, AWS IAM, CloudTrail, EC2 security groups, Amazon RDS, AWS Lambda, and Amazon GuardDuty. Findings use stable check IDs, severities, evidence, and remediation guidance.

The Lambda scanner checks whether Lambda Function URLs allow unauthenticated public access. The GuardDuty scanner checks whether managed threat detection is enabled in the selected AWS region.

Blacklight also performs deterministic risk assessment. Severity weights create a base score, then explicit correlation rules can raise risk when related findings form a more dangerous combination. Every correlation has a rule ID and reason; there is no opaque AI-generated security score.

## Install from source

PyPI publishing is planned but is **not live yet**.

```bash
git clone https://github.com/OloaneShark/Project_Blacklight.git
cd Project_Blacklight
python -m venv .venv
```

Activate the virtual environment, then install Blacklight:

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## AWS credentials and least privilege

Blacklight uses the standard boto3/AWS credential chain. Do not hard-code credentials into the project.

For normal use, prefer a dedicated read-only/least-privilege scanning identity. Project Blacklight includes an example policy at:

```text
examples/aws/blacklight-readonly-policy.json
```

The policy contains only the AWS API actions currently required by the built-in scanners. See [docs/aws-permissions.md](docs/aws-permissions.md) for the permission breakdown and setup notes.

Configure a profile for the scanning identity:

```bash
aws configure --profile blacklight-audit
```

Then run:

```bash
blacklight scan aws --profile blacklight-audit
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
blacklight scan aws --service lambda
blacklight scan aws --service guardduty
```

Generate JSON:

```bash
blacklight scan aws --format json --output reports/aws-scan.json
```

Generate a self-contained HTML report:

```bash
blacklight scan aws --format html --output reports/blacklight-report.html
```

HTML reports contain scan context, risk score, severity counts, deterministic correlations, CI/CD gate results when enabled, findings, remediation guidance, and escaped evidence. They use inline styling only, so the generated file can be opened locally without a web server or external assets.

Console, JSON, and HTML reports include scan execution metadata such as provider, selected region, scanners executed, scan status, and duration.

## CI/CD security gate

Blacklight can act as a deterministic pipeline gate by returning a non-zero exit code when findings meet a requested severity threshold.

```bash
blacklight scan aws --fail-on high
```

Supported thresholds are `low`, `medium`, `high`, and `critical`. A threshold includes that severity and anything above it. For example, `--fail-on high` fails on both HIGH and CRITICAL findings.

```text
0 = scan completed and the security gate passed
1 = security threshold was reached or exceeded
2 = Blacklight could not complete the scan because of an operational or credential error
```

Example GitHub Actions step:

```yaml
- name: Run Project Blacklight security gate
  run: blacklight scan aws --fail-on high
```

JSON output includes a deterministic `policy` object describing the selected threshold, whether the gate passed, how many findings triggered it, and the highest detected security severity.

The gate can also be combined with an HTML artifact:

```bash
blacklight scan aws --fail-on high --format html --output reports/blacklight-report.html
```

Blacklight writes the report before returning the gate exit code, so failed pipeline runs can still retain the report as an artifact.

## Architecture

```text
blacklight_security/
├── cli.py
├── html_reporting.py
├── models.py
├── policy.py
├── registry.py
├── runner.py
├── reporting.py
├── risk.py
└── scanners/
    └── aws/
        ├── s3.py
        ├── iam.py
        ├── cloudtrail.py
        ├── ec2.py
        ├── rds.py
        ├── lambda_functions.py
        └── guardduty.py
```

The CLI parses commands and hands execution to the scan runner. The runner coordinates registered scanners and creates one normalized scan result. Scanner modules collect evidence and determine findings. The risk engine consumes those findings after detection. The policy layer can turn deterministic findings into a CI/CD pass/fail decision, and the reporting layers render console, JSON, or standalone HTML output.

The original CloudGuard Flask dashboard is preserved under `legacy/cloudguard_flask/` for history and reference. It is not the current Blacklight entry point.

## Roadmap

Next priorities:

- Deeper AWS checks and additional AWS services
- More deterministic correlation rules with test coverage
- Contributor-facing scanner registration documentation
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
