# Project Blacklight

**Project Blacklight is an open-source cloud security scanning and risk-visibility toolkit.**

Blacklight reveals security weaknesses that are easy to miss in normal cloud configuration noise. Detection is deterministic: provider APIs and explicit security checks decide what is wrong. AI may be added later as an optional analyst layer for correlation, prioritization, explanation, and remediation assistance, but Blacklight does not require AI to detect security problems.

> Status: **early alpha / active development**

## Current capabilities

Blacklight currently scans Amazon S3, AWS IAM, CloudTrail, EC2 security groups, Amazon RDS, AWS Lambda, and Amazon GuardDuty. Findings use stable check IDs, severities, evidence, and remediation guidance.

The IAM scanner checks root MFA, long-lived access-key age/usage, policies attached directly to IAM users, groups, and roles, and IAM role trust policies. It flags unconditional identity-policy `Allow` statements that grant both `Action: "*"` and `Resource: "*"`, plus role trust statements with a wildcard principal and STS assume-role action but no condition. These checks report directly observed policy evidence; they do not claim to calculate final effective permissions or every prerequisite for successful role assumption.

The Lambda scanner checks whether Lambda Function URLs allow unauthenticated public access. The GuardDuty scanner checks whether managed threat detection is enabled in the selected AWS region.

Blacklight also performs deterministic risk assessment. Severity weights create a base score, then explicit correlation rules can raise risk when related findings form a more dangerous combination. Every correlation has a rule ID and reason; there is no opaque AI-generated security score. See [docs/risk-engine.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/risk-engine.md) for the scoring model and current correlation rules.

Risk and scan coverage are reported separately. Scanner `ERROR` findings do not add security-risk points, but they reduce confidence that the observed risk score represents the entire selected scan scope. Coverage is reported as `FULL`, `PARTIAL`, `LIMITED`, or `UNKNOWN`, with a corresponding deterministic risk-confidence label. See [docs/coverage-confidence.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/coverage-confidence.md).

## Install from source

PyPI publishing automation is prepared, but the first public release is **not live yet**. The remaining account-side step is configuring the PyPI Trusted Publisher for this repository and then publishing a matching GitHub Release.

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

For local release-package validation:

```bash
python -m pip install -e ".[release]"
python -m build
python -m twine check dist/*
```

See [docs/releases.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/releases.md) for versioned GitHub Releases and [docs/publishing.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/publishing.md) for the PyPI Trusted Publishing procedure.

## AWS credentials and least privilege

Blacklight uses the standard boto3/AWS credential chain. Do not hard-code credentials into the project.

For normal use, prefer a dedicated read-only/least-privilege scanning identity. Project Blacklight includes an example policy at:

```text
examples/aws/blacklight-readonly-policy.json
```

The policy contains only the AWS API actions currently required by the built-in scanners. See [docs/aws-permissions.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/aws-permissions.md) for the permission breakdown and setup notes.

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

HTML reports contain scan context, coverage and risk confidence, risk score, severity counts, deterministic correlations, CI/CD gate results when enabled, findings, remediation guidance, and escaped evidence. They use inline styling only, so the generated file can be opened locally without a web server or external assets.

Console, JSON, and HTML reports include scan execution metadata such as provider, selected region, scanners executed, scan status, duration, coverage state, affected scanners, and risk confidence. AWS scans also include best-effort environment identity context such as account ID, caller ARN, partition, selected profile, and resolved region so saved reports can identify the environment that produced them.

If an individual AWS scanner encounters an AWS API `ClientError`, Blacklight records a normalized `ERROR` finding for that scanner and continues with the remaining selected scanners. This preserves usable evidence from healthy services while making the coverage gap explicit.

## CI/CD gates

Blacklight can enforce deterministic security and scan-completeness requirements in CI/CD.

Security finding gate:

```bash
blacklight scan aws --fail-on high
```

Supported security thresholds are `low`, `medium`, `high`, and `critical`. A threshold includes that severity and anything above it. For example, `--fail-on high` fails on both HIGH and CRITICAL findings.

Full-coverage gate:

```bash
blacklight scan aws --require-full-coverage
```

When enabled, any `PARTIAL`, `LIMITED`, or `UNKNOWN` coverage result fails the coverage gate. This does not change the risk score; it only requires every selected scanner to complete without `ERROR` findings.

Both gates can be combined:

```bash
blacklight scan aws --fail-on high --require-full-coverage
```

```text
0 = requested security and coverage gates passed
1 = security threshold was reached or exceeded
2 = operational/credential failure, zero usable scanner coverage, or requested full-coverage gate failure
```

A `PARTIAL` scan can still return `0` when `--require-full-coverage` is not enabled and no security gate fails. With `--require-full-coverage`, the same partial scan returns `2`. A `LIMITED` scan, where every selected scanner returned inspection errors, always returns `2` after the report is rendered or written.

Example GitHub Actions step:

```yaml
- name: Run Project Blacklight gates
  run: blacklight scan aws --fail-on high --require-full-coverage
```

JSON output includes a deterministic `policy` object for the security threshold, a `coverage_gate` object for the optional full-coverage requirement, and a `scan.coverage` object describing inspection completeness independently from security risk.

The gate can also be combined with an HTML artifact:

```bash
blacklight scan aws --fail-on high --require-full-coverage --format html --output reports/blacklight-report.html
```

Blacklight writes the report before returning the final gate or coverage exit code, so failed pipeline runs can still retain the report as an artifact.

## Architecture

```text
blacklight_security/
├── cli.py
├── coverage.py
├── html_reporting.py
├── models.py
├── policy.py
├── registry.py
├── reporting.py
├── risk.py
├── runner.py
├── scan_context.py
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

The CLI parses commands and hands execution to the scan runner. The runner resolves scan context, coordinates registered scanners, isolates per-scanner AWS API failures, tracks coverage, and creates one normalized scan result. Scanner modules collect evidence and determine findings. The risk engine consumes successfully observed security findings after detection. The coverage layer describes how completely the selected scope was inspected without changing the risk score. The policy layer can turn deterministic findings into a CI/CD pass/fail decision, and the reporting layers render console, JSON, or standalone HTML output.

The original CloudGuard Flask dashboard is preserved under `legacy/cloudguard_flask/` for history and reference. It is not the current Blacklight entry point.

## Roadmap

Next priorities:

- Deeper AWS checks and additional AWS services
- First PyPI release after Trusted Publisher activation
- Standalone executables
- Docker distribution
- Docker and Kubernetes security scanners
- Optional pluggable AI analyst integrations

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/CONTRIBUTING.md). Contributors adding scanners should also read [docs/scanner-authoring.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/scanner-authoring.md) for the current scanner contract, registration workflow, permissions, and testing requirements.

## Security

See [SECURITY.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/SECURITY.md) before reporting vulnerabilities or working with credentials.

## License

MIT. See [LICENSE](https://github.com/OloaneShark/Project_Blacklight/blob/main/LICENSE).
