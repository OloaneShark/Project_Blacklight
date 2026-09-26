# Project Blacklight

**Project Blacklight is an open-source cloud, container, Kubernetes, and Linux server security scanning and risk-visibility toolkit.**

Blacklight reveals security weaknesses that are easy to miss in cloud and workload configuration noise. Detection is deterministic: provider APIs and explicit security checks decide what is wrong. An optional external analyst interface can explain completed Blacklight JSON reports, but analyst output never creates, suppresses, or changes security findings.

> Status: **early alpha / active development**

## Current capabilities

Blacklight currently scans Amazon S3, AWS IAM, CloudTrail, EC2 security groups, Amazon RDS, AWS Lambda, Amazon GuardDuty, local Dockerfiles, local Kubernetes workload manifests, and a read-only Linux server baseline over SSH. Findings use stable check IDs, severities, evidence, and remediation guidance.

The Dockerfile scanner statically detects root runtime configuration, implicit/latest base-image tags, secret-like values embedded through ARG/ENV, unchecked remote ADD sources, curl/wget-to-shell pipelines, and chmod 777. It does not require a Docker daemon. See [docs/docker-scanning.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/docker-scanning.md).

The Kubernetes scanner statically checks workload manifests for privileged containers, explicit UID 0, privilege escalation, host namespace sharing, hostPath volumes, ALL capabilities, Unconfined seccomp, hostPort, mutable image tags, and literal secret-like environment values. It does not require cluster credentials. See [docs/kubernetes-scanning.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/kubernetes-scanning.md).

The server scanner uses the local OpenSSH client in non-interactive mode to inspect a remote Linux host with fixed read-only commands. The first baseline checks explicit insecure SSH directives, SSH configuration file permissions, additional UID 0 accounts, and world-writable Docker socket access. See [docs/server-scanning.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/server-scanning.md).

The IAM scanner checks root MFA, long-lived access-key age/usage, policies attached directly to IAM users, groups, and roles, and IAM role trust policies. It flags unconditional identity-policy `Allow` statements that grant both `Action: "*"` and `Resource: "*"`, plus role trust statements with a wildcard principal and STS assume-role action but no condition. These checks report directly observed policy evidence; they do not claim to calculate final effective permissions or every prerequisite for successful role assumption.

The Lambda scanner checks whether Lambda Function URLs allow unauthenticated public access. The GuardDuty scanner checks whether managed threat detection is enabled in the selected AWS region.

Blacklight also performs deterministic risk assessment. Severity weights create a base score, then explicit correlation rules can raise risk when related findings form a more dangerous combination. Every correlation has a rule ID and reason; there is no opaque AI-generated security score. See [docs/risk-engine.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/risk-engine.md) for the scoring model and current correlation rules.

Risk and scan coverage are reported separately. Scanner `ERROR` findings do not add security-risk points, but they reduce confidence that the observed risk score represents the entire selected scan scope. Coverage is reported as `FULL`, `PARTIAL`, `LIMITED`, or `UNKNOWN`, with a corresponding deterministic risk-confidence label. See [docs/coverage-confidence.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/coverage-confidence.md).

## Use from GitHub

Project Blacklight is maintained as a **source-only GitHub project**.

There is no desktop application, native `.exe`, one-command installer, PyPI release flow, or hosted GHCR image to maintain.

Users can either clone the repository:

```bash
git clone https://github.com/OloaneShark/Project_Blacklight.git
cd Project_Blacklight
python -m venv .venv
```

or use GitHub's **Code → Download ZIP** option and extract the repository locally.

Activate the virtual environment, then install the checked-out source:

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

macOS / Linux:

```bash
source .venv/bin/activate
python -m pip install -e .
```

For contributors:

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check blacklight_security tests
```

## AWS credentials and least privilege

Blacklight uses boto3's standard AWS credential provider chain. **Do not put AWS keys in the repository.**

The recommended local setup is a dedicated AWS CLI profile using Blacklight's least-privilege read policy:

```text
examples/aws/blacklight-readonly-policy.json
```

Configure the profile:

```bash
aws configure --profile blacklight-audit
```

The AWS CLI asks for the access key ID, secret access key, default region, and output format, then stores that profile outside the Blacklight project in the normal AWS configuration files.

Run Blacklight with it:

```bash
blacklight scan aws --profile blacklight-audit
```

If the organization uses AWS IAM Identity Center / SSO, that is even better because it avoids long-lived access keys:

```bash
aws configure sso --profile blacklight-audit
aws sso login --profile blacklight-audit
blacklight scan aws --profile blacklight-audit
```

Blacklight does **not** automatically load a project `.env` file. See [docs/aws-credentials.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/aws-credentials.md) for profiles, SSO, environment variables, IAM roles, credential locations, and why a project `.env` is not the preferred credential store.

See [docs/aws-permissions.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/aws-permissions.md) for the exact read-only permission breakdown.

## Usage

Scan all supported AWS services:

```bash
blacklight scan aws
```

Scan Dockerfiles in the current project:

```bash
blacklight scan docker --path .
```

Scan one Dockerfile:

```bash
blacklight scan docker --path ./Dockerfile
```

Scan Kubernetes manifests:

```bash
blacklight scan kubernetes --path .
# short alias
blacklight scan k8s --path .
```

Scan a remote Linux server over SSH:

```bash
blacklight scan server --host server.example.com --user blacklight-audit
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


## Optional analyst integrations

A completed Blacklight JSON report can be handed to an explicitly selected external analyst program:

```bash
blacklight analyze --input reports/aws-scan.json --command python --arg my_analyst.py
```

Blacklight sends the JSON report over stdin and receives explanation over stdout. The analyst layer is out-of-process, uses `shell=False`, and cannot alter Blacklight's original findings or scan exit code. See [docs/analyst-integrations.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/analyst-integrations.md).


## Architecture

```text
blacklight_security/
├── analyst.py
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
    ├── aws/
    │   ├── s3.py
    │   ├── iam.py
    │   ├── cloudtrail.py
    │   ├── ec2.py
    │   ├── rds.py
    │   ├── lambda_functions.py
    │   └── guardduty.py
    ├── docker/
    │   └── dockerfile.py
    ├── kubernetes/
    │   └── manifests.py
    └── server/
        └── linux.py
```

The CLI parses commands and hands execution to the scan runner. The runner resolves scan context, coordinates registered scanners, isolates per-scanner AWS API failures, tracks coverage, and creates one normalized scan result. Scanner modules collect evidence and determine findings. The risk engine consumes successfully observed security findings after detection. The coverage layer describes how completely the selected scope was inspected without changing the risk score. The policy layer can turn deterministic findings into a CI/CD pass/fail decision, and the reporting layers render console, JSON, or standalone HTML output.

The original CloudGuard Flask dashboard is preserved under `legacy/cloudguard_flask/` for history and reference. It is not the current Blacklight entry point.

## Roadmap status

The Blacklight core is implemented as a source-based CLI project: deterministic AWS scanning, Dockerfile scanning, Kubernetes manifest scanning, shared risk/coverage/gates, JSON/HTML reporting, contributor documentation, and an optional external analyst interface.

Future expansion is intentionally a new phase rather than unfinished core work:

- deeper Linux server baseline checks and reusable read-only target profiles
- deeper AWS/Docker/Kubernetes checks
- live Kubernetes cluster and Docker-daemon inspection
- additional cloud providers
- packaging or UI work only if the project direction calls for it later
- richer third-party scanner/analyst extension points

See [docs/how-blacklight-works.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/how-blacklight-works.md) for the end-to-end architecture.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/CONTRIBUTING.md). Contributors adding scanners should also read [docs/scanner-authoring.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/docs/scanner-authoring.md) for the current scanner contract, registration workflow, permissions, and testing requirements.

## Security

See [SECURITY.md](https://github.com/OloaneShark/Project_Blacklight/blob/main/SECURITY.md) before reporting vulnerabilities or working with credentials.

## License

MIT. See [LICENSE](https://github.com/OloaneShark/Project_Blacklight/blob/main/LICENSE).
