# Project Blacklight Demo Guide

This walkthrough is designed to demonstrate Blacklight in a few minutes without requiring cloud credentials, a Docker daemon, a Kubernetes cluster, or real secrets.

## What the project demonstrates

Project Blacklight is a source-based Python security scanning toolkit built around four ideas:

1. **Deterministic detection.** Explicit security rules and provider/runtime evidence decide whether a finding exists.
2. **Read-only inspection.** AWS, Docker, Kubernetes, and Linux server scanners are designed to observe rather than remediate or mutate targets.
3. **Shared security pipeline.** Provider-specific scanners all emit normalized findings that feed the same risk, coverage, CI-gate, JSON, and HTML layers.
4. **False-positive boundaries.** Blacklight reports what the evidence proves and records uncertainty as INFO or ERROR coverage rather than inventing certainty.

The optional analyst integration is deliberately downstream of detection. AI or another analyst process can explain a completed report, but it cannot create, suppress, or change Blacklight findings.

## Setup

Blacklight requires Python 3.11 or newer.

Windows PowerShell:

```powershell
git clone https://github.com/OloaneShark/Project_Blacklight.git
cd Project_Blacklight
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

macOS/Linux:

```bash
git clone https://github.com/OloaneShark/Project_Blacklight.git
cd Project_Blacklight
python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

## Fastest proof that the project works

Run:

```bash
python scripts/verify_demo.py
```

This executes the installed `blacklight` command and verifies:

- the console entry point works
- a secure Dockerfile produces no actionable findings
- an insecure Dockerfile triggers deterministic findings and fails a HIGH security gate
- a secure Kubernetes manifest produces no actionable findings
- an insecure Kubernetes manifest triggers deterministic findings and fails a HIGH security gate
- JSON reports are parseable
- an HTML report is generated even when the security gate fails

The same smoke verifier is run by GitHub Actions after both editable developer installs and a fresh non-editable source install.

## Suggested 5-minute live walkthrough

### 1. Show the CLI

```bash
blacklight --version
blacklight --help
```

Talking point:

> The CLI is thin. It selects a provider/target and sends execution through a shared scanner registry and runner instead of hard-coding every scanner into one command.

### 2. Scan an intentionally insecure Dockerfile

```bash
blacklight scan docker \
  --path examples/demo/docker/insecure/Dockerfile \
  --fail-on high
```

On PowerShell, the same command can be written on one line:

```powershell
blacklight scan docker --path examples/demo/docker/insecure/Dockerfile --fail-on high
```

The fixture intentionally contains multiple detectable conditions, including:

- `FROM ...:latest`
- root runtime configuration
- populated secret-like ARG/ENV names using fake demo values
- remote `ADD`
- download-to-shell execution
- `chmod 777`

The important behavior is the exit code: `--fail-on high` turns findings into a deterministic CI/CD gate instead of only printing a report.

### 3. Show the clean-side boundary

```bash
blacklight scan docker --path examples/demo/docker/secure/Dockerfile --fail-on low
```

This demonstrates that Blacklight is not designed to make every scan look scary. The secure fixture should pass the selected checks without actionable findings.

### 4. Scan Kubernetes configuration

```bash
blacklight scan kubernetes \
  --path examples/demo/kubernetes/insecure.yaml \
  --fail-on high
```

The fixture includes explicit privileged mode, UID 0, privilege escalation, host namespace sharing, hostPath, ALL capabilities, Unconfined seccomp, hostPort, a mutable image tag, and a fake literal secret-like environment value.

Then compare it with:

```bash
blacklight scan kubernetes --path examples/demo/kubernetes/secure.yaml --fail-on low
```

Talking point:

> Static manifest scanning and live-cluster scanning are separate on purpose. A source scan should never unexpectedly require cluster credentials.

### 5. Generate an artifact that can be inspected

```bash
blacklight scan docker \
  --path examples/demo/docker/insecure/Dockerfile \
  --format html \
  --output reports/blacklight-demo.html
```

Or JSON:

```bash
blacklight scan kubernetes \
  --path examples/demo/kubernetes/insecure.yaml \
  --format json \
  --output reports/blacklight-demo.json
```

Reports include normalized findings, evidence, remediation, risk, scan coverage, and optional CI-gate results.

## Optional online vulnerability demo

The SBOM example requires internet access to OSV.dev:

```bash
python scripts/verify_demo.py --online
```

Or run it directly:

```bash
blacklight scan docker \
  --service sbom \
  --path examples/demo/sbom/vulnerable.cdx.json
```

Blacklight sends Package URLs and versions from the selected SBOM to OSV. It does not upload source code, Dockerfile contents, image layers, credentials, or environment variables.

If OSV cannot be reached, Blacklight records a coverage/error condition rather than reporting the package set as clean.

## Live-environment capabilities to discuss without needing them in the demo

### AWS

Blacklight uses boto3 and a documented least-privilege read policy. Current scanners cover S3, IAM, CloudTrail, EC2 security groups, RDS, Lambda Function URLs, and GuardDuty.

### Docker runtime

```bash
blacklight scan docker --service daemon
```

The daemon scanner uses fixed Docker CLI reads with `shell=False` and checks running-container privilege, namespaces, Docker socket mounts, sensitive host mounts, capabilities, device exposure, runtime user, and published ports.

### Kubernetes live cluster

```bash
blacklight scan kubernetes --service cluster --context production
blacklight scan kubernetes --service rbac --context production
blacklight scan kubernetes --service posture --context production
blacklight scan kubernetes --service admission --context production
```

The live scanners use read-only kubectl operations for workload posture, Service exposure, RBAC grants, ServiceAccount/token posture, NetworkPolicy posture, Pod Security Admission, and admission webhooks.

### Linux servers

```bash
blacklight scan server --host server.example.com --user blacklight-audit
```

Server scanners use the local OpenSSH client with fixed non-mutating commands and separate scanners for baseline, network, hardening, accounts, authentication, packages, services, TLS, and effective sshd configuration.

## Architecture explanation

The useful architectural distinction is:

```text
target/provider evidence
        ↓
provider scanner
        ↓
normalized Finding
        ↓
coverage + deterministic risk correlations
        ↓
CI/CD policy gates
        ↓
console / JSON / HTML
```

This keeps detection independent from presentation and lets new scanners reuse the same reporting and policy system.

## Examples of deliberate false-positive control

These are strong examples because they show that the project does not simply flag keywords:

- A powerful Kubernetes Role that is not bound to a subject is not treated as active RBAC exposure.
- Runtime correlations require the same container, Pod, or exact ServiceAccount identity rather than combining unrelated findings from one scan.
- A published Docker port is LOW exposure inventory, not a claim that it is internet reachable.
- A namespace with no NetworkPolicy is LOW because external network controls or CNI behavior may exist.
- Missing scan permission becomes an ERROR coverage gap rather than evidence that the target is secure.
- A vulnerability ID with unavailable severity data remains INFO instead of receiving an invented risk score.

## Security model

Blacklight is intentionally conservative:

- no automatic remediation
- no arbitrary remote shell execution
- no secret values in findings
- no AI-created security findings
- no claim of complete effective IAM/RBAC permission calculation where the scanner has not implemented it
- no claim that an unavailable scanner means the target is safe

## What is intentionally future work

These are useful follow-on directions, but they are not blockers for demonstrating the current project:

- direct package inventory/SBOM generation from Docker image layers
- richer fixed-version/remediation intelligence for vulnerability findings
- deeper provider-specific checks
- Azure and GCP providers
- broader third-party scanner extension points
- packaging or UI only if the source-first project direction changes

A strong way to describe the project is:

> I built Blacklight as a deterministic security-scanning framework rather than a one-off script. The provider-specific code gathers evidence, while findings, risk, coverage, reporting, and CI gates are shared. I spent a lot of effort on boundaries so the tool says what it can prove and exposes missing coverage instead of hiding it.
