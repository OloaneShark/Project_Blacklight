# How Project Blacklight Works

Project Blacklight is a deterministic security scanner with provider-specific evidence collectors and one shared reporting/risk pipeline.

## Core flow

```text
User command / CI job
        ↓
CLI
        ↓
Scan target
        ↓
Scanner registry
        ↓
Provider scanner(s)
        ↓
Normalized Finding objects
        ↓
Coverage assessment
        ↓
Deterministic risk + correlations
        ↓
Optional CI gates
        ↓
Console / JSON / HTML
        ↓
Optional external analyst
```

## Providers

### AWS

AWS scanners use boto3 read APIs and a dedicated least-privilege scanning identity. Blacklight never needs write permissions for the built-in AWS checks.

### Docker

The Docker provider statically parses Dockerfiles from a local file or directory. It does not need the Docker daemon.

### Kubernetes

The Kubernetes provider statically parses workload YAML from a local file or directory. It does not need cluster credentials.

## Findings

Every security result becomes a normalized `Finding` with:

- stable check ID
- provider
- service/scanner
- resource type
- resource ID
- severity
- title
- explanation
- remediation
- deterministic evidence

That common model is why AWS, Docker, and Kubernetes can all use the same reporting and CI/CD logic.

## Risk and coverage are separate

Security findings contribute to deterministic risk.

Scanner `ERROR` findings do not add risk points. They reduce coverage/confidence instead.

This avoids pretending that an inspection failure is either secure or insecure.

## CI/CD

`--fail-on` evaluates observed security severity.

`--require-full-coverage` evaluates whether the requested scanners completed without inspection errors.

Those are deliberately separate gates.

## Optional analyst layer

Blacklight can pass a completed JSON report to a user-selected external analyst program:

```bash
blacklight analyze --input report.json --command python --arg analyst.py
```

The analyst receives report JSON on stdin and returns explanation on stdout.

It cannot change the original findings or scan exit code.

## Distribution

Blacklight is packaged four ways:

1. Python source / editable development install
2. Python wheel + source distribution
3. Native standalone Windows, Linux, and macOS archives
4. Docker image through GHCR

The standalone archives include the frozen Blacklight executable and do not require Python on the destination machine.

## Adding future targets

The registry/runner/finding architecture is intentionally reusable.

A future server scanner can follow the same model:

```text
server connection/profile
        ↓
read-only server evidence
        ↓
server scanner
        ↓
Finding objects
        ↓
existing risk/report/gate pipeline
```

That means a later desktop `.exe` UI can collect a server address, credential reference, cloud profile, Dockerfile path, or Kubernetes directory and hand that target to the appropriate scanner without rebuilding the reporting system.
