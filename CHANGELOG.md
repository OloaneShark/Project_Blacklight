# Changelog

All notable changes to Project Blacklight will be documented here.

## [0.1.0-alpha.8] - 2026-09-12

### Added

- Self-contained HTML security reports with `--format html --output <path>`.
- Scan context, risk score, severity summary, deterministic correlations, findings, remediation, evidence, and optional CI/CD gate status in HTML output.
- HTML escaping for finding, resource, remediation, and evidence values before rendering.
- Print-friendly standalone styling with no external assets or web server requirement.
- Unit coverage for HTML content, escaping, and CLI file-output behavior.

### Changed

- CLI output formats now include `console`, `json`, and `html`.
- HTML output requires an explicit `--output` path so report markup is not dumped into the terminal accidentally.

## [0.1.0-alpha.7] - 2026-09-11

### Added

- Deterministic CI/CD security gate with `--fail-on low|medium|high|critical`.
- Exit code `1` when a requested security severity threshold is reached or exceeded.
- Policy results in console and JSON reports, including threshold, pass/fail status, trigger count, and highest security severity.
- JSON schema version 3 for policy-aware scan output.
- Unit coverage for severity-threshold evaluation and CLI exit-code behavior.

### Changed

- The normal scan path still exits successfully when no `--fail-on` threshold is requested, preserving report-only usage.

## [0.1.0-alpha.6] - 2026-09-10

### Added

- Unified scan runner that coordinates registered scanners and returns one normalized scan result.
- Scan metadata for provider, region, scanners executed, status, finding count, timestamps, and duration.
- Console and JSON reporting support for scan execution metadata.
- Unit coverage for complete and partial scan-runner states.

### Changed

- `blacklight --version` now reads from the same version source used by packaging.
- The original CloudGuard Flask application was moved under `legacy/cloudguard_flask/` so the repository root reflects the current CLI architecture.

## [0.1.0-alpha.5] - 2026-09-08

### Added

- Amazon GuardDuty scanner for regional detector status.
- HIGH finding when no GuardDuty detector is configured or a detector is disabled.
- `blacklight scan aws --service guardduty` support.
- Unit coverage for enabled and missing GuardDuty detectors.
- Least-privilege GuardDuty read permissions and documentation.

## [0.1.0-alpha.4] - 2026-09-08

### Added

- AWS Lambda scanner.
- Detection for Lambda Function URLs configured with unauthenticated `NONE` access.
- Lambda scanner registration so `blacklight scan aws --service lambda` is supported.
- Unit coverage for unauthenticated Lambda Function URL exposure.
- Least-privilege Lambda read permissions and documentation.

## [0.1.0-alpha.3] - 2026-09-04

### Added

- Shared scanner registry used by the CLI instead of hard-coded scanner imports.
- Deterministic risk scoring from normalized finding severities.
- Explainable correlation rules for selected combinations of AWS findings.
- Risk assessment included in console and JSON reports.
- Unit tests for registry behavior and risk correlations.

## [0.1.0-alpha.2] - 2026-09-03

### Added

- Deterministic IAM scanner for root MFA and active access-key age/usage visibility.
- CloudTrail scanner for logging state and multi-region configuration.
- EC2 security-group scanner for unrestricted all-port ingress and sensitive public ports.
- RDS scanner for public accessibility and storage encryption.
- `blacklight scan aws` now runs all supported AWS scanners by default.
- Per-service selection with `--service s3|iam|cloudtrail|ec2|rds`.
- Unit tests for the migrated AWS scanner modules.

## [0.1.0-alpha.1] - 2026-09-03

### Added

- Project Blacklight package foundation.
- Installable `blacklight` command-line entry point.
- Normalized finding model and stable security check IDs.
- first migrated deterministic AWS S3 scanner.
- console and JSON reporting.
- unit test coverage for the S3 scanner.
- GitHub Actions CI for Python 3.11 and 3.12.
- MIT `LICENSE`.
- `CONTRIBUTING.md`.
- `SECURITY.md`.
- `CHANGELOG.md`.
