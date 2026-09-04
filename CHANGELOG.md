# Changelog

All notable changes to Project Blacklight will be documented here.

## [0.1.0-alpha.2] - 2026-09-03

### Added

- Deterministic IAM scanner for root MFA and access-key age/usage visibility.
- CloudTrail scanner for logging and multi-region visibility.
- EC2 security-group scanner for unrestricted sensitive-port exposure.
- RDS scanner for public accessibility and storage encryption.
- `blacklight scan aws` now runs all supported AWS scanners by default.
- Per-service selection with `--service s3|iam|cloudtrail|ec2|rds`.
- Unit tests for the migrated AWS scanner modules.

## [0.1.0-alpha.1] - 2026-09-03

### Added

- Project Blacklight package foundation.
- Installable `blacklight` command-line entry point.
- Normalized finding model and severity levels.
- Deterministic AWS S3 checks for public access blocking, default encryption, versioning, access logging, and public bucket policy status.
- Console and JSON report output.
- Initial unit test coverage.
- GitHub Actions test workflow for Python 3.11 and 3.12.
- MIT license, contribution guidance, and security policy.

### Migration note

The original CloudGuard Flask dashboard files remain in the repository during the migration. The CLI package is the new core direction.
