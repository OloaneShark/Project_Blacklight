# Changelog

All notable changes to Project Blacklight will be documented here.

## [0.1.0-alpha.25] - 2026-09-24

### Changed

- Restored the original dark Blacklight Desktop design from the 0.1.0a23 line.
- Removed the bottom-left `LOCAL SECURITY ENGINE` footer from the sidebar for a cleaner layout.
- Kept the existing AWS, Docker, Kubernetes, findings, reports, background scanning, and desktop executable behavior unchanged.
- The light workspace experiment from 0.1.0a24 is no longer the active desktop design.

## [0.1.0-alpha.25] - 2026-09-24

### Changed

- Restored the Blacklight Desktop interface to the previous dark security-workspace design from `0.1.0a23`.
- Removed the experimental light/Unsloth-style shell introduced in `0.1.0a24`.
- Restored the original Dashboard, Targets, Scan, Findings, Reports, and Settings navigation.
- Restored the dark Blacklight theme, metric cards, target cards, scan form, findings workspace, and report-export presentation.
- Removed the temporary light-UI screenshot capture helper and associated CI screenshot step.

## [0.1.0-alpha.24] - 2026-09-24

### Changed

- Rebuilt Blacklight Desktop as a light-mode-only workspace with a white main canvas, slim light sidebar, subtle dividers, restrained mint accents, and much more whitespace.
- Replaced the card-heavy dashboard with a centered Home launcher built around the primary action: choosing a target and starting a security scan.
- Added a persistent top target selector modeled around modern local desktop-tool navigation.
- Reorganized sidebar navigation to Home, New scan, Targets, Findings, Reports, and More, with local-engine status and in-session recent scans.
- Reworked Targets into compact horizontal rows rather than large dashboard cards.
- Restyled scan forms, findings, metrics, report export, controls, tables, and status elements for the light desktop system.
- Added a direct Home scan path while retaining the advanced New scan form for regions, severity gates, and full-coverage settings.
- Desktop remains local-first and still uses the existing deterministic Blacklight engine, findings, risk, coverage, and report layers.

## [0.1.0-alpha.23] - 2026-09-24

### Added

- First graphical Project Blacklight Desktop application built with PySide6/Qt.
- Dark, sharp-edged local security workspace with Dashboard, Targets, Scan, Findings, Reports, and Settings pages.
- Desktop target cards for AWS, Docker, Kubernetes, and a visible disabled Server/SSH next-phase slot.
- Background scan execution so long-running AWS scans do not block the desktop UI thread.
- Desktop scan controller that reuses the existing `ScanRunner`, deterministic findings, risk engine, coverage engine, severity gate, and full-coverage gate.
- Findings workspace with risk/coverage metrics, severity/resource table, remediation details, and deterministic evidence.
- JSON and HTML report export from the most recent desktop scan without rerunning the scan.
- Windows x64 and Windows ARM64 desktop executable builds using PyInstaller windowed one-file packaging.
- Dedicated Windows Desktop CI that smoke-tests both the source UI and frozen executable.
- Versioned release integration for `Project-Blacklight-Desktop-Windows-x64.exe` and `Project-Blacklight-Desktop-Windows-ARM64.exe`.
- Desktop architecture and usage documentation.

### Changed

- Blacklight's release artifacts now include both the CLI-native executables and the new graphical Windows Desktop application.
- Desktop support is an optional dependency group so the core CLI package does not require Qt for normal command-line use.

## [0.1.0-alpha.22] - 2026-09-24

### Added

- Deterministic Kubernetes workload-manifest scanning through `blacklight scan kubernetes --path <path>` and the `k8s` alias.
- Static Kubernetes checks for privileged containers, explicit UID 0, explicit privilege escalation, host namespace sharing, hostPath volumes, ALL Linux capabilities, Unconfined seccomp, hostPort bindings, mutable/implicit image tags, and literal secret-like environment values.
- Kubernetes support for Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets, ReplicationControllers, Jobs, CronJobs, and Kubernetes List items.
- Secret-value redaction in Kubernetes environment findings.
- Kubernetes scanner/CLI test coverage and dedicated Kubernetes scanning documentation.
- Optional external analyst protocol through `blacklight analyze`, passing completed Blacklight JSON reports over stdin to an explicitly selected command with `shell=False` and a bounded timeout.
- Analyst integration tests and documentation.
- End-to-end architecture documentation describing AWS, Docker, Kubernetes, findings, risk, coverage, reporting, distribution, and future target expansion.
- Automatic public GitHub prereleases for validated alpha/beta/RC versions reaching `main`.
- Automated prerelease handoff paths for PyPI Trusted Publishing and GHCR through successful release-workflow completion.

### Changed

- The original Blacklight 0.1 core roadmap is now marked complete.
- README architecture and usage now include Kubernetes scanning and optional external analyst integrations.
- Release documentation distinguishes automatic public prereleases from human-reviewed stable releases.
- Standalone embedded usage documentation now lists AWS, Docker, and Kubernetes scan commands.

## [0.1.0-alpha.21] - 2026-09-23

### Added

- Deterministic local Dockerfile security scanner available through `blacklight scan docker --path <path>`.
- Recursive discovery for `Dockerfile`, `Dockerfile.*`, and `*.Dockerfile` project files while skipping common generated/dependency directories.
- HIGH checks for final-stage root runtime, populated secret-like `ARG`/`ENV` values, and curl/wget output piped directly into sh/bash.
- MEDIUM checks for implicit/`:latest` base images, unchecked remote HTTP(S) `ADD`, and `chmod 777`.
- Static-analysis boundaries for variable-based `USER` instructions and remote `ADD --checksum=...`.
- Docker scanning support for console, JSON, HTML, risk scoring, coverage reporting, severity gates, and full-coverage gates.
- Dockerfile scanner and CLI tests covering secure/insecure configurations, secret-value redaction, multi-stage builds, discovery, parse boundaries, and missing targets.
- One-command macOS/Linux and Windows standalone installers that select the newest published release, verify `SHA256SUMS`, and install the Blacklight executable.
- Stable standalone release asset names such as `Project-Blacklight-Windows-x64.zip` so install/download tooling does not hard-code a version.
- Standalone CI syntax validation for both installer scripts.
- Dedicated Dockerfile security-scanning documentation.

### Changed

- Project/package descriptions now cover both cloud and container security.
- Console and HTML scan context are provider-aware so Docker scans do not display irrelevant AWS account/identity fields.
- Standalone release documentation now describes stable platform asset names and one-command installation.
- Roadmap advances Docker security scanning from distribution-only support to deterministic Dockerfile analysis.

## [0.1.0-alpha.20] - 2026-09-23

### Added

- Production multi-stage Dockerfile for the Blacklight CLI.
- Non-root container runtime using UID/GID `65532:65532`.
- Focused `.dockerignore` so tests, legacy code, Git metadata, local environments, reports, and build artifacts are excluded from the container build context.
- Docker CI that builds the image and verifies the package version, non-root runtime, AWS CLI parser, and OCI version label.
- GitHub Container Registry release workflow that publishes multi-platform `linux/amd64` and `linux/arm64` images after a GitHub Release is manually published.
- Versioned GHCR image tags at `ghcr.io/oloaneshark/project-blacklight:<version>`, with `latest` reserved for non-prerelease releases.
- OCI source/version/revision/license metadata plus release-build provenance and SBOM attestations.
- Docker usage documentation covering AWS credentials, profile mounts, report persistence, CI/CD gates, local builds, GHCR publication, and digest pinning.

### Changed

- Docker distribution is now part of the versioned release pipeline rather than an unfinished roadmap item.
- The release publish event now drives PyPI and GHCR through separate workflows so either distribution channel can fail independently.
- Generated-artifact ignore rules now correctly ignore `reports/` and `build/` separately instead of the accidental `reports/build/` path.

## [0.1.0-alpha.19] - 2026-09-22

### Added

- Cross-platform PyInstaller build script for self-contained Blacklight command-line executables.
- Standalone archives for Windows, Linux, and macOS containing the frozen executable, license, and standalone usage notes.
- Frozen-binary version smoke test that must match `blacklight_security.__version__`.
- Dedicated standalone CI matrix for Ubuntu, Windows, and macOS.
- Versioned release integration that builds standalone archives on all three operating systems and attaches them to the draft GitHub Release.
- Release-wide SHA-256 checksums covering Python distributions and standalone archives.
- Standalone executable documentation including build commands, AWS credential behavior, artifact layout, and current unsigned-binary limitations.
- `standalone` optional dependency group with PyInstaller.

### Changed

- The versioned release workflow now separates validation, Python distribution builds, standalone builds, and final release preparation into dependent jobs.
- PyPI release downloads are restricted to the `project_blacklight_security-` filename prefix so standalone `.tar.gz` archives cannot be mistaken for Python source distributions.
- Roadmap no longer lists standalone executables as unfinished work.

## [0.1.0-alpha.18] - 2026-09-22

### Added

- Tag-driven GitHub Release preparation workflow for version tags matching `v<package-version>`.
- Release guards requiring the tagged commit to be contained in `main`, the tag to match `blacklight_security.__version__`, and the changelog to contain the matching release entry.
- Draft GitHub Releases with generated notes, wheel/source-distribution assets, prerelease marking for alpha/beta/RC versions, and `SHA256SUMS`.
- Safe rerun behavior that refreshes draft assets but refuses to overwrite an already published release.
- Dedicated versioned release documentation.

### Changed

- PyPI publishing now downloads and validates the exact wheel and source archive attached to the reviewed GitHub Release instead of rebuilding new distributions after publication.
- Versioned GitHub Release creation and PyPI publication are separated by a human review/publish step.
- Roadmap no longer lists versioned GitHub releases as unfinished work.

## [0.1.0-alpha.17] - 2026-09-21

### Added

- Release-package validation job in CI that builds both wheel and source distributions, runs `twine check`, installs the built wheel into an isolated virtual environment, and smoke-tests the `blacklight` command.
- Dedicated `.github/workflows/release.yml` workflow for PyPI Trusted Publishing through GitHub Actions OIDC.
- Release-tag guard requiring the GitHub release tag to match `blacklight_security.__version__`.
- Isolated PyPI publish job using the `pypi` GitHub environment and job-scoped `id-token: write`.
- `release` optional dependency group with PyPA `build` and `twine`.
- PyPI publishing guide covering Trusted Publisher setup, build validation, release flow, and immutable-version handling.
- Additional package metadata URLs for homepage, documentation, and changelog.

### Changed

- README links that need to render on PyPI now use absolute GitHub URLs.
- Python build artifacts are ignored by Git.
- Roadmap marks release automation as prepared while keeping the first PyPI publication dependent on one-time Trusted Publisher activation.

## [0.1.0-alpha.16] - 2026-09-21

### Added

- Contributor-facing scanner authoring and registration guide.
- Documented scanner contract, stable check-ID conventions, severity semantics, error/coverage behavior, AWS registration steps, permission updates, regional-scope guidance, correlation requirements, and test expectations.
- Scanner pull-request checklist covering deterministic evidence, least privilege, registry updates, documentation, Ruff, and pytest.

### Changed

- CONTRIBUTING now links directly to the detailed scanner-authoring guide.
- README contribution guidance now points scanner contributors to the current registration workflow.
- Roadmap no longer lists scanner-registration documentation as unfinished work.

## [0.1.0-alpha.15] - 2026-09-21

### Added

- Deterministic IAM role trust-policy analysis using `iam:GetRole`.
- HIGH finding for an unconditional wildcard trust principal paired with an STS assume-role action.
- Trust-policy evidence including matched statement indexes and assume-role actions.
- Deterministic risk correlation when the same IAM role has both broad wildcard permissions and broad wildcard trust.
- Read-only `iam:GetRole` permission and trust-policy documentation.
- Unit coverage for wildcard trust, conditioned trust, specific service principals, wildcard actions, malformed trust policies, and same-role correlation boundaries.

### Changed

- IAM role findings now cover both what permissions a role receives and who its trust policy broadly delegates role assumption to.
- Role-trust findings explicitly avoid claiming that a wildcard trust statement alone proves any caller can successfully assume the role.

## [0.1.0-alpha.14] - 2026-09-20

### Added

- Deterministic IAM group-policy analysis for inline and directly attached managed policies.
- Deterministic IAM role-policy analysis for inline and directly attached managed policies.
- HIGH findings for IAM groups or roles with unconditional `Allow` statements containing both `Action: "*"` and `Resource: "*"`.
- Identity-type evidence so reports distinguish user, group, and role policy findings.
- Read-only IAM permissions required to list groups, roles, and their attached policy documents.
- Unit coverage for wildcard group policies, wildcard role policies, conditioned/narrow policies, policy parse failures, and accounts with no IAM users.

### Changed

- IAM policy analysis now uses one shared deterministic path for users, groups, and roles.
- An AWS account with no IAM users no longer causes the IAM scanner to return before group and role analysis.
- Effective-permission caveats now explicitly include session policies in addition to permissions boundaries, SCPs, and explicit denies.

## [0.1.0-alpha.13] - 2026-09-19

### Added

- Deterministic direct IAM user-policy analysis for inline and attached managed policies.
- HIGH finding when a directly attached user policy contains an unconditional `Allow` statement with both `Action: "*"` and `Resource: "*"`.
- URL-decoding and JSON normalization for IAM policy documents returned by AWS APIs.
- Policy evidence that identifies matched policy names, policy type, ARN when available, and matched statement indexes.
- Read-only IAM permissions for listing and retrieving direct user policies and managed policy versions.
- Unit coverage for URL-encoded inline policies, attached managed policies, conditioned wildcard statements, narrow policies, and unparseable policy documents.

### Changed

- IAM scan coverage now reflects policy-document retrieval or parsing failures through normalized `ERROR` findings.
- Blacklight explicitly distinguishes broad policy grants from final effective permissions, which may still be constrained by permissions boundaries, SCPs, explicit denies, and other IAM evaluation layers.

## [0.1.0-alpha.12] - 2026-09-18

### Added

- Optional `--require-full-coverage` CI/CD gate that requires every selected scanner to complete without `ERROR` findings.
- Deterministic coverage-gate result with required status, actual coverage state, risk-confidence label, and affected scanners.
- Coverage-gate status in console, JSON, and standalone HTML reports.
- JSON scan schema version 6 when coverage-gate metadata is included.
- Unit coverage for full/partial coverage gate behavior, CLI exit codes, JSON serialization, HTML rendering, and combined security/coverage gate precedence.

### Changed

- Partial coverage remains reportable without failing by default, but returns exit code `2` when full coverage was explicitly required.
- Coverage-gate failure takes precedence over security-gate exit code `1` because the requested assessment completeness was not achieved.
- Reports are still rendered or written before the final gate exit code is returned.

## [0.1.0-alpha.11] - 2026-09-16

### Added

- Deterministic scanner-level coverage assessment with `FULL`, `PARTIAL`, `LIMITED`, and `UNKNOWN` states.
- Risk-confidence labels (`HIGH`, `REDUCED`, `LOW`, `UNKNOWN`) derived from observable scan coverage rather than probability estimates.
- Coverage metadata in console, JSON, and HTML reports, including affected scanners, completion percentage, and `ERROR` finding count.
- JSON scan schema version 5 with nested `scan.coverage` metadata.
- Per-scanner AWS `ClientError` isolation so one failed service can become a normalized `ERROR` finding while healthy scanners continue.
- Dedicated coverage/confidence documentation and tests for full, partial, limited, and unknown scan states.

### Changed

- Scan status is now `FAILED` when every selected scanner returns inspection errors, `PARTIAL` when only some scanners are affected, and `COMPLETE` when all selected scanners finish without `ERROR` findings.
- A fully failed scan returns exit code `2` after the report is rendered or written, preventing CI/CD from treating zero usable scanner coverage as a successful assessment.
- Security risk remains independent from coverage: `ERROR` findings still add zero risk points.

## [0.1.0-alpha.10] - 2026-09-16

### Added

- Correlation for public S3 bucket policy exposure combined with incomplete bucket-level Block Public Access on the same bucket.
- Correlation for root MFA being disabled while CloudTrail audit visibility has a high-severity gap.
- Correlation for regional internet-exposed EC2, RDS, or Lambda resources while GuardDuty is not enabled in the scanned region.
- Unit coverage for new correlations and false-positive boundaries.

### Changed

- A completely missing CloudTrail trail now counts as an audit-visibility gap for critical-finding correlations, not only an existing trail that stopped logging.
- Same-resource correlation grouping now keys on provider, service, and resource ID instead of resource ID alone.

## [0.1.0-alpha.9] - 2026-09-13

### Added

- Best-effort AWS environment identity context collected with STS before scanner execution.
- Scan metadata for AWS account ID, principal ARN, caller user ID, partition, selected profile, and resolved region.
- Environment identity context in console, JSON, and HTML reports.
- JSON scan schema version 4 with nested `scan.context` metadata.
- Unit coverage for resolved and unavailable identity context, reporting output, and AWS partition detection.

### Changed

- Identity lookup failures are recorded as unavailable context instead of preventing the security scanners from running.

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
- CloudTrail scanner for logging state and multi-region visibility.
- EC2 security-group scanner for unrestricted sensitive-port exposure.
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
