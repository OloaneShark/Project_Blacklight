# Security Policy

Project Blacklight scans infrastructure and therefore must be conservative with credentials and security data.

## Credentials

Blacklight uses the standard AWS credential provider chain through `boto3`. Do not commit AWS keys, tokens, passwords, `.env` secrets, private-key contents, kubeconfig credentials, or captured customer data to this repository.

For routine scanning, use a dedicated read-only or least-privilege identity whenever possible. The repository includes an example AWS policy at `examples/aws/blacklight-readonly-policy.json`, with credential setup in `docs/aws-credentials.md` and a permission breakdown in `docs/aws-permissions.md`.

Avoid running Blacklight with `AdministratorAccess` or equivalent broad credentials when a narrower scanning identity can be used.

Live Kubernetes scanning uses the locally selected kubectl context. Linux server scanning uses the local OpenSSH client and key/agent configuration. Docker daemon scanning uses the local Docker CLI. Blacklight should never print private-key contents, AWS secret keys, kubeconfig tokens, or password hashes into findings.

## External vulnerability data

The opt-in Docker SBOM scanner queries OSV.dev.

Blacklight sends package identity data from the selected SBOM—Package URLs and package versions—to `api.osv.dev`. It does **not** intentionally upload source files, Dockerfiles, image layers, AWS credentials, kubeconfig credentials, SSH keys, environment-variable values, or secret values to OSV.

Users scanning confidential software inventories should evaluate whether sending package coordinates to an external vulnerability service is acceptable for their environment before using the SBOM scanner.

## Scanner behavior

Blacklight scanners are read-only by design. A scanner must not make remediation changes unless a future feature explicitly introduces an opt-in remediation mode with clear confirmation and documentation.

Permission/API/transport failures must be represented as coverage limitations or `ERROR` findings rather than being interpreted as secure state.

Any new AWS scanner or check that requires additional AWS API permissions must update the example read-only policy and permission documentation in the same change.

## Demo fixtures

Files under `examples/demo/` intentionally contain insecure configuration patterns and fake placeholder secret-like values. They are test/demo data only and must never contain real credentials.

## Reporting vulnerabilities in Blacklight

Do not publish exploit details for a vulnerability in Project Blacklight before the maintainer has had an opportunity to review it. Use GitHub private vulnerability reporting if it is enabled for the repository; otherwise contact the maintainer privately through the GitHub account associated with this repository.
