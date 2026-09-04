# Security Policy

Project Blacklight scans infrastructure and therefore must be conservative with credentials and security data.

## Credentials

Blacklight uses the standard AWS credential provider chain through `boto3`. Do not commit AWS keys, tokens, passwords, `.env` secrets, or captured customer data to this repository.

For routine scanning, use a dedicated read-only or least-privilege identity whenever possible. The repository includes an example policy at `examples/aws/blacklight-readonly-policy.json`, with a permission breakdown in `docs/aws-permissions.md`.

Avoid running Blacklight with `AdministratorAccess` when a narrower scanning identity can be used.

## Scanner behavior

Blacklight's scanners should be read-only by default. A scanner must not make remediation changes unless a future feature explicitly introduces an opt-in remediation mode with clear confirmation and documentation.

Any new AWS scanner or check that requires additional AWS API permissions must update the example read-only policy and permission documentation in the same change.

## Reporting vulnerabilities in Blacklight

Do not publish exploit details for a vulnerability in Project Blacklight before the maintainer has had an opportunity to review it. Use GitHub private vulnerability reporting if it is enabled for the repository; otherwise contact the maintainer privately through the GitHub account associated with this repository.
