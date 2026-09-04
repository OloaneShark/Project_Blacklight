# Security Policy

Project Blacklight scans infrastructure and therefore must be conservative with credentials and security data.

## Credentials

Blacklight uses the standard AWS credential provider chain through `boto3`. Do not commit AWS keys, tokens, passwords, `.env` secrets, or captured customer data to this repository.

Use a dedicated read-only or least-privilege identity for scanning whenever possible.

## Scanner behavior

Blacklight's scanners should be read-only by default. A scanner must not make remediation changes unless a future feature explicitly introduces an opt-in remediation mode with clear confirmation and documentation.

## Reporting vulnerabilities in Blacklight

Do not publish exploit details for a vulnerability in Project Blacklight before the maintainer has had an opportunity to review it. Use GitHub private vulnerability reporting if it is enabled for the repository; otherwise contact the maintainer privately through the GitHub account associated with this repository.
