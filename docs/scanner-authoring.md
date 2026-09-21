# Writing and Registering a Blacklight Scanner

Project Blacklight scanners are deterministic security checks. A scanner gathers provider evidence, converts that evidence into normalized `Finding` objects, and never relies on AI to decide whether a security condition exists.

This guide documents the current built-in scanner workflow. Registration is centralized today; adding a built-in scanner requires updating the AWS package exports and `blacklight_security/registry.py`.

## Scanner contract

A built-in scanner class should:

- accept a provider session in its constructor
- expose `scan() -> list[Finding]`
- use provider/API evidence for every security decision
- return stable check IDs
- avoid modifying the target environment
- return `ERROR` when Blacklight cannot inspect something instead of treating missing evidence as insecure
- include remediation text for actionable findings
- include compact evidence that explains why the finding exists

A minimal AWS scanner looks like:

```python
from typing import Any

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity


class ExampleScanner:
    def __init__(self, session: Any):
        self.client = session.client("example")

    def scan(self) -> list[Finding]:
        try:
            response = self.client.describe_things()
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "Unknown")
            return [
                Finding(
                    check_id="aws.example.describe_things",
                    provider="aws",
                    service="example",
                    resource_type="aws_example",
                    resource_id="aws-account",
                    severity=Severity.ERROR,
                    title="Blacklight could not inspect Example",
                    description=f"AWS returned {code}.",
                    remediation="Verify the scanning identity has the required read permission.",
                    evidence={"aws_error_code": code},
                )
            ]

        findings: list[Finding] = []
        for item in response.get("Things", []):
            resource_id = item["ThingId"]
            secure = bool(item.get("Secure"))

            findings.append(
                Finding(
                    check_id="aws.example.secure_configuration",
                    provider="aws",
                    service="example",
                    resource_type="aws_example",
                    resource_id=resource_id,
                    severity=Severity.PASS if secure else Severity.HIGH,
                    title=(
                        "Example resource is securely configured"
                        if secure
                        else "Example resource is not securely configured"
                    ),
                    description="Describe the deterministic evidence Blacklight observed.",
                    remediation=(
                        ""
                        if secure
                        else "Describe the smallest concrete remediation for this condition."
                    ),
                    evidence={"secure": secure},
                )
            )

        return findings
```

## Check IDs

Use stable IDs in this form:

```text
<provider>.<service>.<check>
```

Examples:

```text
aws.rds.public_access
aws.guardduty.detector_enabled
aws.iam.role_trust_wildcard
```

Do not encode resource names, timestamps, regions, or other run-specific values into the check ID. Those belong in `resource_id` or `evidence`.

Changing a check ID can break downstream automation, stored reports, correlation rules, and tests, so treat IDs as part of Blacklight's public data model.

## Severity rules

Use severity to describe confirmed security evidence, not scanner confidence.

- `CRITICAL`: direct, severe exposure or compromise-enabling configuration
- `HIGH`: serious security weakness that should be prioritized
- `MEDIUM`: meaningful weakness or credential/configuration hygiene problem
- `LOW`: limited-impact weakness
- `PASS`: the explicit check passed
- `INFO`: useful context that is not a security failure
- `ERROR`: Blacklight could not complete the check

`ERROR` findings add no risk points. They feed Blacklight's coverage/confidence system instead.

When severity is debatable, document the assumption in the pull request and add tests around the intended boundary.

## Error handling and coverage

Prefer localized error handling when a scanner can still preserve useful evidence.

For example, if one bucket cannot be inspected but the remaining buckets can, return an `ERROR` for that bucket and continue scanning the others.

The scan runner also catches an uncaught AWS `ClientError` at the scanner boundary and converts it into a scanner-execution `ERROR`. That is a safety net, not a replacement for precise scanner-level handling.

Do not turn `AccessDenied`, missing credentials, timeouts, or malformed provider responses into `PASS` or security findings.

## AWS registration steps

For a new AWS scanner named `ExampleScanner`:

1. Add the scanner module, for example:
   `blacklight_security/scanners/aws/example.py`
2. Export the class from:
   `blacklight_security/scanners/aws/__init__.py`
3. Import it in `load_builtin_scanners()` inside:
   `blacklight_security/registry.py`
4. Add its CLI service name to the built-in registry mapping:
   ```python
   "example": ExampleScanner,
   ```
5. Update `tests/test_registry.py` so the expected built-in scanner list includes the new service.
6. Add focused scanner tests for insecure, secure, and API-error paths.
7. Update `examples/aws/blacklight-readonly-policy.json` with every new AWS read action.
8. Update `docs/aws-permissions.md` with the same permissions and what Blacklight uses them for.
9. Update the README supported-service list and the changelog.
10. Run the full validation commands before opening the pull request.

Current built-in registration is intentionally explicit. Blacklight does not yet auto-discover third-party scanner plugins.

## Findings and evidence

Keep evidence useful but minimal. Good evidence usually includes the provider values that caused the deterministic decision:

```python
evidence={
    "publicly_accessible": True,
    "storage_encrypted": False,
}
```

Avoid secrets, access keys, session tokens, passwords, complete credentials, or unnecessarily large provider responses.

For credentials, Blacklight should expose only safe metadata such as an access-key suffix when needed.

## Regional behavior

Be explicit about whether a scanner is:

- account-global
- regional
- effectively global but discovered through a regional API
- dependent on the configured/default region

Do not describe a single-region scan as account-wide if the provider service is regional.

If a new scanner changes Blacklight's regional assumptions, document that behavior in the README or a dedicated provider document.

## Correlation rules

Only add a risk correlation when the combined findings represent a meaningfully different security situation.

A correlation should:

- be deterministic
- have a stable rule ID
- explain why the combination is more dangerous
- avoid correlating unrelated resources
- include tests for both the positive case and false-positive boundaries

Same-resource correlations currently group by provider, service, and resource ID.

## Testing

At minimum, test:

- the insecure condition
- the secure/PASS condition
- provider/API failure behavior
- important false-positive boundaries
- registry inclusion for a new scanner
- any new correlation rule

Run:

```bash
ruff check blacklight_security tests
pytest -q
```

CI runs the same validation on Python 3.11 and 3.12.

## Pull-request checklist for a scanner

Before opening the PR, verify:

- [ ] deterministic provider evidence drives the finding
- [ ] stable check IDs are used
- [ ] no target-environment mutation is performed
- [ ] errors become `ERROR`, not false PASS/fail results
- [ ] tests cover insecure, secure, and failure paths
- [ ] scanner is exported and registered
- [ ] registry tests are updated
- [ ] new provider permissions are documented
- [ ] least-privilege example policy is updated
- [ ] README/changelog are updated
- [ ] Ruff passes
- [ ] pytest passes
