## What changed?

Describe the change in a few sentences.

## Why?

What problem does this solve or what capability does it add?

## Testing

List the commands/tests you ran.

```text
pytest -q
ruff check blacklight_security tests
```

## Security impact

Explain any new security assumptions, severity changes, provider permissions, credential handling, or data-handling behavior. Write `None` if this change has no security impact.

## Checklist

- [ ] I kept security detection deterministic and evidence-based.
- [ ] I added or updated tests for behavior changes.
- [ ] `pytest -q` passes locally.
- [ ] `ruff check blacklight_security tests` passes locally.
- [ ] I did not commit credentials, tokens, `.env` secrets, or customer data.
- [ ] I updated documentation when behavior or usage changed.
- [ ] If this adds an AWS API call, I updated the least-privilege policy and permission docs.
