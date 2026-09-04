# Contributing to Project Blacklight

Project Blacklight is intended to be a community-usable security tool, not a private portfolio script. Contributions are welcome.

## Good first contribution areas

- New deterministic security checks
- Additional AWS service scanners
- False-positive reductions
- Test coverage
- Report formats
- Documentation and examples

## Development setup

```bash
git clone https://github.com/OloaneShark/cloudguard.git
cd cloudguard
python -m venv .venv
```

Activate the virtual environment, then install the package in editable mode:

```bash
python -m pip install -e ".[dev]"
pytest -q
```

## Scanner rules

A scanner should:

1. Use provider/API evidence to decide whether a security condition exists.
2. Return normalized `Finding` objects.
3. Give each check a stable `check_id`.
4. Avoid modifying the target environment.
5. Treat access/permission failures as `ERROR`, not as proof that a resource is insecure.
6. Include remediation guidance when a finding is actionable.

AI-assisted analysis may be added later, but AI output must not replace deterministic security detection.

## Pull requests

Keep pull requests focused. Add or update tests for behavior changes, and explain any security assumptions that affect severity or false-positive risk.
