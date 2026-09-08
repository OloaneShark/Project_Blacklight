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
git clone https://github.com/OloaneShark/Project_Blacklight.git
cd Project_Blacklight
python -m venv .venv
```

Activate the virtual environment, then install the package in editable mode:

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check blacklight_security tests
```

## Simple contribution workflow

1. Update `main`.
2. Create a feature branch.
3. Make the change.
4. Run tests and Ruff.
5. Commit and push the feature branch.
6. Open a pull request into `main`.
7. Merge only after review and CI pass.

See [docs/git-workflow.md](docs/git-workflow.md) for the exact commands.

## Scanner rules

A scanner should:

1. Use provider/API evidence to decide whether a security condition exists.
2. Return normalized `Finding` objects.
3. Give each check a stable `check_id`.
4. Avoid modifying the target environment.
5. Treat access/permission failures as `ERROR`, not as proof that a resource is insecure.
6. Include remediation guidance when a finding is actionable.
7. Document any new AWS API permissions required by the scanner and update `examples/aws/blacklight-readonly-policy.json` in the same pull request.

AI-assisted analysis may be added later, but AI output must not replace deterministic security detection.

## Pull requests

Keep pull requests focused. Add or update tests for behavior changes, and explain any security assumptions that affect severity or false-positive risk. GitHub will provide a pull-request checklist automatically.
