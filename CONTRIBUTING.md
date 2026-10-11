# Contributing to Project Blacklight

Project Blacklight is intended to be a community-usable security tool, not a private portfolio script. Contributions are welcome.

## Good first contribution areas

- New deterministic security checks
- Additional provider/service coverage
- False-positive reductions
- Test and demo coverage
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
ruff check blacklight_security tests scripts
python scripts/verify_demo.py
```

The credential-free demo verifier uses the fixtures under `examples/demo/` and exercises the installed CLI, security gates, JSON reporting, and HTML reporting. Use `python scripts/verify_demo.py --online` only when you intentionally want to include the OSV-backed SBOM demo.

## Simple contribution workflow

1. Update `main`.
2. Create a feature branch.
3. Make the change.
4. Run tests, Ruff, and the credential-free demo verifier.
5. Commit and push the feature branch.
6. Open a pull request into `main`.
7. Merge only after review and CI pass.

See [docs/git-workflow.md](docs/git-workflow.md) for the exact commands.

## Scanner rules

A scanner should:

1. Use provider/API/runtime/configuration evidence to decide whether a security condition exists.
2. Return normalized `Finding` objects.
3. Give each check a stable `check_id`.
4. Avoid modifying the target environment.
5. Treat access/permission failures as `ERROR`, not as proof that a resource is insecure.
6. Include remediation guidance when a finding is actionable.
7. Document any new external data source or required provider permission in the same pull request.
8. Add false-positive boundary tests when a rule depends on resource identity, correlation, or uncertain environment state.

Any new AWS scanner or check that requires additional AWS API permissions must also update `examples/aws/blacklight-readonly-policy.json` and `docs/aws-permissions.md`.

AI-assisted analysis may explain completed reports, but AI output must not replace deterministic security detection.

For the exact built-in scanner contract, registration steps, check-ID conventions, error handling, permission updates, and test checklist, see [docs/scanner-authoring.md](docs/scanner-authoring.md).

## Pull requests

Keep pull requests focused. Add or update tests for behavior changes, explain security assumptions that affect severity or false-positive risk, and update demo fixtures when a change alters user-visible scan behavior. GitHub will provide a pull-request checklist automatically.
