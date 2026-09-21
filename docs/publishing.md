# Publishing Project Blacklight to PyPI

Project Blacklight uses PyPI Trusted Publishing through GitHub Actions. The repository does not require a long-lived PyPI API token.

The package distribution name is:

```text
project-blacklight-security
```

The installed command remains:

```text
blacklight
```

## One-time account setup

Before the first PyPI release, configure both sides of the trust relationship.

### 1. Create the GitHub environment

In the GitHub repository settings, create an environment named:

```text
pypi
```

For stronger release control, configure required reviewers on that environment.

### 2. Configure the PyPI Trusted Publisher

If the PyPI project does not exist yet, create a pending Trusted Publisher for the package name `project-blacklight-security`.

Use these GitHub values:

```text
Owner: OloaneShark
Repository: Project_Blacklight
Workflow: release.yml
Environment: pypi
```

If the PyPI project already exists, add the same GitHub Actions Trusted Publisher from that project's Publishing settings.

A pending publisher does not reserve the package name. The name becomes established only when the first matching publish succeeds.

## Release prerequisites

Before publishing:

1. Merge all intended release changes into `main`.
2. Ensure CI is green.
3. Ensure `blacklight_security.__version__` is the exact version being released.
4. Ensure the changelog has a matching version entry.
5. Do not reuse a version that has already been uploaded to PyPI.

The release workflow rejects a GitHub release whose tag does not match the package version.

For example, package version:

```python
__version__ = "0.1.0a17"
```

requires release tag:

```text
v0.1.0a17
```

## Local package validation

Install release tooling:

```bash
python -m pip install -e ".[release]"
```

Build both distributions:

```bash
python -m build
```

Validate metadata and README rendering:

```bash
python -m twine check dist/*
```

The normal CI workflow performs these package checks automatically and smoke-tests the built wheel.

## Publishing flow

The dedicated workflow is:

```text
.github/workflows/release.yml
```

It runs when a GitHub Release is published.

The workflow:

1. checks out the exact release ref
2. verifies the release tag matches `blacklight_security.__version__`
3. builds the wheel and source distribution
4. runs `twine check`
5. uploads the distributions as a workflow artifact
6. downloads that artifact in the isolated publish job
7. requests a short-lived PyPI credential through GitHub OIDC
8. publishes through `pypa/gh-action-pypi-publish`

Only the publish job receives `id-token: write`.

## After the first successful publish

Users can install Blacklight with:

```bash
python -m pip install project-blacklight-security
```

and run:

```bash
blacklight --version
```

## Failed publish rules

Do not simply retry after changing package contents while keeping the same version. PyPI distributions are immutable once uploaded.

If a release artifact is wrong:

1. fix the repository
2. bump the package version
3. update the changelog
4. create a new GitHub release/tag
5. publish the new version
