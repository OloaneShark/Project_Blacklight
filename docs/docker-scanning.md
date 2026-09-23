# Dockerfile Security Scanning

Project Blacklight can statically inspect Dockerfiles without requiring a Docker daemon.

The first Docker security scanner focuses on deterministic, high-signal build and runtime configuration problems rather than image CVE databases.

## Run the scanner

Scan the current project directory:

```bash
blacklight scan docker --path .
```

Scan one Dockerfile directly:

```bash
blacklight scan docker --path ./Dockerfile
```

Generate JSON:

```bash
blacklight scan docker --path . --format json --output reports/docker-scan.json
```

Generate HTML:

```bash
blacklight scan docker --path . --format html --output reports/docker-report.html
```

Use the normal CI/CD gate:

```bash
blacklight scan docker --path . --fail-on high --require-full-coverage
```

## Dockerfile discovery

When `--path` is a directory, Blacklight recursively discovers common Dockerfile names:

```text
Dockerfile
Dockerfile.*
*.Dockerfile
```

Generated/dependency directories such as `.git`, `.venv`, `venv`, `node_modules`, `build`, `dist`, and `__pycache__` are skipped.

Point `--path` at an exact file when you want to scan only one Dockerfile.

## Current deterministic checks

### `docker.dockerfile.root_user`

Detects whether the final image stage:

- omits `USER`, which means Docker defaults to root
- explicitly selects `root` or UID `0`

Both are HIGH findings.

A literal non-root user is PASS. A variable-based user such as `USER $APP_USER` is INFO because static Dockerfile text cannot prove the resolved UID.

### `docker.dockerfile.base_image_latest`

Detects `FROM` instructions that:

- omit a tag
- use `:latest`

These are MEDIUM findings because the selected base can change without a Dockerfile edit.

A digest-pinned image or an explicit non-`latest` tag avoids this check. This rule does not claim that a mutable version tag is equivalent to digest pinning.

### `docker.dockerfile.embedded_secret`

Detects populated `ARG` or `ENV` keys with secret-like names such as passwords, tokens, API keys, access keys, private keys, and client secrets.

The finding is HIGH.

Blacklight never records the detected secret value in finding evidence. Evidence contains only:

- instruction type
- key name
- line number
- a marker confirming values were redacted

An `ARG SECRET_NAME` declaration with no default value is not treated as an embedded secret by this rule.

### `docker.dockerfile.remote_add`

Detects an HTTP(S) source passed to `ADD` without Docker's `--checksum` option.

The finding is MEDIUM.

Remote `ADD --checksum=...` is not flagged by this rule because the remote content has an explicit integrity expectation.

### `docker.dockerfile.remote_shell_pipe`

Detects `RUN` instructions that pipe a `curl` or `wget` download directly into `sh` or `bash`.

The finding is HIGH because remote content is executed without an explicit local integrity-verification step.

### `docker.dockerfile.world_writable_permissions`

Detects `chmod 777` in `RUN` instructions.

The finding is MEDIUM.

## What the first Docker scanner does not do

This first slice does **not** yet:

- inspect running containers
- connect to the Docker daemon/socket
- enumerate images
- scan installed OS/package CVEs
- inspect Docker Compose
- analyze Linux capabilities
- analyze seccomp/AppArmor profiles
- inspect Kubernetes manifests
- calculate whether a base-image version tag is immutable
- execute the Dockerfile

Those belong to later Docker/Kubernetes roadmap slices.

## Security model

Dockerfile detection follows the same Blacklight rule used for AWS:

```text
local configuration evidence
        ↓
deterministic checks
        ↓
normalized findings
        ↓
risk / coverage / CI gates
        ↓
console / JSON / HTML reports
```

No AI model decides whether a Dockerfile finding exists.

## CI example

```yaml
- name: Install Project Blacklight
  run: python -m pip install project-blacklight-security

- name: Scan Dockerfiles
  run: blacklight scan docker --path . --fail-on high --require-full-coverage
```

The same command can be run from the standalone executable once a release has been downloaded.
