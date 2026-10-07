# Docker Security Scanning

Project Blacklight supports both static Dockerfile analysis and explicit read-only inspection of the local Docker daemon.

Static Dockerfile scanning remains the default so source scans do not unexpectedly require a running daemon.

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

Inspect currently running containers through the local Docker CLI:

```bash
blacklight scan docker --service daemon
```

Run both static Dockerfile and live-daemon scanners:

```bash
blacklight scan docker --service all --path .
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

## Live daemon checks

The `daemon` scanner uses the local Docker CLI with argument-list subprocess calls, bounded timeouts, and `shell=False`. It does not create, start, stop, restart, exec into, or modify containers.

For each currently running container it checks:

- privileged mode — CRITICAL
- host network/PID/IPC/UTS/cgroup namespace sharing — HIGH
- Docker daemon socket mounts — CRITICAL when read-write, HIGH when observed read-only
- `CapAdd: ALL` — HIGH
- selected individually added high-risk Linux capabilities (for example `SYS_ADMIN`, `SYS_MODULE`, raw-I/O/DAC capabilities) — HIGH
- selected elevated capabilities such as `SYS_PTRACE`, `NET_ADMIN`, `NET_RAW`, and `MKNOD` — MEDIUM
- explicit unconfined seccomp/AppArmor options — HIGH
- writable bind mounts from selected sensitive host paths such as `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/var/lib/docker`, and `/var/lib/kubelet` — HIGH
- read-only sensitive host-path bind mounts — MEDIUM
- raw/sensitive host device passthrough or broad device-cgroup rules — HIGH
- other explicit host device passthrough — MEDIUM
- empty/root/UID-0 configured runtime user — HIGH
- ports published on all host interfaces — LOW exposure inventory

The configured-user check describes Docker's container configuration. An application can still voluntarily drop privileges after startup, so Blacklight does not claim every process remains root solely from `Config.User`.

Published ports bound to `0.0.0.0` or `::` are LOW because this proves host-interface publication, not internet reachability or vulnerability.

Sensitive bind-mount detection is limited to explicit Docker bind mounts from selected host paths. Docker volumes are not treated as host-path exposure by this check, and Docker socket mounts remain a separate higher-signal finding.

The risk engine adds a deterministic correlation when the same container is configured to run as root and also has a writable sensitive host-path bind mount. Read-only sensitive mounts do not trigger that correlation.

If the Docker CLI or daemon is unavailable, live-daemon inspection reports INFO availability context rather than breaking the independent static Dockerfile scanner.

## Current Docker boundaries

Blacklight still does **not** yet:

- scan installed container-image OS/package CVEs
- inspect Docker Compose effective configuration
- execute commands inside containers
- mutate Docker daemon/container state
- calculate whether a base-image version tag is immutable
- infer internet reachability from a published host port

Those belong to later Docker/container roadmap slices.

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

No AI model decides whether a Dockerfile or live-daemon finding exists.

## CI example

```yaml
- name: Install Project Blacklight
  run: python -m pip install project-blacklight-security

- name: Scan Dockerfiles
  run: blacklight scan docker --path . --fail-on high --require-full-coverage
```

