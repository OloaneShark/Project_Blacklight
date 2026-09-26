# Server / SSH scanning

Project Blacklight can perform a small read-only security baseline against a remote Linux server over SSH.

```bash
blacklight scan server --host server.example.com --user blacklight-audit
```

Use a non-default SSH port:

```bash
blacklight scan server --host server.example.com --user blacklight-audit --port 2222
```

Use a specific private key:

```bash
blacklight scan server --host server.example.com --user blacklight-audit --identity-file ~/.ssh/blacklight_audit
```

## Authentication model

Blacklight delegates transport and authentication to the local OpenSSH `ssh` client.

It runs SSH with `BatchMode=yes`, so the scanner will not stop and ask for a password or interactive credential. Use one of the normal OpenSSH authentication mechanisms already configured on the machine running Blacklight:

- ssh-agent
- a key selected through `~/.ssh/config`
- `--identity-file`
- another non-interactive OpenSSH configuration

Blacklight does not disable host-key verification. A new host should be verified and trusted through normal OpenSSH workflow before an automated Blacklight scan.

## First baseline checks

The first server scanner is intentionally small. It currently inspects:

- successful SSH connectivity and Linux platform metadata
- explicit `PermitRootLogin yes`
- explicit `PasswordAuthentication yes`
- explicit `PermitEmptyPasswords yes`
- group/world write permissions on `/etc/ssh/sshd_config`
- additional accounts with UID 0
- world-writable `/var/run/docker.sock`, when the socket exists

The remote commands are fixed by Blacklight and are intended only to read configuration or metadata. The scanner does not modify packages, users, SSH configuration, firewall rules, services, or files.

## Important SSH configuration boundary

Blacklight reads `/etc/ssh/sshd_config` and readable files matching `/etc/ssh/sshd_config.d/*.conf`.

An explicit insecure enabling value is enough for Blacklight to report a security finding. The absence of that value is reported as `INFO`, not `PASS`, because the final effective sshd configuration can depend on defaults, include ordering, `Match` blocks, distribution-specific behavior, or configuration files the audit account cannot read.

This first scanner deliberately does not run privileged `sshd -T` commands or claim to reconstruct every possible effective SSH configuration.

## Permissions

The audit account should have ordinary read access to the information Blacklight inspects. Root or passwordless sudo is not required by the scanner design.

If the account cannot read a piece of configuration, Blacklight should preserve that limitation rather than silently claiming the configuration is safe.

## Current scope

This phase supports Linux only. It is a configuration baseline, not a network vulnerability scanner, exploit framework, patch-management system, or replacement for authenticated vulnerability-management platforms.

Future server checks can be added incrementally while keeping the same deterministic finding model, coverage reporting, severity gates, JSON/HTML reports, and read-only target philosophy.
