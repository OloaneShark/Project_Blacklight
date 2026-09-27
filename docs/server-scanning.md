# Server / SSH scanning

Project Blacklight can perform read-only security checks against a remote Linux server over SSH. Server scanning is split into registered scanners so baseline configuration and host-network visibility can report coverage independently.

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

## Scanner selection

Run every current server scanner:

```bash
blacklight scan server --host server.example.com --user blacklight-audit
```

Run only the original configuration baseline:

```bash
blacklight scan server --host server.example.com --user blacklight-audit --service baseline
```

Run only host-network visibility:

```bash
blacklight scan server --host server.example.com --user blacklight-audit --service network
```

Run only host-hardening checks:

```bash
blacklight scan server --host server.example.com --user blacklight-audit --service hardening
```

## Baseline checks

The `baseline` scanner currently inspects:

- successful SSH connectivity and Linux platform metadata
- explicit `PermitRootLogin yes`
- explicit `PasswordAuthentication yes`
- explicit `PermitEmptyPasswords yes`
- group/world write permissions on `/etc/ssh/sshd_config`
- additional accounts with UID 0
- world-writable `/var/run/docker.sock`, when the socket exists

The remote commands are fixed by Blacklight and are intended only to read configuration or metadata. The scanner does not modify packages, users, SSH configuration, firewall rules, services, or files.

## Network visibility

The `network` scanner currently inspects:

- TCP/UDP listening sockets using `ss`, with `netstat` as a fallback
- whether listeners are loopback-only, bound to all interfaces, or bound to a specific non-loopback address
- UFW state when `ufw` is available
- firewalld state when `firewall-cmd` is available
- nftables INPUT/FORWARD hook visibility when `nft` is readable
- iptables INPUT/FORWARD filtering when `iptables` is readable

Listening sockets are exposure inventory and are reported as `INFO` rather than automatically becoming vulnerabilities. A service bound beyond loopback may be intentional, and Blacklight does not infer public-internet reachability or application identity from an address and port alone.

The firewall check reports `PASS` only when a supported firewall manager reports active state or readable nftables/iptables evidence shows INPUT/FORWARD filtering. It reports `MEDIUM` when the supported backends that can be inspected show inactive state or no observed input filtering. If installed tooling cannot be read, the check becomes `ERROR` so scan coverage reflects the uncertainty.

External controls such as cloud security groups, hardware/network firewalls, service meshes, or unsupported host firewall implementations are outside this check.

## Host hardening

The `hardening` scanner currently inspects:

- ownership and write permissions for `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/sudoers`, and observed `/etc/sudoers.d/*` entries
- the connected SSH account's home, `.ssh`, and `authorized_keys` ownership/write permissions
- supported automatic-update posture for APT/unattended-upgrades and DNF automatic updates using existing local configuration and timer state

The hardening scanner is read-only. It does not run package refresh/update commands, invoke `sudo`, change permissions, or enable timers. If Blacklight cannot prove that supported automatic security updates are enabled or explicitly disabled, it reports `INFO` rather than guessing. Another enterprise patch-management system may own that responsibility.

## Important SSH configuration boundary

Blacklight reads `/etc/ssh/sshd_config` and readable files matching `/etc/ssh/sshd_config.d/*.conf`.

An explicit insecure enabling value is enough for Blacklight to report a security finding. The absence of that value is reported as `INFO`, not `PASS`, because the final effective sshd configuration can depend on defaults, include ordering, `Match` blocks, distribution-specific behavior, or configuration files the audit account cannot read.

This first scanner deliberately does not run privileged `sshd -T` commands or claim to reconstruct every possible effective SSH configuration.

## Permissions

The audit account should have ordinary read access to the information Blacklight inspects. The baseline scanner does not require root or passwordless sudo. Some firewall tools restrict ruleset/status visibility to privileged users; Blacklight does not elevate with `sudo`. If the audit account cannot inspect an installed firewall backend, the network scanner records an `ERROR` coverage gap rather than silently claiming the host is filtered or unfiltered.

If the account cannot read a piece of configuration, Blacklight preserves that limitation rather than silently claiming the configuration is safe.

## Current scope

This phase supports Linux only. It provides configuration and host-network visibility, not a remote exploit scanner, service fingerprinting engine, patch-management system, or replacement for authenticated vulnerability-management platforms.

Future server checks can be added incrementally while keeping the same deterministic finding model, coverage reporting, severity gates, JSON/HTML reports, and read-only target philosophy.
