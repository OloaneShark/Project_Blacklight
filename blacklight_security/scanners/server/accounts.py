from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.server.linux import (
    CommandResult,
    SSHCommandRunner,
    SSHExecutionError,
    ServerScanTarget,
)


_ACCOUNT_PROBE_COMMAND = "printf 'BLACKLIGHT_OK\\n'; uname -s; hostname"
_ACCOUNT_INVENTORY_COMMAND = (
    "uid_min=$(awk '$1 == \"UID_MIN\" {print $2; exit}' /etc/login.defs 2>/dev/null); "
    "if [ -n \"$uid_min\" ]; then uid_source=login.defs; "
    "else uid_min=1000; uid_source=fallback; fi; "
    "printf 'BLACKLIGHT_UID_MIN=%s\\nBLACKLIGHT_UID_MIN_SOURCE=%s\\n' "
    "\"$uid_min\" \"$uid_source\"; "
    "if [ -r /etc/shells ]; then "
    "awk 'NF && $1 !~ /^#/ {print \"BLACKLIGHT_SHELL=\" $1}' /etc/shells; "
    "fi; "
    "printf 'BLACKLIGHT_PASSWD_BEGIN\\n'; "
    "if command -v getent >/dev/null 2>&1; then getent passwd; "
    "else cat /etc/passwd 2>/dev/null; fi"
)
_PRIVILEGED_GROUPS_COMMAND = (
    "if command -v getent >/dev/null 2>&1; then "
    "for g in sudo wheel admin docker lxd; do "
    "line=$(getent group \"$g\" 2>/dev/null || true); "
    "[ -n \"$line\" ] && printf 'BLACKLIGHT_GROUP=%s\\n' \"$line\"; "
    "done; "
    "else "
    "awk -F: '$1 ~ /^(sudo|wheel|admin|docker|lxd)$/ "
    "{print \"BLACKLIGHT_GROUP=\" $0}' /etc/group 2>/dev/null; "
    "fi"
)
_SUDOERS_COMMAND = (
    "seen=0; "
    "for f in /etc/sudoers /etc/sudoers.d/*; do "
    '[ -e "$f" ] || continue; '
    "seen=1; "
    "if [ -r \"$f\" ]; then "
    "printf 'BLACKLIGHT_SUDO_READABLE=%s\\n' \"$f\"; "
    "awk 'BEGIN{IGNORECASE=1} "
    "/^[[:space:]]*#/ {next} "
    "/NOPASSWD[[:space:]]*:/ "
    "{print \"BLACKLIGHT_SUDO_RULE=\" FILENAME \"|\" $0}' \"$f\"; "
    "else printf 'BLACKLIGHT_SUDO_UNREADABLE=%s\\n' \"$f\"; fi; "
    "done; "
    "[ \"$seen\" -eq 0 ] && printf 'BLACKLIGHT_SUDO_NONE=1\\n'"
)

_BROAD_NOPASSWD_RE = re.compile(
    r"^(?P<subject>%?[A-Za-z0-9_.-]+)\s+ALL\s*=\s*"
    r"(?:\(\s*ALL(?:\s*:\s*ALL)?\s*\)\s*)?"
    r"NOPASSWD\s*:\s*ALL\s*$",
    re.IGNORECASE,
)

_NON_LOGIN_SHELLS = {
    "",
    "/bin/false",
    "/usr/bin/false",
    "/sbin/nologin",
    "/usr/sbin/nologin",
}


@dataclass(frozen=True, slots=True)
class AccountRecord:
    username: str
    uid: int
    gid: int
    home: str
    shell: str

    def to_dict(self) -> dict[str, object]:
        return {
            "username": self.username,
            "uid": self.uid,
            "gid": self.gid,
            "home": self.home,
            "shell": self.shell,
        }


@dataclass(frozen=True, slots=True)
class GroupRecord:
    name: str
    gid: int
    members: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "gid": self.gid,
            "members": list(self.members),
        }


class ServerAccountsScanner:
    """Read-only account and local-privilege checks for a remote Linux server."""

    def __init__(self, target: ServerScanTarget):
        self.target = target
        self.executor = target.executor or SSHCommandRunner(target)

    def scan(self) -> list[Finding]:
        try:
            probe = self.executor.run(_ACCOUNT_PROBE_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("account_probe", error)]

        probe_lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
        if probe.returncode != 0 or len(probe_lines) < 3 or probe_lines[0] != "BLACKLIGHT_OK":
            return [
                self._error(
                    "server.accounts.platform_probe",
                    "Blacklight could not identify the remote account-audit target",
                    "The SSH session opened, but the fixed account probe did not return the expected metadata.",
                    {"returncode": probe.returncode, "stderr": probe.stderr[:500]},
                )
            ]

        platform_name, hostname = probe_lines[1:3]
        if platform_name.lower() != "linux":
            return [
                self._error(
                    "server.accounts.unsupported_platform",
                    "Remote account-audit target platform is not supported",
                    "The server account scanner currently supports Linux targets only.",
                    {"platform": platform_name, "hostname": hostname},
                )
            ]

        findings: list[Finding] = []
        results: dict[str, CommandResult] = {}

        for name, command in [
            ("account_inventory", _ACCOUNT_INVENTORY_COMMAND),
            ("privileged_groups", _PRIVILEGED_GROUPS_COMMAND),
            ("sudoers", _SUDOERS_COMMAND),
        ]:
            try:
                results[name] = self.executor.run(command)
            except SSHExecutionError as error:
                findings.append(self._transport_error(name, error))

        accounts: list[AccountRecord] = []
        uid_min = 1000
        uid_min_source = "fallback"
        login_shells: set[str] = set()

        inventory = results.get("account_inventory")
        if inventory is not None:
            if inventory.returncode != 0:
                findings.append(
                    self._error(
                        "server.accounts.account_inventory",
                        "Blacklight could not inspect the local account database",
                        "The fixed read-only account inventory command did not complete successfully.",
                        {
                            "returncode": inventory.returncode,
                            "stderr": inventory.stderr[:500],
                        },
                    )
                )
            else:
                accounts, uid_min, uid_min_source, login_shells = self._parse_account_inventory(
                    inventory.stdout
                )
                findings.append(self._check_duplicate_uids(accounts))
                findings.append(
                    self._check_system_login_accounts(
                        accounts,
                        uid_min,
                        uid_min_source,
                        login_shells,
                    )
                )

        groups = results.get("privileged_groups")
        if groups is not None:
            if groups.returncode != 0:
                findings.append(
                    self._error(
                        "server.accounts.privileged_groups",
                        "Blacklight could not inspect privileged local groups",
                        "The fixed read-only privileged-group inventory did not complete successfully.",
                        {
                            "returncode": groups.returncode,
                            "stderr": groups.stderr[:500],
                        },
                    )
                )
            else:
                findings.append(
                    self._check_privileged_groups(
                        accounts,
                        self._parse_group_inventory(groups.stdout),
                    )
                )

        sudoers = results.get("sudoers")
        if sudoers is not None:
            findings.extend(self._check_sudoers(sudoers))

        return findings

    def _check_duplicate_uids(self, accounts: list[AccountRecord]) -> Finding:
        by_uid: dict[int, list[str]] = {}
        for account in accounts:
            by_uid.setdefault(account.uid, []).append(account.username)

        duplicates = [
            {"uid": uid, "accounts": sorted(names)}
            for uid, names in sorted(by_uid.items())
            if len(names) > 1
        ]

        if duplicates:
            severity = (
                Severity.HIGH
                if any(item["uid"] == 0 for item in duplicates)
                else Severity.MEDIUM
            )
            return self._finding(
                "server.accounts.duplicate_uids",
                severity,
                "Multiple Linux account names share the same numeric UID",
                (
                    "Blacklight observed duplicate numeric user identifiers. Accounts sharing a "
                    "UID are indistinguishable to normal Unix file ownership and process identity "
                    "checks for that UID."
                ),
                remediation=(
                    "Review duplicate UID assignments and keep shared identities only when they "
                    "are explicitly required and documented."
                ),
                evidence={"duplicates": duplicates},
            )

        return self._finding(
            "server.accounts.duplicate_uids",
            Severity.PASS,
            "No duplicate numeric user IDs were observed",
            "The readable local account database did not contain multiple names for the same UID.",
        )

    def _check_system_login_accounts(
        self,
        accounts: list[AccountRecord],
        uid_min: int,
        uid_min_source: str,
        login_shells: set[str],
    ) -> Finding:
        if not login_shells:
            return self._finding(
                "server.accounts.system_login_shells",
                Severity.INFO,
                "Login-capable shell inventory was not available",
                (
                    "Blacklight could not read an accepted-shell list from /etc/shells, so it "
                    "did not guess which system-account shells are interactive."
                ),
                evidence={
                    "uid_min": uid_min,
                    "uid_min_source": uid_min_source,
                },
            )

        matches = [
            account.to_dict()
            for account in accounts
            if 0 < account.uid < uid_min
            and account.shell not in _NON_LOGIN_SHELLS
            and account.shell in login_shells
        ]

        if matches:
            return self._finding(
                "server.accounts.system_login_shells",
                Severity.MEDIUM,
                "System accounts with login-capable shells were observed",
                (
                    "One or more non-root accounts below the configured UID_MIN use a shell "
                    "listed in /etc/shells. This does not prove remote login is possible, but it "
                    "expands the account's local login capability beyond a nologin/false shell."
                ),
                remediation=(
                    "Review whether each listed system account requires an interactive shell and "
                    "replace unnecessary login shells with the platform's nologin mechanism."
                ),
                evidence={
                    "uid_min": uid_min,
                    "uid_min_source": uid_min_source,
                    "accounts": matches,
                },
            )

        return self._finding(
            "server.accounts.system_login_shells",
            Severity.PASS,
            "No login-capable shells were observed on non-root system accounts",
            (
                "Accounts below the configured UID_MIN did not use an observed accepted login "
                "shell, excluding root."
            ),
            evidence={
                "uid_min": uid_min,
                "uid_min_source": uid_min_source,
                "login_shells": sorted(login_shells),
            },
        )

    def _check_privileged_groups(
        self,
        accounts: list[AccountRecord],
        groups: list[GroupRecord],
    ) -> Finding:
        accounts_by_gid: dict[int, list[str]] = {}
        for account in accounts:
            accounts_by_gid.setdefault(account.gid, []).append(account.username)

        observed: list[dict[str, object]] = []
        root_equivalent: list[dict[str, object]] = []

        for group in groups:
            members = set(group.members)
            members.update(accounts_by_gid.get(group.gid, []))
            members.discard("root")
            if not members:
                continue

            item = {
                "group": group.name,
                "gid": group.gid,
                "members": sorted(members),
            }
            observed.append(item)
            if group.name in {"docker", "lxd"}:
                root_equivalent.append(item)

        if root_equivalent:
            return self._finding(
                "server.accounts.privileged_groups",
                Severity.MEDIUM,
                "Root-equivalent container-management group access was observed",
                (
                    "Non-root users belong to Docker or LXD management groups. In common daemon "
                    "configurations, this can provide a path to root-equivalent host control. "
                    "Blacklight reports the membership itself and does not assume it is unintended."
                ),
                remediation=(
                    "Confirm every listed Docker/LXD group member requires that level of host "
                    "control and remove unnecessary memberships."
                ),
                evidence={
                    "root_equivalent_groups": root_equivalent,
                    "other_privileged_groups": [
                        item for item in observed if item not in root_equivalent
                    ],
                },
            )

        if observed:
            return self._finding(
                "server.accounts.privileged_groups",
                Severity.INFO,
                "Administrative group memberships were observed",
                (
                    "Blacklight observed non-root membership in sudo, wheel, or admin groups. "
                    "This is privilege inventory rather than an automatic vulnerability."
                ),
                evidence={"groups": observed},
            )

        return self._finding(
            "server.accounts.privileged_groups",
            Severity.PASS,
            "No non-root membership was observed in selected privileged groups",
            (
                "The selected sudo, wheel, admin, docker, and lxd groups contained no observed "
                "non-root members or were not present."
            ),
        )

    def _check_sudoers(self, result: CommandResult) -> list[Finding]:
        if result.returncode != 0:
            return [
                self._error(
                    "server.accounts.sudoers_readability",
                    "Blacklight could not inspect sudoers configuration",
                    "The fixed read-only sudoers inspection did not complete successfully.",
                    {"returncode": result.returncode, "stderr": result.stderr[:500]},
                )
            ]

        readable: list[str] = []
        unreadable: list[str] = []
        rules: list[dict[str, str]] = []
        broad_rules: list[dict[str, str]] = []

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BLACKLIGHT_SUDO_READABLE="):
                readable.append(line.split("=", 1)[1])
                continue
            if line.startswith("BLACKLIGHT_SUDO_UNREADABLE="):
                unreadable.append(line.split("=", 1)[1])
                continue
            if not line.startswith("BLACKLIGHT_SUDO_RULE="):
                continue

            payload = line.split("=", 1)[1]
            if "|" not in payload:
                continue
            path, rule = payload.split("|", 1)
            item = {"path": path, "rule": rule.strip()}
            rules.append(item)
            match = _BROAD_NOPASSWD_RE.match(rule.strip())
            if match:
                broad_rules.append(
                    {
                        "path": path,
                        "subject": match.group("subject"),
                        "rule": rule.strip(),
                    }
                )

        findings: list[Finding] = []

        if broad_rules:
            findings.append(
                self._finding(
                    "server.accounts.broad_nopasswd_sudo",
                    Severity.HIGH,
                    "Broad passwordless sudo rules were observed",
                    (
                        "Blacklight found direct sudoers rules granting a user or group "
                        "NOPASSWD access to ALL commands on ALL hosts with an ALL run-as target "
                        "or omitted run-as restriction."
                    ),
                    remediation=(
                        "Replace broad passwordless sudo grants with the narrowest required "
                        "commands, hosts, and run-as identities."
                    ),
                    evidence={"matches": broad_rules},
                )
            )
        elif readable:
            findings.append(
                self._finding(
                    "server.accounts.broad_nopasswd_sudo",
                    Severity.PASS,
                    "No direct broad NOPASSWD sudo rule was observed in readable files",
                    (
                        "Readable sudoers files did not contain the specific direct ALL-host, "
                        "ALL-command NOPASSWD rule pattern Blacklight checks."
                    ),
                    evidence={"nopasswd_rules_observed": rules},
                )
            )
        else:
            findings.append(
                self._finding(
                    "server.accounts.broad_nopasswd_sudo",
                    Severity.INFO,
                    "No readable sudoers rule content was available",
                    (
                        "Blacklight did not receive readable sudoers rule content and therefore "
                        "did not infer whether broad passwordless sudo access exists."
                    ),
                )
            )

        if unreadable:
            findings.append(
                self._error(
                    "server.accounts.sudoers_readability",
                    "Some sudoers configuration files were not readable",
                    (
                        "One or more existing sudoers files could not be inspected by the audit "
                        "account, so sudo-rule coverage is incomplete."
                    ),
                    {
                        "readable_files": sorted(readable),
                        "unreadable_files": sorted(unreadable),
                    },
                )
            )
        else:
            findings.append(
                self._finding(
                    "server.accounts.sudoers_readability",
                    Severity.PASS,
                    "Observed sudoers configuration files were readable",
                    (
                        "Every sudoers file surfaced by the fixed inspection loop was readable to "
                        "the audit session."
                    ),
                    evidence={"readable_files": sorted(readable)},
                )
            )

        return findings

    @staticmethod
    def _parse_account_inventory(
        output: str,
    ) -> tuple[list[AccountRecord], int, str, set[str]]:
        uid_min = 1000
        uid_min_source = "fallback"
        login_shells: set[str] = set()
        accounts: list[AccountRecord] = []
        in_passwd = False

        for line in output.splitlines():
            if line.startswith("BLACKLIGHT_UID_MIN="):
                value = line.split("=", 1)[1].strip()
                if value.isdigit():
                    uid_min = int(value)
                continue
            if line.startswith("BLACKLIGHT_UID_MIN_SOURCE="):
                uid_min_source = line.split("=", 1)[1].strip() or "fallback"
                continue
            if line.startswith("BLACKLIGHT_SHELL="):
                shell = line.split("=", 1)[1].strip()
                if shell:
                    login_shells.add(shell)
                continue
            if line == "BLACKLIGHT_PASSWD_BEGIN":
                in_passwd = True
                continue
            if not in_passwd:
                continue

            parts = line.split(":")
            if len(parts) < 7 or not parts[2].isdigit() or not parts[3].isdigit():
                continue
            accounts.append(
                AccountRecord(
                    username=parts[0],
                    uid=int(parts[2]),
                    gid=int(parts[3]),
                    home=parts[5],
                    shell=parts[6],
                )
            )

        return accounts, uid_min, uid_min_source, login_shells

    @staticmethod
    def _parse_group_inventory(output: str) -> list[GroupRecord]:
        groups: list[GroupRecord] = []
        for line in output.splitlines():
            if not line.startswith("BLACKLIGHT_GROUP="):
                continue
            payload = line.split("=", 1)[1]
            parts = payload.split(":")
            if len(parts) < 4 or not parts[2].isdigit():
                continue
            members = tuple(
                sorted(
                    member.strip()
                    for member in parts[3].split(",")
                    if member.strip()
                )
            )
            groups.append(
                GroupRecord(
                    name=parts[0],
                    gid=int(parts[2]),
                    members=members,
                )
            )
        return groups

    def _transport_error(self, name: str, error: SSHExecutionError) -> Finding:
        return self._error(
            f"server.accounts.{name}",
            f"Blacklight could not complete the {name.replace('_', ' ')} inspection",
            "The SSH transport failed before this read-only account inspection completed.",
            {"error": str(error)},
        )

    def _error(
        self,
        check_id: str,
        title: str,
        description: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return self._finding(
            check_id,
            Severity.ERROR,
            title,
            description,
            remediation=(
                "Verify SSH connectivity, the audit account's read permissions, and availability "
                "of the required local account-management tools, then retry."
            ),
            evidence=evidence,
        )

    def _finding(
        self,
        check_id: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            provider="server",
            service="accounts",
            resource_type="linux_server",
            resource_id=self.target.resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
