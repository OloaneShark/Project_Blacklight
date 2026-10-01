from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.server.linux import (
    CommandResult,
    SSHCommandRunner,
    SSHExecutionError,
    ServerScanTarget,
)


_AUTH_PROBE_COMMAND = "printf 'BLACKLIGHT_OK\\n'; uname -s; hostname"
_PAM_POLICY_COMMAND = (
    "for f in /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/common-auth "
    "/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/su /etc/pam.d/sudo; do "
    '[ -e "$f" ] || continue; '
    "if [ -r \"$f\" ]; then "
    "printf 'BLACKLIGHT_PAM_READABLE=%s\\n' \"$f\"; "
    "awk '"
    "/^[[:space:]]*#/ {next} "
    "/^[[:space:]]*auth[[:space:]]+/ && /pam_permit[.]so/ "
    "{print \"BLACKLIGHT_PAM_PERMIT=\" FILENAME \"|\" $0} "
    "/^[[:space:]]*auth[[:space:]]+/ && /pam_unix[.]so/ && "
    "/(^|[[:space:]])nullok([[:space:]]|$)/ "
    "{print \"BLACKLIGHT_PAM_NULLOK=\" FILENAME \"|\" $0}' "
    "\"$f\"; "
    "else printf 'BLACKLIGHT_PAM_UNREADABLE=%s\\n' \"$f\"; fi; "
    "done"
)
_AUTH_STATE_COMMAND = (
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
    "else cat /etc/passwd 2>/dev/null; fi; "
    "printf 'BLACKLIGHT_PASSWD_END\\n'; "
    "if command -v passwd >/dev/null 2>&1; then "
    "s=$(passwd -S 2>/dev/null || true); "
    "[ -n \"$s\" ] && printf 'BLACKLIGHT_SELF_PASSWD=%s\\n' \"$s\"; "
    "fi; "
    "if [ -r /etc/shadow ]; then "
    "printf 'BLACKLIGHT_SHADOW_READABLE=1\\n'; "
    "awk -F: '{"
    "state=\"set\"; "
    "if ($2 == \"\") state=\"empty\"; "
    "else if ($2 ~ /^[!*]/) state=\"locked\"; "
    "printf \"BLACKLIGHT_SHADOW_ACCOUNT=%s|%s|%s|%s|%s|%s\\n\", "
    "$1,state,$3,$5,$7,$8"
    "}' /etc/shadow; "
    "else printf 'BLACKLIGHT_SHADOW_READABLE=0\\n'; fi"
)

_NON_LOGIN_SHELLS = {
    "",
    "/bin/false",
    "/usr/bin/false",
    "/sbin/nologin",
    "/usr/sbin/nologin",
}


@dataclass(frozen=True, slots=True)
class AuthAccount:
    username: str
    uid: int
    shell: str

    def to_dict(self) -> dict[str, object]:
        return {
            "username": self.username,
            "uid": self.uid,
            "shell": self.shell,
        }


@dataclass(frozen=True, slots=True)
class ShadowAccountState:
    username: str
    state: str
    last_change: str
    max_days: str
    inactive_days: str
    expire_day: str

    def to_dict(self) -> dict[str, str]:
        return {
            "username": self.username,
            "state": self.state,
            "last_change": self.last_change,
            "max_days": self.max_days,
            "inactive_days": self.inactive_days,
            "expire_day": self.expire_day,
        }


class ServerAuthenticationScanner:
    """Read-only authentication-policy and account-state checks for Linux servers."""

    def __init__(self, target: ServerScanTarget):
        self.target = target
        self.executor = target.executor or SSHCommandRunner(target)

    def scan(self) -> list[Finding]:
        try:
            probe = self.executor.run(_AUTH_PROBE_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("authentication_probe", error)]

        probe_lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
        if probe.returncode != 0 or len(probe_lines) < 3 or probe_lines[0] != "BLACKLIGHT_OK":
            return [
                self._error(
                    "server.auth.platform_probe",
                    "Blacklight could not identify the remote authentication target",
                    "The SSH session opened, but the fixed authentication probe did not return the expected metadata.",
                    {"returncode": probe.returncode, "stderr": probe.stderr[:500]},
                )
            ]

        platform_name, hostname = probe_lines[1:3]
        if platform_name.lower() != "linux":
            return [
                self._error(
                    "server.auth.unsupported_platform",
                    "Remote authentication target platform is not supported",
                    "The server authentication scanner currently supports Linux targets only.",
                    {"platform": platform_name, "hostname": hostname},
                )
            ]

        findings: list[Finding] = []
        results: dict[str, CommandResult] = {}

        for name, command in [
            ("pam_policy", _PAM_POLICY_COMMAND),
            ("account_state", _AUTH_STATE_COMMAND),
        ]:
            try:
                results[name] = self.executor.run(command)
            except SSHExecutionError as error:
                findings.append(self._transport_error(name, error))

        policy = results.get("pam_policy")
        if policy is not None:
            findings.extend(self._check_pam_policy(policy))

        state = results.get("account_state")
        if state is not None:
            findings.extend(self._check_account_state(state))

        return findings

    def _check_pam_policy(self, result: CommandResult) -> list[Finding]:
        if result.returncode != 0:
            return [
                self._error(
                    "server.auth.pam_policy",
                    "Blacklight could not inspect PAM authentication policy",
                    "The fixed read-only PAM policy inspection did not complete successfully.",
                    {"returncode": result.returncode, "stderr": result.stderr[:500]},
                )
            ]

        readable: list[str] = []
        unreadable: list[str] = []
        permit_rules: list[dict[str, str]] = []
        nullok_rules: list[dict[str, str]] = []

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BLACKLIGHT_PAM_READABLE="):
                readable.append(line.split("=", 1)[1])
            elif line.startswith("BLACKLIGHT_PAM_UNREADABLE="):
                unreadable.append(line.split("=", 1)[1])
            elif line.startswith("BLACKLIGHT_PAM_PERMIT="):
                parsed = self._parse_rule_marker(line, "BLACKLIGHT_PAM_PERMIT=")
                if parsed is not None:
                    permit_rules.append(parsed)
            elif line.startswith("BLACKLIGHT_PAM_NULLOK="):
                parsed = self._parse_rule_marker(line, "BLACKLIGHT_PAM_NULLOK=")
                if parsed is not None:
                    nullok_rules.append(parsed)

        findings: list[Finding] = []

        if permit_rules:
            findings.append(
                self._finding(
                    "server.auth.pam_permit_auth",
                    Severity.HIGH,
                    "PAM authentication stack contains active pam_permit rules",
                    (
                        "Blacklight observed active auth lines using pam_permit.so in selected "
                        "login-related PAM service files. pam_permit always reports success to "
                        "the PAM stack, so these rules require explicit review in context."
                    ),
                    remediation=(
                        "Review each listed PAM service and remove pam_permit from authentication "
                        "paths unless the unconditional success behavior is explicitly required."
                    ),
                    evidence={"matches": permit_rules},
                )
            )
        else:
            findings.append(
                self._finding(
                    "server.auth.pam_permit_auth",
                    Severity.INFO,
                    "No active pam_permit authentication rule was observed",
                    (
                        "Blacklight did not observe pam_permit.so on active auth lines in the "
                        "selected readable PAM service files. PAM includes and uninspected service "
                        "files can still affect authentication behavior."
                    ),
                    evidence={
                        "readable_files": sorted(readable),
                        "unreadable_files": sorted(unreadable),
                    },
                )
            )

        if nullok_rules:
            findings.append(
                self._finding(
                    "server.auth.pam_null_passwords",
                    Severity.HIGH,
                    "PAM explicitly allows null passwords for pam_unix authentication",
                    (
                        "Blacklight observed active pam_unix authentication lines containing the "
                        "nullok option. This option allows pam_unix to accept accounts whose local "
                        "password field is empty when the rest of the service policy permits it."
                    ),
                    remediation=(
                        "Remove nullok from login-related PAM authentication paths unless empty "
                        "local passwords are an intentional and separately controlled requirement."
                    ),
                    evidence={"matches": nullok_rules},
                )
            )
        else:
            findings.append(
                self._finding(
                    "server.auth.pam_null_passwords",
                    Severity.INFO,
                    "No explicit pam_unix nullok option was observed",
                    (
                        "Blacklight did not observe the explicit pam_unix nullok token on active "
                        "auth lines in the selected readable PAM files. This is not a complete "
                        "effective-PAM evaluation."
                    ),
                    evidence={
                        "readable_files": sorted(readable),
                        "unreadable_files": sorted(unreadable),
                    },
                )
            )

        if unreadable:
            findings.append(
                self._finding(
                    "server.auth.pam_policy_visibility",
                    Severity.INFO,
                    "Some selected PAM service files were not readable",
                    (
                        "Blacklight could inspect some authentication policy but could not read "
                        "every selected PAM service file. The unreadable paths are retained as "
                        "coverage context without assuming unsafe or safe behavior."
                    ),
                    evidence={
                        "readable_files": sorted(readable),
                        "unreadable_files": sorted(unreadable),
                    },
                )
            )
        else:
            findings.append(
                self._finding(
                    "server.auth.pam_policy_visibility",
                    Severity.PASS if readable else Severity.INFO,
                    (
                        "Selected PAM service files were readable"
                        if readable
                        else "No selected PAM service files were present"
                    ),
                    (
                        "Blacklight read every selected PAM file that was present."
                        if readable
                        else "None of Blacklight's selected PAM service paths existed on the host."
                    ),
                    evidence={"readable_files": sorted(readable)},
                )
            )

        return findings

    def _check_account_state(self, result: CommandResult) -> list[Finding]:
        if result.returncode != 0:
            return [
                self._error(
                    "server.auth.account_state",
                    "Blacklight could not inspect local authentication account state",
                    "The fixed read-only account-state inspection did not complete successfully.",
                    {"returncode": result.returncode, "stderr": result.stderr[:500]},
                )
            ]

        accounts, uid_min, uid_min_source, login_shells, shadow_readable, shadow, self_state = (
            self._parse_account_state(result.stdout)
        )

        findings = [
            self._check_connected_password_state(self_state),
            self._check_empty_password_accounts(
                accounts,
                uid_min,
                uid_min_source,
                login_shells,
                shadow_readable,
                shadow,
            ),
        ]

        locked_count = sum(1 for item in shadow if item.state == "locked")
        set_count = sum(1 for item in shadow if item.state == "set")
        empty_count = sum(1 for item in shadow if item.state == "empty")
        findings.append(
            self._finding(
                "server.auth.shadow_visibility",
                Severity.INFO,
                (
                    "Local shadow account-state metadata was readable"
                    if shadow_readable
                    else "Local shadow account-state metadata was not readable"
                ),
                (
                    "Blacklight classified password-field state without returning password hashes."
                    if shadow_readable
                    else (
                        "The audit account could not read /etc/shadow. Blacklight therefore did "
                        "not claim whole-host password lock or empty-password coverage."
                    )
                ),
                evidence={
                    "shadow_readable": shadow_readable,
                    "classified_accounts": len(shadow),
                    "locked_count": locked_count,
                    "password_set_count": set_count,
                    "empty_password_count": empty_count,
                    "password_hashes_returned": False,
                },
            )
        )
        return findings

    def _check_connected_password_state(
        self,
        self_state: tuple[str, str] | None,
    ) -> Finding:
        if self_state is None:
            return self._finding(
                "server.auth.connected_password_state",
                Severity.INFO,
                "Connected account password state was not available",
                (
                    "The local passwd utility did not return a parseable status for the connected "
                    "audit account."
                ),
            )

        username, status = self_state
        normalized = status.upper()

        if normalized == "NP":
            return self._finding(
                "server.auth.connected_password_state",
                Severity.HIGH,
                "Connected audit account reports no local password",
                (
                    "The local passwd status for the connected account is NP (no password). "
                    "Whether this permits authentication still depends on PAM and service policy."
                ),
                remediation=(
                    "Confirm that the account is intentionally passwordless and cannot authenticate "
                    "through any password path that accepts an empty credential."
                ),
                evidence={"username": username, "status": normalized},
            )

        if normalized in {"L", "LK"}:
            return self._finding(
                "server.auth.connected_password_state",
                Severity.PASS,
                "Connected account local password is locked",
                (
                    "The local passwd status reports a locked password credential. Other "
                    "authentication methods such as SSH keys may still be available."
                ),
                evidence={"username": username, "status": normalized},
            )

        return self._finding(
            "server.auth.connected_password_state",
            Severity.INFO,
            "Connected account has a local password credential state",
            (
                "The local passwd utility returned a non-empty, non-locked password status for "
                "the connected account. This is authentication inventory, not a vulnerability."
            ),
            evidence={"username": username, "status": normalized},
        )

    def _check_empty_password_accounts(
        self,
        accounts: list[AuthAccount],
        uid_min: int,
        uid_min_source: str,
        login_shells: set[str],
        shadow_readable: bool,
        shadow: list[ShadowAccountState],
    ) -> Finding:
        if not shadow_readable:
            return self._finding(
                "server.auth.empty_password_accounts",
                Severity.INFO,
                "Whole-host empty-password state was not assessable",
                (
                    "The audit account could not read /etc/shadow, so Blacklight did not infer "
                    "whether other local accounts have empty password fields."
                ),
                evidence={
                    "shadow_readable": False,
                    "password_hashes_returned": False,
                },
            )

        account_map = {account.username: account for account in accounts}
        empty_states = [item for item in shadow if item.state == "empty"]
        evidence_accounts: list[dict[str, object]] = []
        login_capable: list[dict[str, object]] = []

        for item in empty_states:
            account = account_map.get(item.username)
            record: dict[str, object] = {
                "username": item.username,
                "state": "empty",
            }
            if account is not None:
                record.update(
                    {
                        "uid": account.uid,
                        "shell": account.shell,
                    }
                )
                can_login = (
                    account.username == "root"
                    or (
                        account.shell not in _NON_LOGIN_SHELLS
                        and (
                            account.shell in login_shells
                            if login_shells
                            else account.uid >= uid_min
                        )
                    )
                )
                record["login_capable_shell"] = can_login
                if can_login:
                    login_capable.append(record)

            evidence_accounts.append(record)

        evidence = {
            "uid_min": uid_min,
            "uid_min_source": uid_min_source,
            "empty_password_accounts": evidence_accounts,
            "password_hashes_returned": False,
        }

        if login_capable:
            return self._finding(
                "server.auth.empty_password_accounts",
                Severity.HIGH,
                "Login-capable local accounts have empty password fields",
                (
                    "Blacklight observed one or more local shadow entries with an empty password "
                    "field and an account shell that is login-capable by the available evidence. "
                    "This does not by itself prove a service will accept an empty password."
                ),
                remediation=(
                    "Set or lock the affected account password and review PAM/service policy for "
                    "any path that accepts null passwords."
                ),
                evidence=evidence,
            )

        if empty_states:
            return self._finding(
                "server.auth.empty_password_accounts",
                Severity.MEDIUM,
                "Local accounts with empty password fields were observed",
                (
                    "Blacklight observed empty local password fields, but the associated accounts "
                    "were not proven login-capable from the available shell evidence."
                ),
                remediation=(
                    "Review the listed accounts and either set/lock their password field or confirm "
                    "that their non-login design prevents password authentication."
                ),
                evidence=evidence,
            )

        return self._finding(
            "server.auth.empty_password_accounts",
            Severity.PASS,
            "No empty local password fields were observed",
            (
                "Readable shadow account-state metadata contained no empty password fields. "
                "Blacklight did not return any password hash material."
            ),
            evidence={
                "shadow_readable": True,
                "classified_accounts": len(shadow),
                "password_hashes_returned": False,
            },
        )

    @staticmethod
    def _parse_rule_marker(line: str, prefix: str) -> dict[str, str] | None:
        payload = line.removeprefix(prefix)
        if "|" not in payload:
            return None
        path, rule = payload.split("|", 1)
        return {"path": path, "rule": rule.strip()}

    @staticmethod
    def _parse_account_state(
        output: str,
    ) -> tuple[
        list[AuthAccount],
        int,
        str,
        set[str],
        bool,
        list[ShadowAccountState],
        tuple[str, str] | None,
    ]:
        accounts: list[AuthAccount] = []
        uid_min = 1000
        uid_min_source = "fallback"
        login_shells: set[str] = set()
        shadow_readable = False
        shadow: list[ShadowAccountState] = []
        self_state: tuple[str, str] | None = None
        in_passwd = False

        for raw_line in output.splitlines():
            line = raw_line.strip()
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
            if line == "BLACKLIGHT_PASSWD_END":
                in_passwd = False
                continue
            if in_passwd:
                parts = line.split(":")
                if len(parts) >= 7 and parts[2].isdigit():
                    accounts.append(
                        AuthAccount(
                            username=parts[0],
                            uid=int(parts[2]),
                            shell=parts[6],
                        )
                    )
                continue
            if line.startswith("BLACKLIGHT_SELF_PASSWD="):
                payload = line.split("=", 1)[1].strip().split()
                if len(payload) >= 2:
                    self_state = (payload[0], payload[1])
                continue
            if line == "BLACKLIGHT_SHADOW_READABLE=1":
                shadow_readable = True
                continue
            if line == "BLACKLIGHT_SHADOW_READABLE=0":
                shadow_readable = False
                continue
            if line.startswith("BLACKLIGHT_SHADOW_ACCOUNT="):
                payload = line.split("=", 1)[1]
                parts = payload.split("|")
                if len(parts) != 6:
                    continue
                shadow.append(
                    ShadowAccountState(
                        username=parts[0],
                        state=parts[1],
                        last_change=parts[2],
                        max_days=parts[3],
                        inactive_days=parts[4],
                        expire_day=parts[5],
                    )
                )

        return (
            accounts,
            uid_min,
            uid_min_source,
            login_shells,
            shadow_readable,
            shadow,
            self_state,
        )

    def _transport_error(self, name: str, error: SSHExecutionError) -> Finding:
        return self._error(
            f"server.auth.{name}",
            f"Blacklight could not complete the {name.replace('_', ' ')} inspection",
            "The SSH transport failed before this read-only authentication inspection completed.",
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
                "of the required local authentication files/tools, then retry."
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
            service="auth",
            resource_type="linux_server",
            resource_id=self.target.resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
