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


_HARDENING_PROBE_COMMAND = "printf 'BLACKLIGHT_OK\\n'; uname -s; hostname; id -un"
_SENSITIVE_FILES_COMMAND = (
    "for f in /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/sudoers.d/*; do "
    '[ -e "$f" ] || continue; '
    "stat -c '%n|%a|%U|%G' \"$f\" 2>/dev/null || true; "
    "done"
)
_SSH_PATHS_COMMAND = (
    'u="$(id -un)"; '
    'h="$(getent passwd "$u" 2>/dev/null | cut -d: -f6)"; '
    '[ -n "$h" ] || h="$HOME"; '
    'printf "BLACKLIGHT_USER=%s\\nBLACKLIGHT_HOME=%s\\n" "$u" "$h"; '
    'for f in "$h" "$h/.ssh" "$h/.ssh/authorized_keys"; do '
    '[ -e "$f" ] || continue; '
    'stat -c "%n|%a|%U|%G" "$f" 2>/dev/null || true; '
    "done"
)
_AUTO_UPDATES_COMMAND = (
    "if command -v apt-get >/dev/null 2>&1; then "
    "printf 'BLACKLIGHT_FAMILY=apt\\n'; "
    "v=$(grep -hE '^[[:space:]]*APT::Periodic::Unattended-Upgrade[[:space:]]+\"[01]\";' "
    "/etc/apt/apt.conf.d/* 2>/dev/null | tail -n 1); "
    "printf 'BLACKLIGHT_CONFIG=%s\\n' \"$v\"; "
    "if command -v systemctl >/dev/null 2>&1; then "
    "s=$(systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null || true); "
    "printf 'BLACKLIGHT_TIMER=%s\\n' \"$s\"; fi; "
    "elif command -v dnf >/dev/null 2>&1; then "
    "printf 'BLACKLIGHT_FAMILY=dnf\\n'; "
    "v=$(awk -F= 'BEGIN{IGNORECASE=1} "
    "/^[[:space:]]*apply_updates[[:space:]]*=/ {gsub(/[[:space:]]/,\"\",$2); print $2}' "
    "/etc/dnf/automatic.conf 2>/dev/null | tail -n 1); "
    "printf 'BLACKLIGHT_CONFIG=%s\\n' \"$v\"; "
    "if command -v systemctl >/dev/null 2>&1; then "
    "s=$(systemctl is-enabled dnf-automatic-install.timer 2>/dev/null || "
    "systemctl is-enabled dnf-automatic.timer 2>/dev/null || true); "
    "printf 'BLACKLIGHT_TIMER=%s\\n' \"$s\"; fi; "
    "else printf 'BLACKLIGHT_FAMILY=unknown\\n'; fi"
)

_STAT_RE = re.compile(r"^(?P<path>[^|]+)\\|(?P<mode>[0-7]{3,4})\\|(?P<owner>[^|]+)\\|(?P<group>[^|]+)$")


@dataclass(frozen=True, slots=True)
class FileMetadata:
    path: str
    mode_text: str
    owner: str
    group: str

    @property
    def mode(self) -> int:
        return int(self.mode_text, 8)

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "mode": self.mode_text,
            "owner": self.owner,
            "group": self.group,
        }


class ServerHardeningScanner:
    """Read-only host-hardening checks for a remote Linux server."""

    def __init__(self, target: ServerScanTarget):
        self.target = target
        self.executor = target.executor or SSHCommandRunner(target)

    def scan(self) -> list[Finding]:
        try:
            probe = self.executor.run(_HARDENING_PROBE_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("hardening_probe", error)]

        probe_lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
        if probe.returncode != 0 or len(probe_lines) < 4 or probe_lines[0] != "BLACKLIGHT_OK":
            return [
                self._error(
                    "server.hardening.platform_probe",
                    "Blacklight could not identify the remote hardening target",
                    "The SSH session opened, but the fixed hardening probe did not return the expected metadata.",
                    {"returncode": probe.returncode, "stderr": probe.stderr[:500]},
                )
            ]

        platform_name, hostname, username = probe_lines[1:4]
        if platform_name.lower() != "linux":
            return [
                self._error(
                    "server.hardening.unsupported_platform",
                    "Remote hardening target platform is not supported",
                    "The server hardening scanner currently supports Linux targets only.",
                    {"platform": platform_name, "hostname": hostname},
                )
            ]

        findings: list[Finding] = []
        commands = [
            ("sensitive_files", _SENSITIVE_FILES_COMMAND),
            ("ssh_paths", _SSH_PATHS_COMMAND),
            ("automatic_updates", _AUTO_UPDATES_COMMAND),
        ]

        results: dict[str, CommandResult] = {}
        for name, command in commands:
            try:
                results[name] = self.executor.run(command)
            except SSHExecutionError as error:
                findings.append(self._transport_error(name, error))
                continue

        if "sensitive_files" in results:
            findings.append(self._check_sensitive_files(results["sensitive_files"]))
        if "ssh_paths" in results:
            findings.append(self._check_ssh_paths(results["ssh_paths"], username))
        if "automatic_updates" in results:
            findings.append(self._check_automatic_updates(results["automatic_updates"]))

        return findings

    def _check_sensitive_files(self, result: CommandResult) -> Finding:
        if result.returncode != 0:
            return self._error(
                "server.hardening.sensitive_file_permissions",
                "Blacklight could not inspect sensitive file permissions",
                "The fixed metadata-only stat inspection did not complete successfully.",
                {"returncode": result.returncode, "stderr": result.stderr[:500]},
            )

        entries = self._parse_stat_lines(result.stdout)
        by_path = {entry.path: entry for entry in entries}
        required = ["/etc/passwd", "/etc/group", "/etc/shadow"]
        missing = [path for path in required if path not in by_path]
        violations: list[dict[str, Any]] = []

        for entry in entries:
            mode = entry.mode
            reason: list[str] = []

            if entry.path in {"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers"} or entry.path.startswith("/etc/sudoers.d/"):
                if entry.owner != "root":
                    reason.append("owner-is-not-root")

            if entry.path in {"/etc/passwd", "/etc/group"}:
                if mode & 0o022:
                    reason.append("group-or-other-writable")
            elif entry.path == "/etc/shadow":
                if mode & 0o027:
                    reason.append("shadow-permissions-too-broad")
            elif entry.path == "/etc/sudoers" or entry.path.startswith("/etc/sudoers.d/"):
                if mode & 0o022:
                    reason.append("sudo-config-group-or-other-writable")

            if reason:
                violations.append({**entry.to_dict(), "reasons": reason})

        evidence = {
            "observed": [entry.to_dict() for entry in entries],
            "missing_core_files": missing,
            "violations": violations,
        }

        if violations:
            return self._finding(
                "server.hardening.sensitive_file_permissions",
                Severity.HIGH,
                "Sensitive Linux security files have unsafe ownership or write permissions",
                (
                    "Blacklight observed one or more authentication or privilege-control files "
                    "with ownership or permissions that allow unsafe modification or excessive "
                    "access."
                ),
                remediation=(
                    "Restore trusted root ownership and restrictive permissions appropriate to "
                    "the affected file, then review how the permission drift occurred."
                ),
                evidence=evidence,
            )

        if missing:
            return self._finding(
                "server.hardening.sensitive_file_permissions",
                Severity.INFO,
                "Some core sensitive file metadata was not observed",
                (
                    "No unsafe permission state was observed in the returned metadata, but one or "
                    "more expected Linux account files were not visible to the audit session."
                ),
                evidence=evidence,
            )

        return self._finding(
            "server.hardening.sensitive_file_permissions",
            Severity.PASS,
            "Observed sensitive Linux files have restrictive ownership and write permissions",
            (
                "The account, shadow, and observed sudo configuration metadata did not show the "
                "specific unsafe ownership or write-permission conditions Blacklight checks."
            ),
            evidence=evidence,
        )

    def _check_ssh_paths(self, result: CommandResult, probe_username: str) -> Finding:
        if result.returncode != 0:
            return self._error(
                "server.hardening.ssh_key_permissions",
                "Blacklight could not inspect SSH key-path permissions",
                "The fixed metadata-only SSH path inspection did not complete successfully.",
                {"returncode": result.returncode, "stderr": result.stderr[:500]},
            )

        username = probe_username
        home = ""
        stat_lines: list[str] = []
        for line in result.stdout.splitlines():
            if line.startswith("BLACKLIGHT_USER="):
                username = line.split("=", 1)[1].strip() or username
            elif line.startswith("BLACKLIGHT_HOME="):
                home = line.split("=", 1)[1].strip()
            elif "|" in line:
                stat_lines.append(line)

        entries = self._parse_stat_lines("\n".join(stat_lines))
        violations: list[dict[str, Any]] = []

        for entry in entries:
            reasons: list[str] = []
            is_home = bool(home) and entry.path == home
            is_ssh_dir = bool(home) and entry.path == f"{home}/.ssh"
            is_authorized_keys = bool(home) and entry.path == f"{home}/.ssh/authorized_keys"

            if is_home and entry.mode & 0o002:
                reasons.append("home-world-writable")
            if is_ssh_dir and entry.mode & 0o022:
                reasons.append("ssh-directory-group-or-other-writable")
            if is_authorized_keys and entry.mode & 0o022:
                reasons.append("authorized-keys-group-or-other-writable")

            if (is_ssh_dir or is_authorized_keys) and entry.owner not in {username, "root"}:
                reasons.append("unexpected-owner")

            if reasons:
                violations.append({**entry.to_dict(), "reasons": reasons})

        evidence = {
            "user": username,
            "home": home or None,
            "observed": [entry.to_dict() for entry in entries],
            "violations": violations,
        }

        if violations:
            return self._finding(
                "server.hardening.ssh_key_permissions",
                Severity.HIGH,
                "SSH account paths have unsafe ownership or write permissions",
                (
                    "Blacklight observed writable or unexpectedly owned paths that can weaken "
                    "the integrity of the scanned account's SSH authentication files."
                ),
                remediation=(
                    "Remove group/other write access from the affected SSH paths and ensure the "
                    "SSH directory and authorized_keys file are owned by the account or root."
                ),
                evidence=evidence,
            )

        if not home or not entries:
            return self._finding(
                "server.hardening.ssh_key_permissions",
                Severity.INFO,
                "SSH account path metadata was not available",
                (
                    "Blacklight could not observe enough metadata for the connected account's "
                    "home and SSH paths to make a permission finding."
                ),
                evidence=evidence,
            )

        return self._finding(
            "server.hardening.ssh_key_permissions",
            Severity.PASS,
            "Observed SSH account paths are not group- or world-writable",
            (
                "The connected account's observed home and SSH authentication paths did not show "
                "the unsafe write-permission or ownership conditions Blacklight checks."
            ),
            evidence=evidence,
        )

    def _check_automatic_updates(self, result: CommandResult) -> Finding:
        if result.returncode != 0:
            return self._error(
                "server.hardening.automatic_security_updates",
                "Blacklight could not inspect automatic-update configuration",
                "The read-only package-update posture inspection did not complete successfully.",
                {"returncode": result.returncode, "stderr": result.stderr[:500]},
            )

        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if line.startswith("BLACKLIGHT_") and "=" in line:
                key, value = line.split("=", 1)
                values[key.removeprefix("BLACKLIGHT_").lower()] = value.strip()

        family = values.get("family", "unknown").lower()
        config = values.get("config", "")
        timer = values.get("timer", "").lower()

        if family == "apt":
            enabled = 'Unattended-Upgrade "1"' in config
            if enabled and timer in {"enabled", "static"}:
                return self._finding(
                    "server.hardening.automatic_security_updates",
                    Severity.PASS,
                    "Automatic APT upgrade posture is explicitly enabled",
                    (
                        "Blacklight observed APT unattended-upgrade configuration enabled and the "
                        "apt-daily-upgrade timer enabled or static."
                    ),
                    evidence={"family": family, "config": config, "timer": timer},
                )
            if 'Unattended-Upgrade "0"' in config or timer in {"disabled", "masked"}:
                return self._finding(
                    "server.hardening.automatic_security_updates",
                    Severity.MEDIUM,
                    "Automatic APT upgrade posture is explicitly disabled",
                    (
                        "Blacklight observed unattended-upgrade configuration or timer state that "
                        "explicitly disables automatic upgrade execution."
                    ),
                    remediation=(
                        "Review the host's patch-management policy and enable unattended security "
                        "updates or another documented automated patch mechanism."
                    ),
                    evidence={"family": family, "config": config, "timer": timer},
                )

        if family == "dnf":
            enabled = config.lower() in {"yes", "true", "1"}
            if enabled and timer in {"enabled", "static"}:
                return self._finding(
                    "server.hardening.automatic_security_updates",
                    Severity.PASS,
                    "Automatic DNF update installation is explicitly enabled",
                    (
                        "Blacklight observed dnf-automatic apply_updates enabled and an automatic "
                        "update timer enabled or static."
                    ),
                    evidence={"family": family, "config": config, "timer": timer},
                )
            if config.lower() in {"no", "false", "0"} or timer in {"disabled", "masked"}:
                return self._finding(
                    "server.hardening.automatic_security_updates",
                    Severity.MEDIUM,
                    "Automatic DNF update installation is explicitly disabled",
                    (
                        "Blacklight observed dnf-automatic configuration or timer state that "
                        "explicitly disables automatic update installation."
                    ),
                    remediation=(
                        "Review the host's patch-management policy and enable an approved automated "
                        "security-update mechanism."
                    ),
                    evidence={"family": family, "config": config, "timer": timer},
                )

        return self._finding(
            "server.hardening.automatic_security_updates",
            Severity.INFO,
            "Automatic security-update posture could not be confirmed",
            (
                "Blacklight did not observe a supported configuration state that proves automatic "
                "security updates are enabled or explicitly disabled. Another patch-management "
                "system may be responsible for this host."
            ),
            evidence={"family": family, "config": config, "timer": timer},
        )

    @staticmethod
    def _parse_stat_lines(output: str) -> list[FileMetadata]:
        entries: list[FileMetadata] = []
        for line in output.splitlines():
            match = _STAT_RE.match(line.strip())
            if not match:
                continue
            entries.append(
                FileMetadata(
                    path=match.group("path"),
                    mode_text=match.group("mode"),
                    owner=match.group("owner"),
                    group=match.group("group"),
                )
            )
        return entries

    def _transport_error(self, name: str, error: SSHExecutionError) -> Finding:
        return self._error(
            f"server.hardening.{name}",
            f"Blacklight could not complete the {name.replace('_', ' ')} inspection",
            "The SSH transport failed before this read-only hardening inspection completed.",
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
                "of the required local inspection tools, then retry."
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
            service="hardening",
            resource_type="linux_server",
            resource_id=self.target.resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
