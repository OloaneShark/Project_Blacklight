from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blacklight_security.models import Finding, Severity


_PROBE_COMMAND = "printf 'BLACKLIGHT_OK\\n'; uname -s; uname -r; hostname"
_SSH_DIRECTIVES_COMMAND = (
    "for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do "
    '[ -r "$f" ] || continue; '
    "awk 'BEGIN{IGNORECASE=1} "
    "/^[[:space:]]*#/ {next} "
    "/^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords)"
    "[[:space:]]+/ {print FILENAME \":\" $0}' "
    '"$f"; '
    "done"
)
_SSH_CONFIG_MODE_COMMAND = (
    "if [ -e /etc/ssh/sshd_config ]; then "
    "stat -c '%a %U %G' /etc/ssh/sshd_config 2>/dev/null || true; "
    "fi"
)
_UID_ZERO_COMMAND = "awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null || true"
_DOCKER_SOCKET_COMMAND = (
    "if [ -S /var/run/docker.sock ]; then "
    "stat -c '%a %U %G' /var/run/docker.sock 2>/dev/null || true; "
    "fi"
)

_DIRECTIVE_RE = re.compile(
    r"^(?P<source>[^:]+):\s*(?P<key>PermitRootLogin|PasswordAuthentication|"
    r"PermitEmptyPasswords)\s+(?P<value>\S+)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class SSHExecutionError(RuntimeError):
    """Raised when Blacklight cannot establish or keep the SSH transport."""


@dataclass(slots=True)
class ServerScanTarget:
    """Remote Linux target inspected through the local OpenSSH client."""

    host: str
    user: str | None = None
    port: int = 22
    identity_file: Path | None = None
    connect_timeout: int = 10
    executor: Any | None = field(default=None, repr=False, compare=False)
    region_name: None = None
    profile_name: None = None

    def __post_init__(self) -> None:
        self.host = self.host.strip()
        if not self.host or self.host.startswith("-") or any(ch.isspace() for ch in self.host):
            raise ValueError("server host must be a non-empty hostname or IP address")
        if self.user is not None:
            self.user = self.user.strip()
            if (
                not self.user
                or self.user.startswith("-")
                or "@" in self.user
                or any(ch.isspace() for ch in self.user)
            ):
                raise ValueError("server user contains unsupported characters")
        if not 1 <= self.port <= 65535:
            raise ValueError("server SSH port must be between 1 and 65535")
        if not 1 <= self.connect_timeout <= 60:
            raise ValueError("server connect timeout must be between 1 and 60 seconds")
        if self.identity_file is not None:
            self.identity_file = Path(self.identity_file).expanduser()

    @property
    def destination(self) -> str:
        if self.user:
            return f"{self.user}@{self.host}"
        return self.host

    @property
    def resource_id(self) -> str:
        return f"{self.destination}:{self.port}"


class SSHCommandRunner:
    """Execute Blacklight's fixed read-only inspection commands through OpenSSH."""

    def __init__(self, target: ServerScanTarget):
        self.target = target

    def run(self, command: str) -> CommandResult:
        argv = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.target.connect_timeout}",
            "-p",
            str(self.target.port),
        ]
        if self.target.identity_file is not None:
            argv.extend(["-i", str(self.target.identity_file)])
        argv.extend([self.target.destination, command])

        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.target.connect_timeout + 5,
                check=False,
                shell=False,
            )
        except FileNotFoundError as error:
            raise SSHExecutionError(
                "OpenSSH client 'ssh' was not found on this system"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise SSHExecutionError(
                f"SSH inspection timed out after {self.target.connect_timeout + 5} seconds"
            ) from error

        result = CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
        )
        if result.returncode == 255:
            detail = result.stderr or "SSH transport failed"
            raise SSHExecutionError(detail)
        return result


class ServerBaselineScanner:
    """Deterministic read-only baseline checks for a remote Linux server."""

    def __init__(self, target: ServerScanTarget):
        self.target = target
        self.executor = target.executor or SSHCommandRunner(target)

    def scan(self) -> list[Finding]:
        try:
            probe = self.executor.run(_PROBE_COMMAND)
        except SSHExecutionError as error:
            return [self._connection_error(error)]

        probe_lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
        if (
            probe.returncode != 0
            or len(probe_lines) < 4
            or probe_lines[0] != "BLACKLIGHT_OK"
        ):
            return [
                self._error(
                    "server.baseline.platform_probe",
                    "Blacklight could not identify the remote server",
                    "The SSH session opened, but the fixed platform probe did not return the "
                    "expected Linux metadata.",
                    {"returncode": probe.returncode, "stderr": probe.stderr[:500]},
                )
            ]

        platform_name, kernel_release, hostname = probe_lines[1:4]
        if platform_name.lower() != "linux":
            return [
                self._error(
                    "server.baseline.unsupported_platform",
                    "Remote server platform is not supported",
                    "The first Server/SSH scanner supports Linux targets only.",
                    {
                        "platform": platform_name,
                        "kernel_release": kernel_release,
                        "hostname": hostname,
                    },
                )
            ]

        findings = [
            self._finding(
                "server.baseline.ssh_connection",
                Severity.PASS,
                "SSH connection and Linux platform probe succeeded",
                "Blacklight connected using the local OpenSSH client and confirmed a Linux target.",
                evidence={
                    "hostname": hostname,
                    "platform": platform_name,
                    "kernel_release": kernel_release,
                },
            )
        ]

        checks = [
            ("ssh_directives", _SSH_DIRECTIVES_COMMAND),
            ("ssh_config_mode", _SSH_CONFIG_MODE_COMMAND),
            ("uid_zero_accounts", _UID_ZERO_COMMAND),
            ("docker_socket", _DOCKER_SOCKET_COMMAND),
        ]
        results: dict[str, CommandResult] = {}
        for name, command in checks:
            try:
                results[name] = self.executor.run(command)
            except SSHExecutionError as error:
                findings.append(
                    self._error(
                        f"server.baseline.{name}_inspection",
                        f"Blacklight could not complete the {name.replace('_', ' ')} inspection",
                        "The SSH transport failed before this read-only inspection completed.",
                        {"error": str(error)},
                    )
                )
                return findings

        findings.extend(self._check_ssh_directives(results["ssh_directives"].stdout))
        findings.append(self._check_ssh_config_permissions(results["ssh_config_mode"].stdout))
        findings.append(self._check_uid_zero_accounts(results["uid_zero_accounts"].stdout))
        findings.append(self._check_docker_socket(results["docker_socket"].stdout))
        return findings

    def _check_ssh_directives(self, output: str) -> list[Finding]:
        observed: dict[str, list[dict[str, str]]] = {
            "permitrootlogin": [],
            "passwordauthentication": [],
            "permitemptypasswords": [],
        }
        for line in output.splitlines():
            match = _DIRECTIVE_RE.match(line.strip())
            if not match:
                continue
            observed[match.group("key").lower()].append(
                {
                    "source": match.group("source"),
                    "value": match.group("value").lower(),
                }
            )

        return [
            self._directive_finding(
                check_id="server.baseline.ssh_root_login",
                key="permitrootlogin",
                observed=observed["permitrootlogin"],
                insecure_value="yes",
                severity=Severity.HIGH,
                title="SSH configuration explicitly permits root login",
                remediation=(
                    "Set PermitRootLogin no after confirming administrators have a separate "
                    "non-root access path."
                ),
            ),
            self._directive_finding(
                check_id="server.baseline.ssh_password_authentication",
                key="passwordauthentication",
                observed=observed["passwordauthentication"],
                insecure_value="yes",
                severity=Severity.MEDIUM,
                title="SSH configuration explicitly enables password authentication",
                remediation=(
                    "Prefer public-key or centrally managed authentication and set "
                    "PasswordAuthentication no where operationally appropriate."
                ),
            ),
            self._directive_finding(
                check_id="server.baseline.ssh_empty_passwords",
                key="permitemptypasswords",
                observed=observed["permitemptypasswords"],
                insecure_value="yes",
                severity=Severity.CRITICAL,
                title="SSH configuration explicitly permits empty passwords",
                remediation="Set PermitEmptyPasswords no and ensure all accounts require authentication.",
            ),
        ]

    def _directive_finding(
        self,
        *,
        check_id: str,
        key: str,
        observed: list[dict[str, str]],
        insecure_value: str,
        severity: Severity,
        title: str,
        remediation: str,
    ) -> Finding:
        matches = [item for item in observed if item["value"] == insecure_value]
        if matches:
            return self._finding(
                check_id,
                severity,
                title,
                (
                    "Blacklight found an explicit enabling directive in readable SSH server "
                    "configuration. This is an observed configuration value, not a claim about "
                    "the final effective sshd configuration after Match blocks or external policy."
                ),
                remediation=remediation,
                evidence={"matches": matches},
            )

        return self._finding(
            check_id,
            Severity.INFO,
            f"No explicit enabling {key} directive was observed",
            (
                "Blacklight did not find the specific enabling value in the readable SSH "
                "configuration files it inspected. INFO is used instead of PASS because sshd "
                "defaults, Include order, Match blocks, or unreadable configuration can affect "
                "the final effective setting."
            ),
            evidence={"observed": observed},
        )

    def _check_ssh_config_permissions(self, output: str) -> Finding:
        parsed = self._parse_stat(output)
        if parsed is None:
            return self._finding(
                "server.baseline.ssh_config_permissions",
                Severity.INFO,
                "SSH daemon configuration permissions were not observed",
                "Blacklight could not read GNU stat metadata for /etc/ssh/sshd_config.",
            )

        mode_text, owner, group = parsed
        mode = int(mode_text, 8)
        if mode & 0o002:
            severity = Severity.HIGH
            title = "SSH daemon configuration is world-writable"
        elif mode & 0o020:
            severity = Severity.MEDIUM
            title = "SSH daemon configuration is group-writable"
        else:
            return self._finding(
                "server.baseline.ssh_config_permissions",
                Severity.PASS,
                "SSH daemon configuration is not group- or world-writable",
                "The observed /etc/ssh/sshd_config mode does not grant write permission to group or others.",
                evidence={"mode": mode_text, "owner": owner, "group": group},
            )

        return self._finding(
            "server.baseline.ssh_config_permissions",
            severity,
            title,
            "The observed /etc/ssh/sshd_config mode permits modification outside the file owner.",
            remediation=(
                "Restrict write access to the trusted owner, typically root, and review who can "
                "modify included SSH configuration files."
            ),
            evidence={"mode": mode_text, "owner": owner, "group": group},
        )

    def _check_uid_zero_accounts(self, output: str) -> Finding:
        accounts = sorted({line.strip() for line in output.splitlines() if line.strip()})
        unexpected = [account for account in accounts if account != "root"]
        if unexpected:
            return self._finding(
                "server.baseline.uid_zero_accounts",
                Severity.HIGH,
                "Additional UID 0 accounts were detected",
                "One or more accounts other than root use UID 0 and therefore have root-equivalent identity.",
                remediation="Review the listed accounts and remove unnecessary UID 0 assignments.",
                evidence={"uid_zero_accounts": accounts, "unexpected_accounts": unexpected},
            )
        if accounts == ["root"]:
            return self._finding(
                "server.baseline.uid_zero_accounts",
                Severity.PASS,
                "Only root uses UID 0",
                "The readable account database showed no additional UID 0 accounts.",
                evidence={"uid_zero_accounts": accounts},
            )
        return self._finding(
            "server.baseline.uid_zero_accounts",
            Severity.INFO,
            "UID 0 account information was not observed",
            "The read-only /etc/passwd inspection returned no UID 0 account names.",
        )

    def _check_docker_socket(self, output: str) -> Finding:
        parsed = self._parse_stat(output)
        if parsed is None:
            return self._finding(
                "server.baseline.docker_socket_permissions",
                Severity.PASS,
                "No local Docker socket was observed",
                "Blacklight did not observe /var/run/docker.sock as a Unix socket on this target.",
            )

        mode_text, owner, group = parsed
        mode = int(mode_text, 8)
        if mode & 0o002:
            return self._finding(
                "server.baseline.docker_socket_permissions",
                Severity.HIGH,
                "Docker socket is world-writable",
                (
                    "The local Docker control socket grants write permission to other users. "
                    "Docker socket write access can provide root-equivalent control of the host."
                ),
                remediation="Remove world-write permission from /var/run/docker.sock and restrict access.",
                evidence={"mode": mode_text, "owner": owner, "group": group},
            )

        return self._finding(
            "server.baseline.docker_socket_permissions",
            Severity.PASS,
            "Docker socket is not world-writable",
            "The observed Docker socket mode does not grant write access to other users.",
            evidence={"mode": mode_text, "owner": owner, "group": group},
        )

    @staticmethod
    def _parse_stat(output: str) -> tuple[str, str, str] | None:
        first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
        parts = first_line.split()
        if len(parts) < 3 or not re.fullmatch(r"[0-7]{3,4}", parts[0]):
            return None
        return parts[0], parts[1], parts[2]

    def _connection_error(self, error: SSHExecutionError) -> Finding:
        return self._error(
            "server.baseline.ssh_connection",
            "Blacklight could not establish the SSH inspection session",
            (
                "The local OpenSSH client could not connect non-interactively to the target. "
                "Blacklight does not request or store SSH passwords."
            ),
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
                "Verify SSH connectivity, host-key trust, key/agent authentication, and read "
                "access for the audit account, then retry."
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
            service="baseline",
            resource_type="linux_server",
            resource_id=self.target.resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
