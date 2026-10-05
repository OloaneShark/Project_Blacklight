from __future__ import annotations

from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.server.linux import (
    CommandResult,
    SSHCommandRunner,
    SSHExecutionError,
    ServerScanTarget,
)


_SERVICE_PROBE_COMMAND = "printf 'BLACKLIGHT_OK\\n'; uname -s; hostname"
_SERVICE_INVENTORY_COMMAND = (
    "if ! command -v systemctl >/dev/null 2>&1; then "
    "printf 'BLACKLIGHT_SYSTEMCTL=missing\\n'; exit 0; fi; "
    "printf 'BLACKLIGHT_SYSTEMCTL=present\\n'; "
    "for u in "
    "telnet.socket telnet.service "
    "rsh.socket rsh.service "
    "rlogin.socket rlogin.service "
    "rexec.socket rexec.service "
    "tftp.socket tftp.service "
    "vsftpd.service proftpd.service pure-ftpd.service "
    "xinetd.service; do "
    "s=$(systemctl is-active \"$u\" 2>/dev/null || true); "
    "[ \"$s\" = active ] && printf 'BLACKLIGHT_ACTIVE=%s\\n' \"$u\"; "
    "done"
)

_HIGH_LEGACY_REMOTE = {
    "telnet.socket",
    "telnet.service",
    "rsh.socket",
    "rsh.service",
    "rlogin.socket",
    "rlogin.service",
    "rexec.socket",
    "rexec.service",
}
_MEDIUM_CLEAR_TEXT = {"tftp.socket", "tftp.service"}
_FTP_SERVICES = {"vsftpd.service", "proftpd.service", "pure-ftpd.service"}
_REVIEW_SERVICES = {"xinetd.service"}


class ServerServicesScanner:
    """Read-only visibility into explicitly active legacy/risky Linux services."""

    def __init__(self, target: ServerScanTarget):
        self.target = target
        self.executor = target.executor or SSHCommandRunner(target)

    def scan(self) -> list[Finding]:
        try:
            probe = self.executor.run(_SERVICE_PROBE_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("service_probe", error)]

        lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
        if probe.returncode != 0 or len(lines) < 3 or lines[0] != "BLACKLIGHT_OK":
            return [
                self._error(
                    "server.services.platform_probe",
                    "Blacklight could not identify the remote service-audit target",
                    "The SSH session opened, but the fixed service probe did not return expected metadata.",
                    {"returncode": probe.returncode, "stderr": probe.stderr[:500]},
                )
            ]

        if lines[1].lower() != "linux":
            return [
                self._error(
                    "server.services.unsupported_platform",
                    "Remote service-audit target platform is not supported",
                    "The server services scanner currently supports Linux targets only.",
                    {"platform": lines[1], "hostname": lines[2]},
                )
            ]

        try:
            result = self.executor.run(_SERVICE_INVENTORY_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("service_inventory", error)]

        return self._check_services(result)

    def _check_services(self, result: CommandResult) -> list[Finding]:
        if result.returncode != 0:
            return [
                self._error(
                    "server.services.inventory",
                    "Blacklight could not inspect systemd service state",
                    "The fixed read-only service inventory did not complete successfully.",
                    {"returncode": result.returncode, "stderr": result.stderr[:500]},
                )
            ]

        systemctl = "unknown"
        active: set[str] = set()
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BLACKLIGHT_SYSTEMCTL="):
                systemctl = line.split("=", 1)[1].strip().lower()
            elif line.startswith("BLACKLIGHT_ACTIVE="):
                active.add(line.split("=", 1)[1].strip())

        if systemctl == "missing":
            return [
                self._finding(
                    "server.services.inventory",
                    Severity.INFO,
                    "systemd service-state inspection is not available",
                    (
                        "The host does not expose the systemctl command used by this scanner. "
                        "Blacklight did not infer service state from process names alone."
                    ),
                    evidence={"backend": "systemctl", "available": False},
                )
            ]

        high = sorted(active & _HIGH_LEGACY_REMOTE)
        medium = sorted(active & _MEDIUM_CLEAR_TEXT)
        ftp = sorted(active & _FTP_SERVICES)
        review = sorted(active & _REVIEW_SERVICES)

        findings: list[Finding] = []

        if high:
            findings.append(
                self._finding(
                    "server.services.legacy_remote_access",
                    Severity.HIGH,
                    "Legacy cleartext remote-access services are active",
                    (
                        "Blacklight observed active Telnet/rsh/rlogin/rexec systemd units. "
                        "These protocols are legacy remote-access mechanisms and commonly expose "
                        "credentials or session content without modern transport protection."
                    ),
                    remediation=(
                        "Disable the listed legacy remote-access units and migrate required access "
                        "to SSH or another authenticated encrypted management channel."
                    ),
                    evidence={"active_units": high},
                )
            )
        else:
            findings.append(
                self._finding(
                    "server.services.legacy_remote_access",
                    Severity.PASS,
                    "No selected legacy remote-access service was observed active",
                    "No active Telnet/rsh/rlogin/rexec unit was returned by systemctl.",
                )
            )

        if medium:
            findings.append(
                self._finding(
                    "server.services.tftp",
                    Severity.MEDIUM,
                    "TFTP service is active",
                    (
                        "Blacklight observed an active TFTP unit. TFTP provides no built-in "
                        "authentication or transport encryption, so exposure should be tightly "
                        "scoped to an intentional network segment and use case."
                    ),
                    remediation=(
                        "Disable TFTP if it is unnecessary, or constrain it with network controls "
                        "and a narrowly scoped read/write root."
                    ),
                    evidence={"active_units": medium},
                )
            )
        else:
            findings.append(
                self._finding(
                    "server.services.tftp",
                    Severity.PASS,
                    "No selected TFTP service was observed active",
                    "No active TFTP systemd unit was returned by systemctl.",
                )
            )

        findings.append(
            self._finding(
                "server.services.ftp",
                Severity.INFO,
                (
                    "FTP-capable server service is active"
                    if ftp
                    else "No selected FTP server service was observed active"
                ),
                (
                    "Blacklight observed an FTP-capable daemon. This is inventory only because "
                    "the daemon may be configured for TLS or restricted use; Blacklight does not "
                    "infer cleartext credential exposure from the unit name alone."
                    if ftp
                    else "No active vsftpd, ProFTPD, or Pure-FTPd unit was returned by systemctl."
                ),
                evidence={"active_units": ftp},
            )
        )

        findings.append(
            self._finding(
                "server.services.legacy_multiplexer",
                Severity.INFO,
                (
                    "xinetd service multiplexer is active"
                    if review
                    else "xinetd service multiplexer was not observed active"
                ),
                (
                    "xinetd can launch multiple legacy network services. Its presence is a review "
                    "signal rather than a vulnerability by itself; service definitions should be "
                    "audited separately when xinetd is active."
                    if review
                    else "No active xinetd unit was returned by systemctl."
                ),
                evidence={"active_units": review},
            )
        )
        return findings

    def _transport_error(self, name: str, error: SSHExecutionError) -> Finding:
        return self._error(
            f"server.services.{name}",
            f"Blacklight could not complete the {name.replace('_', ' ')} inspection",
            "The SSH transport failed before this read-only service inspection completed.",
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
                "Verify SSH connectivity and systemctl visibility for the audit account, then retry."
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
            service="services",
            resource_type="linux_server",
            resource_id=self.target.resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
