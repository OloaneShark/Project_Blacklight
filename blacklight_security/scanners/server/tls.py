from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.server.linux import (
    CommandResult,
    SSHCommandRunner,
    SSHExecutionError,
    ServerScanTarget,
)


_TLS_PROBE_COMMAND = "printf 'BLACKLIGHT_OK\\n'; uname -s; hostname"
_TLS_INVENTORY_COMMAND = (
    "if ! command -v openssl >/dev/null 2>&1; then "
    "printf 'BLACKLIGHT_OPENSSL=missing\\n'; exit 0; fi; "
    "if ! command -v timeout >/dev/null 2>&1; then "
    "printf 'BLACKLIGHT_TIMEOUT=missing\\n'; exit 0; fi; "
    "printf 'BLACKLIGHT_OPENSSL=present\\nBLACKLIGHT_TIMEOUT=present\\n'; "
    "h=$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf localhost); "
    "if command -v ss >/dev/null 2>&1; then "
    "ports=$(ss -H -ltn 2>/dev/null | awk '{n=split($4,a,\":\"); print a[n]}'); "
    "printf 'BLACKLIGHT_LISTENER_BACKEND=ss\\n'; "
    "elif command -v netstat >/dev/null 2>&1; then "
    "ports=$(netstat -lnt 2>/dev/null | awk 'NR>2 {n=split($4,a,\":\"); print a[n]}'); "
    "printf 'BLACKLIGHT_LISTENER_BACKEND=netstat\\n'; "
    "else printf 'BLACKLIGHT_LISTENER_BACKEND=missing\\n'; exit 0; fi; "
    "for p in 443 465 636 993 995 2376 3269 6443 8443 9443; do "
    "printf '%s\\n' \"$ports\" | grep -qx \"$p\" || continue; "
    "printf 'BLACKLIGHT_TLS_PORT=%s\\n' \"$p\"; "
    "out=$(timeout 5 openssl s_client -connect 127.0.0.1:\"$p\" "
    "-servername \"$h\" -showcerts </dev/null 2>/dev/null | "
    "openssl x509 -noout -subject -issuer -startdate -enddate -fingerprint -sha256 "
    "2>/dev/null); "
    "if [ -z \"$out\" ]; then "
    "printf 'BLACKLIGHT_TLS_NO_CERT=%s\\n' \"$p\"; continue; fi; "
    "printf '%s\\n' \"$out\" | while IFS= read -r line; do "
    "printf 'BLACKLIGHT_TLS_META=%s|%s\\n' \"$p\" \"$line\"; done; "
    "done"
)


@dataclass(frozen=True, slots=True)
class TLSCertificate:
    port: int
    subject: str
    issuer: str
    not_before: datetime | None
    not_after: datetime | None
    fingerprint_sha256: str | None

    @property
    def self_signed(self) -> bool:
        return bool(self.subject and self.issuer and self.subject == self.issuer)


class ServerTLSScanner:
    """Non-mutating localhost TLS certificate posture for common server ports."""

    def __init__(self, target: ServerScanTarget):
        self.target = target
        self.executor = target.executor or SSHCommandRunner(target)

    def scan(self) -> list[Finding]:
        try:
            probe = self.executor.run(_TLS_PROBE_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("tls_probe", error)]

        lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
        if probe.returncode != 0 or len(lines) < 3 or lines[0] != "BLACKLIGHT_OK":
            return [
                self._error(
                    "server.tls.platform_probe",
                    "Blacklight could not identify the remote TLS target",
                    "The SSH session opened, but the fixed TLS probe did not return expected metadata.",
                    {"returncode": probe.returncode, "stderr": probe.stderr[:500]},
                )
            ]

        if lines[1].lower() != "linux":
            return [
                self._error(
                    "server.tls.unsupported_platform",
                    "Remote TLS target platform is not supported",
                    "The server TLS scanner currently supports Linux targets only.",
                    {"platform": lines[1], "hostname": lines[2]},
                )
            ]

        try:
            result = self.executor.run(_TLS_INVENTORY_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("certificate_inventory", error)]

        return self._check_tls(result)

    def _check_tls(self, result: CommandResult) -> list[Finding]:
        if result.returncode != 0:
            return [
                self._error(
                    "server.tls.certificate_inventory",
                    "Blacklight could not inspect local TLS certificate posture",
                    "The fixed non-mutating localhost TLS inspection did not complete successfully.",
                    {"returncode": result.returncode, "stderr": result.stderr[:500]},
                )
            ]

        openssl = "unknown"
        timeout_tool = "unknown"
        listener_backend = "unknown"
        observed_ports: set[int] = set()
        no_certificate: set[int] = set()
        metadata: dict[int, dict[str, str]] = {}

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BLACKLIGHT_OPENSSL="):
                openssl = line.split("=", 1)[1].strip().lower()
            elif line.startswith("BLACKLIGHT_TIMEOUT="):
                timeout_tool = line.split("=", 1)[1].strip().lower()
            elif line.startswith("BLACKLIGHT_LISTENER_BACKEND="):
                listener_backend = line.split("=", 1)[1].strip().lower()
            elif line.startswith("BLACKLIGHT_TLS_PORT="):
                value = line.split("=", 1)[1].strip()
                if value.isdigit():
                    observed_ports.add(int(value))
            elif line.startswith("BLACKLIGHT_TLS_NO_CERT="):
                value = line.split("=", 1)[1].strip()
                if value.isdigit():
                    no_certificate.add(int(value))
            elif line.startswith("BLACKLIGHT_TLS_META="):
                payload = line.split("=", 1)[1]
                if "|" not in payload:
                    continue
                port_text, item = payload.split("|", 1)
                if not port_text.isdigit():
                    continue
                port = int(port_text)
                bucket = metadata.setdefault(port, {})
                if item.startswith("subject="):
                    bucket["subject"] = item.split("=", 1)[1].strip()
                elif item.startswith("issuer="):
                    bucket["issuer"] = item.split("=", 1)[1].strip()
                elif item.startswith("notBefore="):
                    bucket["not_before"] = item.split("=", 1)[1].strip()
                elif item.startswith("notAfter="):
                    bucket["not_after"] = item.split("=", 1)[1].strip()
                elif "Fingerprint=" in item:
                    bucket["fingerprint_sha256"] = item.split("=", 1)[1].strip()

        if openssl == "missing":
            return [
                self._finding(
                    "server.tls.certificate_inventory",
                    Severity.INFO,
                    "OpenSSL is not available for local TLS certificate inspection",
                    "Blacklight did not attempt certificate posture checks without the openssl client.",
                    evidence={"openssl_available": False},
                )
            ]

        if timeout_tool == "missing":
            return [
                self._finding(
                    "server.tls.certificate_inventory",
                    Severity.INFO,
                    "Safe TLS handshake timeout tooling is not available",
                    (
                        "Blacklight requires the timeout command before making localhost TLS "
                        "handshakes so a non-responsive service cannot stall the scan."
                    ),
                    evidence={"timeout_available": False},
                )
            ]

        if listener_backend == "missing":
            return [
                self._finding(
                    "server.tls.certificate_inventory",
                    Severity.INFO,
                    "Listening TCP port inventory is not available for TLS inspection",
                    "Neither ss nor netstat was available to identify common TLS ports already listening.",
                )
            ]

        if not observed_ports:
            return [
                self._finding(
                    "server.tls.certificate_inventory",
                    Severity.INFO,
                    "No selected common TLS port was observed listening",
                    (
                        "Blacklight checks a fixed set of common TLS ports and did not observe any "
                        "of them in the local TCP listener inventory."
                    ),
                    evidence={
                        "ports_checked": [443, 465, 636, 993, 995, 2376, 3269, 6443, 8443, 9443],
                        "listener_backend": listener_backend,
                    },
                )
            ]

        certificates = [
            self._certificate_from_metadata(port, metadata.get(port, {}))
            for port in sorted(observed_ports - no_certificate)
            if metadata.get(port)
        ]

        findings: list[Finding] = []
        for cert in certificates:
            findings.append(self._certificate_finding(cert))

        if no_certificate:
            findings.append(
                self._finding(
                    "server.tls.unverified_listener",
                    Severity.INFO,
                    "Common TLS-designated listener did not return a parseable certificate",
                    (
                        "A selected common TLS port was listening, but Blacklight could not parse "
                        "an X.509 certificate from a localhost TLS handshake. The service may be "
                        "non-TLS, require different SNI, bind only to another address, or reject "
                        "the probe."
                    ),
                    evidence={"ports": sorted(no_certificate)},
                )
            )

        if not certificates and not no_certificate:
            findings.append(
                self._finding(
                    "server.tls.certificate_inventory",
                    Severity.INFO,
                    "TLS certificate metadata was not observed",
                    "Selected common TLS listeners were present, but no certificate metadata was returned.",
                    evidence={"ports": sorted(observed_ports)},
                )
            )
        return findings

    def _certificate_finding(self, cert: TLSCertificate) -> Finding:
        now = datetime.now(timezone.utc)
        days_remaining: int | None = None
        if cert.not_after is not None:
            days_remaining = int((cert.not_after - now).total_seconds() // 86400)

        evidence = {
            "port": cert.port,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "not_before": cert.not_before.isoformat() if cert.not_before else None,
            "not_after": cert.not_after.isoformat() if cert.not_after else None,
            "days_remaining": days_remaining,
            "self_signed": cert.self_signed,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "hostname_match_evaluated": False,
        }

        if days_remaining is not None and days_remaining < 0:
            return self._finding(
                "server.tls.certificate_expiry",
                Severity.HIGH,
                f"TLS certificate on local port {cert.port} is expired",
                "The certificate returned by the localhost TLS handshake is past its notAfter time.",
                remediation="Replace or renew the expired certificate and restart/reload the service safely.",
                evidence=evidence,
            )

        if days_remaining is not None and days_remaining <= 30:
            return self._finding(
                "server.tls.certificate_expiry",
                Severity.MEDIUM,
                f"TLS certificate on local port {cert.port} expires soon",
                "The observed certificate expires within 30 days.",
                remediation="Schedule certificate renewal before the reported notAfter time.",
                evidence=evidence,
            )

        if cert.not_after is None:
            severity = Severity.INFO
            title = f"TLS certificate expiry on local port {cert.port} could not be parsed"
        else:
            severity = Severity.PASS
            title = f"TLS certificate on local port {cert.port} is not near expiry"

        finding = self._finding(
            "server.tls.certificate_expiry",
            severity,
            title,
            (
                "Blacklight parsed the certificate returned by a localhost TLS handshake. "
                "Hostname validation is intentionally not inferred from the host's local name."
            ),
            evidence=evidence,
        )

        if cert.self_signed:
            return self._finding(
                "server.tls.self_signed_certificate",
                Severity.INFO,
                f"TLS certificate on local port {cert.port} is self-signed",
                (
                    "The observed certificate subject and issuer are identical. Self-signed "
                    "certificates can be intentional for private systems, so this is inventory "
                    "rather than an automatic security failure."
                ),
                evidence=evidence,
            )
        return finding

    @staticmethod
    def _certificate_from_metadata(port: int, metadata: dict[str, str]) -> TLSCertificate:
        return TLSCertificate(
            port=port,
            subject=metadata.get("subject", ""),
            issuer=metadata.get("issuer", ""),
            not_before=ServerTLSScanner._parse_certificate_time(metadata.get("not_before")),
            not_after=ServerTLSScanner._parse_certificate_time(metadata.get("not_after")),
            fingerprint_sha256=metadata.get("fingerprint_sha256"),
        )

    @staticmethod
    def _parse_certificate_time(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _transport_error(self, name: str, error: SSHExecutionError) -> Finding:
        return self._error(
            f"server.tls.{name}",
            f"Blacklight could not complete the {name.replace('_', ' ')} inspection",
            "The SSH transport failed before this TLS posture inspection completed.",
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
            remediation="Verify SSH connectivity and local TLS inspection tooling, then retry.",
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
            service="tls",
            resource_type="linux_server",
            resource_id=self.target.resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
