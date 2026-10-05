from __future__ import annotations

from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.server.linux import (
    CommandResult,
    SSHCommandRunner,
    SSHExecutionError,
    ServerScanTarget,
)


_SSHD_PROBE_COMMAND = "printf 'BLACKLIGHT_OK\\n'; uname -s; hostname"
_SSHD_EFFECTIVE_COMMAND = (
    "if ! command -v sshd >/dev/null 2>&1; then "
    "printf 'BLACKLIGHT_SSHD_BACKEND=missing\\n'; exit 0; fi; "
    "printf 'BLACKLIGHT_SSHD_BACKEND=openssh\\n'; "
    "u=$(id -un 2>/dev/null || printf nobody); "
    "h=$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf localhost); "
    "out=$(sshd -T -C user=\"$u\",host=\"$h\",addr=127.0.0.1 2>&1); rc=$?; "
    "printf 'BLACKLIGHT_SSHD_RC=%s\\n' \"$rc\"; "
    "if [ \"$rc\" -ne 0 ]; then "
    "printf 'BLACKLIGHT_SSHD_ERROR=%s\\n' \"$(printf '%s' \"$out\" | head -c 500)\"; "
    "exit 0; fi; "
    "printf '%s\\n' \"$out\" | awk '"
    "$1 ~ /^(strictmodes|gatewayports|allowtcpforwarding|permituserenvironment|"
    "hostbasedauthentication|ciphers|macs|kexalgorithms|hostkeyalgorithms|"
    "pubkeyacceptedalgorithms)$/ "
    "{print \"BLACKLIGHT_SSHD=\" $0}'"
)

_WEAK_CIPHERS = {
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
}
_WEAK_MACS = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-sha1-96",
    "hmac-sha1-96-etm@openssh.com",
}
_WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha1",
}
_WEAK_HOSTKEY = {"ssh-dss", "ssh-rsa"}


class ServerSSHDEffectiveScanner:
    """Read-only OpenSSH effective configuration checks using sshd -T."""

    def __init__(self, target: ServerScanTarget):
        self.target = target
        self.executor = target.executor or SSHCommandRunner(target)

    def scan(self) -> list[Finding]:
        try:
            probe = self.executor.run(_SSHD_PROBE_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("sshd_probe", error)]

        lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
        if probe.returncode != 0 or len(lines) < 3 or lines[0] != "BLACKLIGHT_OK":
            return [
                self._error(
                    "server.sshd.platform_probe",
                    "Blacklight could not identify the remote OpenSSH target",
                    "The SSH session opened, but the fixed sshd probe did not return expected metadata.",
                    {"returncode": probe.returncode, "stderr": probe.stderr[:500]},
                )
            ]

        if lines[1].lower() != "linux":
            return [
                self._error(
                    "server.sshd.unsupported_platform",
                    "Remote OpenSSH target platform is not supported",
                    "The effective sshd scanner currently supports Linux targets only.",
                    {"platform": lines[1], "hostname": lines[2]},
                )
            ]

        try:
            result = self.executor.run(_SSHD_EFFECTIVE_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("effective_config", error)]

        return self._check_effective_config(result)

    def _check_effective_config(self, result: CommandResult) -> list[Finding]:
        if result.returncode != 0:
            return [
                self._error(
                    "server.sshd.effective_config",
                    "Blacklight could not run the effective OpenSSH inspection",
                    "The fixed read-only sshd inspection command did not complete successfully.",
                    {"returncode": result.returncode, "stderr": result.stderr[:500]},
                )
            ]

        backend = "unknown"
        sshd_rc: int | None = None
        sshd_error = ""
        settings: dict[str, str] = {}

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BLACKLIGHT_SSHD_BACKEND="):
                backend = line.split("=", 1)[1].strip().lower()
            elif line.startswith("BLACKLIGHT_SSHD_RC="):
                value = line.split("=", 1)[1].strip()
                if value.isdigit():
                    sshd_rc = int(value)
            elif line.startswith("BLACKLIGHT_SSHD_ERROR="):
                sshd_error = line.split("=", 1)[1].strip()
            elif line.startswith("BLACKLIGHT_SSHD="):
                payload = line.split("=", 1)[1].strip()
                if " " not in payload:
                    continue
                key, value = payload.split(None, 1)
                settings[key.lower()] = value.strip().lower()

        if backend == "missing":
            return [
                self._finding(
                    "server.sshd.effective_config",
                    Severity.INFO,
                    "OpenSSH sshd effective-configuration backend is not available",
                    (
                        "The host accepted SSH, but the sshd executable used for OpenSSH "
                        "effective-configuration evaluation was not available in the audit "
                        "account's command path. Blacklight did not infer effective settings."
                    ),
                    evidence={"backend": "sshd", "available": False},
                )
            ]

        if sshd_rc != 0:
            return [
                self._error(
                    "server.sshd.effective_config",
                    "OpenSSH effective configuration could not be evaluated",
                    (
                        "Blacklight attempted read-only sshd -T evaluation, but sshd could not "
                        "produce effective configuration for the connected audit context."
                    ),
                    {
                        "backend": backend,
                        "sshd_returncode": sshd_rc,
                        "error": sshd_error[:500],
                    },
                )
            ]

        if not settings:
            return [
                self._error(
                    "server.sshd.effective_config",
                    "OpenSSH effective configuration returned no selected settings",
                    "sshd -T completed, but Blacklight did not receive the settings it evaluates.",
                    {"backend": backend},
                )
            ]

        return [
            self._check_weak_crypto(settings),
            self._check_strict_modes(settings),
            self._check_gateway_ports(settings),
            self._check_user_environment(settings),
            self._check_hostbased_auth(settings),
        ]

    def _check_weak_crypto(self, settings: dict[str, str]) -> Finding:
        ciphers = self._csv_values(settings.get("ciphers"))
        macs = self._csv_values(settings.get("macs"))
        kex = self._csv_values(settings.get("kexalgorithms"))
        hostkeys = self._csv_values(settings.get("hostkeyalgorithms"))
        pubkeys = self._csv_values(settings.get("pubkeyacceptedalgorithms"))

        weak = {
            "ciphers": sorted(ciphers & _WEAK_CIPHERS),
            "macs": sorted(macs & _WEAK_MACS),
            "kex_algorithms": sorted(kex & _WEAK_KEX),
            "hostkey_algorithms": sorted(hostkeys & _WEAK_HOSTKEY),
            "pubkey_algorithms": sorted(pubkeys & _WEAK_HOSTKEY),
        }
        present = {key: value for key, value in weak.items() if value}

        if present:
            return self._finding(
                "server.sshd.weak_crypto",
                Severity.MEDIUM,
                "OpenSSH effective configuration enables legacy cryptographic algorithms",
                (
                    "sshd -T reports one or more selected legacy cipher, MAC, key-exchange, "
                    "host-key, or public-key algorithms. Blacklight reports only algorithms "
                    "explicitly present in the effective OpenSSH lists."
                ),
                remediation=(
                    "Remove legacy algorithms from the relevant OpenSSH algorithm lists after "
                    "confirming client compatibility."
                ),
                evidence={"weak_algorithms": present},
            )

        return self._finding(
            "server.sshd.weak_crypto",
            Severity.PASS,
            "No selected legacy OpenSSH algorithms were observed",
            "The effective algorithm lists did not contain Blacklight's selected legacy algorithms.",
        )

    def _check_strict_modes(self, settings: dict[str, str]) -> Finding:
        value = settings.get("strictmodes")
        if value == "no":
            return self._finding(
                "server.sshd.strict_modes",
                Severity.MEDIUM,
                "OpenSSH StrictModes is disabled",
                (
                    "The effective sshd configuration disables ownership and mode checks for "
                    "user files/home paths used during authentication."
                ),
                remediation="Set StrictModes yes unless a documented compatibility requirement prevents it.",
                evidence={"strictmodes": value},
            )
        return self._observed_or_unknown(
            "server.sshd.strict_modes",
            value,
            "OpenSSH StrictModes is enabled",
            {"strictmodes": value},
        )

    def _check_gateway_ports(self, settings: dict[str, str]) -> Finding:
        gateway = settings.get("gatewayports")
        forwarding = settings.get("allowtcpforwarding")
        risky_gateway = gateway in {"yes", "clientspecified"}
        remote_forwarding_allowed = forwarding in {"yes", "all", "remote"}

        if risky_gateway and remote_forwarding_allowed:
            return self._finding(
                "server.sshd.gateway_ports",
                Severity.MEDIUM,
                "OpenSSH remote forwarding can expose non-loopback listeners",
                (
                    "The effective sshd configuration allows remote TCP forwarding while "
                    "GatewayPorts permits forwarded listeners beyond loopback."
                ),
                remediation=(
                    "Set GatewayPorts no or restrict TCP forwarding unless non-loopback remote "
                    "forwarding is an intentional administrative requirement."
                ),
                evidence={
                    "gatewayports": gateway,
                    "allowtcpforwarding": forwarding,
                },
            )

        if gateway is None or forwarding is None:
            return self._finding(
                "server.sshd.gateway_ports",
                Severity.INFO,
                "OpenSSH forwarding exposure could not be fully evaluated",
                "One or more required effective forwarding settings were not returned.",
                evidence={
                    "gatewayports": gateway,
                    "allowtcpforwarding": forwarding,
                },
            )

        return self._finding(
            "server.sshd.gateway_ports",
            Severity.PASS,
            "Effective OpenSSH forwarding settings do not expose GatewayPorts condition",
            (
                "Blacklight did not observe the combination of remote TCP forwarding and "
                "non-loopback GatewayPorts that this check targets."
            ),
            evidence={
                "gatewayports": gateway,
                "allowtcpforwarding": forwarding,
            },
        )

    def _check_user_environment(self, settings: dict[str, str]) -> Finding:
        value = settings.get("permituserenvironment")
        if value == "yes":
            return self._finding(
                "server.sshd.user_environment",
                Severity.MEDIUM,
                "OpenSSH PermitUserEnvironment is enabled",
                (
                    "The effective sshd configuration permits user-controlled environment "
                    "settings during login, which can weaken environment-based security "
                    "assumptions in some deployments."
                ),
                remediation="Set PermitUserEnvironment no unless it is explicitly required.",
                evidence={"permituserenvironment": value},
            )
        return self._observed_or_unknown(
            "server.sshd.user_environment",
            value,
            "OpenSSH PermitUserEnvironment is disabled",
            {"permituserenvironment": value},
        )

    def _check_hostbased_auth(self, settings: dict[str, str]) -> Finding:
        value = settings.get("hostbasedauthentication")
        if value == "yes":
            return self._finding(
                "server.sshd.hostbased_authentication",
                Severity.MEDIUM,
                "OpenSSH host-based authentication is enabled",
                (
                    "The effective sshd configuration accepts host-based authentication. This "
                    "trust model should be enabled only when host keys and trust relationships are "
                    "explicitly managed."
                ),
                remediation="Set HostbasedAuthentication no unless managed host trust is required.",
                evidence={"hostbasedauthentication": value},
            )
        return self._observed_or_unknown(
            "server.sshd.hostbased_authentication",
            value,
            "OpenSSH host-based authentication is disabled",
            {"hostbasedauthentication": value},
        )

    def _observed_or_unknown(
        self,
        check_id: str,
        value: str | None,
        pass_title: str,
        evidence: dict[str, Any],
    ) -> Finding:
        if value is None:
            return self._finding(
                check_id,
                Severity.INFO,
                "OpenSSH effective setting was not returned",
                "Blacklight did not infer a value absent from the selected sshd -T output.",
                evidence=evidence,
            )
        return self._finding(
            check_id,
            Severity.PASS,
            pass_title,
            "The effective OpenSSH value does not match the insecure state targeted by this check.",
            evidence=evidence,
        )

    @staticmethod
    def _csv_values(value: str | None) -> set[str]:
        if not value:
            return set()
        return {item.strip().lower() for item in value.split(",") if item.strip()}

    def _transport_error(self, name: str, error: SSHExecutionError) -> Finding:
        return self._error(
            f"server.sshd.{name}",
            f"Blacklight could not complete the {name.replace('_', ' ')} inspection",
            "The SSH transport failed before this effective OpenSSH inspection completed.",
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
                "Verify that OpenSSH sshd is available and can evaluate its configuration "
                "read-only for the audit account, then retry."
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
            service="sshd",
            resource_type="linux_server",
            resource_id=self.target.resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
