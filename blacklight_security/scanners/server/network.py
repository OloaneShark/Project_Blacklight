from __future__ import annotations

import ipaddress
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


_NETWORK_PROBE_COMMAND = "printf 'BLACKLIGHT_OK\\n'; uname -s; hostname"
_LISTENING_SOCKETS_COMMAND = (
    "if command -v ss >/dev/null 2>&1; then "
    "printf 'BLACKLIGHT_TOOL=ss\\n'; ss -H -lntu; exit $?; "
    "elif command -v netstat >/dev/null 2>&1; then "
    "printf 'BLACKLIGHT_TOOL=netstat\\n'; netstat -lntu; exit $?; "
    "else printf 'BLACKLIGHT_TOOL=none\\n'; exit 127; fi"
)
_FIREWALL_COMMANDS = {
    "ufw": (
        "if command -v ufw >/dev/null 2>&1; then "
        "ufw status; exit $?; else exit 127; fi"
    ),
    "firewalld": (
        "if command -v firewall-cmd >/dev/null 2>&1; then "
        "firewall-cmd --state; exit $?; else exit 127; fi"
    ),
    "nftables": (
        "if command -v nft >/dev/null 2>&1; then "
        "nft list ruleset; exit $?; else exit 127; fi"
    ),
    "iptables": (
        "if command -v iptables >/dev/null 2>&1; then "
        "iptables -S; exit $?; else exit 127; fi"
    ),
}

_NFT_INPUT_HOOK_RE = re.compile(r"\\bhook\\s+(?:input|forward)\\b", re.IGNORECASE)
_IPTABLES_FILTER_RE = re.compile(
    r"^(?:-A\\s+(?:INPUT|FORWARD)\\b|-P\\s+(?:INPUT|FORWARD)\\s+DROP\\b)",
    re.MULTILINE,
)


@dataclass(frozen=True, slots=True)
class ListeningSocket:
    protocol: str
    address: str
    port: int
    scope: str

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "address": self.address,
            "port": self.port,
            "scope": self.scope,
        }


class ServerNetworkScanner:
    """Read-only host-network visibility checks for a remote Linux server."""

    def __init__(self, target: ServerScanTarget):
        self.target = target
        self.executor = target.executor or SSHCommandRunner(target)

    def scan(self) -> list[Finding]:
        try:
            probe = self.executor.run(_NETWORK_PROBE_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("network_probe", error)]

        probe_lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
        if (
            probe.returncode != 0
            or len(probe_lines) < 3
            or probe_lines[0] != "BLACKLIGHT_OK"
        ):
            return [
                self._error(
                    "server.network.platform_probe",
                    "Blacklight could not identify the remote network target",
                    "The SSH session opened, but the fixed network probe did not return the "
                    "expected platform metadata.",
                    {"returncode": probe.returncode, "stderr": probe.stderr[:500]},
                )
            ]

        platform_name, hostname = probe_lines[1:3]
        if platform_name.lower() != "linux":
            return [
                self._error(
                    "server.network.unsupported_platform",
                    "Remote network target platform is not supported",
                    "The server network scanner currently supports Linux targets only.",
                    {"platform": platform_name, "hostname": hostname},
                )
            ]

        findings: list[Finding] = []

        try:
            socket_result = self.executor.run(_LISTENING_SOCKETS_COMMAND)
        except SSHExecutionError as error:
            findings.append(self._transport_error("listening_sockets", error))
        else:
            findings.append(self._check_listening_sockets(socket_result))

        firewall_results: dict[str, CommandResult] = {}
        firewall_transport_errors: dict[str, str] = {}
        for backend, command in _FIREWALL_COMMANDS.items():
            try:
                firewall_results[backend] = self.executor.run(command)
            except SSHExecutionError as error:
                firewall_transport_errors[backend] = str(error)

        findings.append(
            self._check_firewall_controls(
                firewall_results,
                firewall_transport_errors,
            )
        )
        return findings

    def _check_listening_sockets(self, result: CommandResult) -> Finding:
        tool, body = self._socket_tool_and_body(result.stdout)
        if result.returncode != 0 or tool == "none":
            return self._error(
                "server.network.listening_sockets",
                "Blacklight could not inspect listening network sockets",
                (
                    "Neither a usable ss nor netstat inspection completed successfully on the "
                    "remote host."
                ),
                {
                    "tool": tool,
                    "returncode": result.returncode,
                    "stderr": result.stderr[:500],
                },
            )

        sockets = self._parse_sockets(tool, body)
        network_reachable = [item for item in sockets if item.scope != "loopback"]
        loopback = [item for item in sockets if item.scope == "loopback"]

        evidence = {
            "tool": tool,
            "observed_socket_count": len(sockets),
            "network_reachable_count": len(network_reachable),
            "loopback_count": len(loopback),
            "network_reachable": [item.to_dict() for item in network_reachable[:100]],
            "evidence_truncated": len(network_reachable) > 100,
        }

        if network_reachable:
            return self._finding(
                "server.network.listening_sockets",
                Severity.INFO,
                "Non-loopback listening sockets were observed",
                (
                    "One or more TCP/UDP sockets are bound beyond loopback and may be reachable "
                    "through one or more host network interfaces. This is exposure inventory, "
                    "not a claim that the service is reachable from the public internet or that "
                    "a particular application owns the port."
                ),
                evidence=evidence,
            )

        return self._finding(
            "server.network.listening_sockets",
            Severity.PASS,
            "No non-loopback listening sockets were observed",
            (
                "The available socket-inspection tool reported only loopback listeners or no "
                "TCP/UDP listening sockets."
            ),
            evidence=evidence,
        )

    def _check_firewall_controls(
        self,
        results: dict[str, CommandResult],
        transport_errors: dict[str, str],
    ) -> Finding:
        states: dict[str, str] = {}
        for backend in _FIREWALL_COMMANDS:
            if backend in transport_errors:
                states[backend] = "transport-error"
                continue
            result = results.get(backend)
            if result is None:
                states[backend] = "unavailable"
                continue
            states[backend] = self._firewall_state(backend, result)

        active_states = {"active", "input-filter-observed"}
        if any(state in active_states for state in states.values()):
            return self._finding(
                "server.network.firewall_controls",
                Severity.PASS,
                "Supported local firewall controls were observed",
                (
                    "At least one supported firewall manager reported active state or a readable "
                    "packet-filter ruleset contained INPUT/FORWARD filtering. Blacklight does not "
                    "claim that the observed rules block every unwanted connection."
                ),
                evidence={"backends": states},
            )

        uncertain_states = {"unreadable", "transport-error"}
        if any(state in uncertain_states for state in states.values()):
            return self._error(
                "server.network.firewall_controls",
                "Local firewall state could not be determined",
                (
                    "No active supported firewall control was confirmed, and at least one "
                    "installed or attempted backend could not be inspected. Blacklight therefore "
                    "cannot make a complete local-firewall assessment."
                ),
                {
                    "backends": states,
                    "transport_errors": transport_errors,
                },
            )

        if all(state == "unavailable" for state in states.values()):
            return self._error(
                "server.network.firewall_controls",
                "No supported local firewall backend was available to inspect",
                (
                    "Blacklight could not find UFW, firewalld, nftables, or iptables tooling on "
                    "the target, so host-level filtering state is unknown."
                ),
                {"backends": states},
            )

        return self._finding(
            "server.network.firewall_controls",
            Severity.MEDIUM,
            "No active supported local firewall control was observed",
            (
                "The supported firewall backends that Blacklight could inspect reported inactive "
                "state or no observed INPUT/FORWARD filtering. External controls such as cloud "
                "security groups, network firewalls, or another host firewall implementation are "
                "outside this check."
            ),
            remediation=(
                "Confirm the intended host-level filtering design. If this server should enforce "
                "a local firewall, enable and review an appropriate supported firewall policy."
            ),
            evidence={"backends": states},
        )

    @staticmethod
    def _socket_tool_and_body(output: str) -> tuple[str, str]:
        lines = output.splitlines()
        if not lines or not lines[0].startswith("BLACKLIGHT_TOOL="):
            return "unknown", output
        tool = lines[0].split("=", 1)[1].strip().lower()
        return tool, "\n".join(lines[1:])

    def _parse_sockets(self, tool: str, output: str) -> list[ListeningSocket]:
        sockets: list[ListeningSocket] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split()

            if tool == "ss":
                if len(parts) < 5:
                    continue
                protocol = parts[0].lower()
                endpoint = parts[4]
            elif tool == "netstat":
                if parts[0].lower() == "proto" or len(parts) < 4:
                    continue
                protocol = parts[0].lower()
                endpoint = parts[3]
            else:
                continue

            parsed = self._parse_endpoint(endpoint)
            if parsed is None:
                continue
            address, port = parsed
            sockets.append(
                ListeningSocket(
                    protocol=protocol,
                    address=address,
                    port=port,
                    scope=self._address_scope(address),
                )
            )
        return sockets

    @staticmethod
    def _parse_endpoint(endpoint: str) -> tuple[str, int] | None:
        value = endpoint.strip()
        if not value or ":" not in value:
            return None

        if value.startswith("[") and "]:" in value:
            address, port_text = value[1:].rsplit("]:", 1)
        else:
            address, port_text = value.rsplit(":", 1)

        if not port_text.isdigit():
            return None

        address = address.strip("[]")
        if "%" in address:
            address = address.split("%", 1)[0]
        return address or "*", int(port_text)

    @staticmethod
    def _address_scope(address: str) -> str:
        normalized = address.strip().lower()
        if normalized in {"*", "0.0.0.0", "::"}:
            return "all_interfaces"
        if normalized == "localhost":
            return "loopback"
        try:
            parsed = ipaddress.ip_address(normalized)
        except ValueError:
            return "non_loopback"
        return "loopback" if parsed.is_loopback else "non_loopback"

    @staticmethod
    def _firewall_state(backend: str, result: CommandResult) -> str:
        combined = "\n".join(value for value in (result.stdout, result.stderr) if value).strip()
        lowered = combined.lower()

        if result.returncode == 127:
            return "unavailable"

        if backend == "ufw":
            if "status: active" in lowered:
                return "active"
            if "status: inactive" in lowered:
                return "inactive"
            return "unreadable" if result.returncode != 0 else "unknown"

        if backend == "firewalld":
            if "not running" in lowered:
                return "inactive"
            if result.returncode == 0 and "running" in lowered:
                return "active"
            return "unreadable" if result.returncode != 0 else "unknown"

        if backend == "nftables":
            if result.returncode != 0:
                return "unreadable"
            if _NFT_INPUT_HOOK_RE.search(result.stdout):
                return "input-filter-observed"
            return "no-input-filter-observed"

        if backend == "iptables":
            if result.returncode != 0:
                return "unreadable"
            if _IPTABLES_FILTER_RE.search(result.stdout):
                return "input-filter-observed"
            return "no-input-filter-observed"

        return "unknown"

    def _transport_error(self, name: str, error: SSHExecutionError) -> Finding:
        return self._error(
            f"server.network.{name}",
            f"Blacklight could not complete the {name.replace('_', ' ')} inspection",
            "The SSH transport failed before this read-only network inspection completed.",
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
            service="network",
            resource_type="linux_server",
            resource_id=self.target.resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
