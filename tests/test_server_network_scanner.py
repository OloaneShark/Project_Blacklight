from __future__ import annotations

from blacklight_security.models import Severity
from blacklight_security.scanners.server.linux import CommandResult, ServerScanTarget
from blacklight_security.scanners.server.network import ServerNetworkScanner


class SequenceExecutor:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []

    def run(self, command):
        self.commands.append(command)
        return self.results.pop(0)


def _scan_with(*results):
    executor = SequenceExecutor(results)
    target = ServerScanTarget(host="server.example", user="audit", executor=executor)
    return ServerNetworkScanner(target).scan()


def _by_id(findings):
    return {finding.check_id: finding for finding in findings}


def test_network_scanner_inventories_non_loopback_sockets_and_active_ufw():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_TOOL=ss\n"
            "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
            "tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"
            "udp UNCONN 0 0 [::]:5353 [::]:*",
            "",
        ),
        CommandResult(0, "Status: active", ""),
        CommandResult(127, "", ""),
        CommandResult(127, "", ""),
        CommandResult(127, "", ""),
    )

    findings_by_id = _by_id(findings)
    sockets = findings_by_id["server.network.listening_sockets"]
    firewall = findings_by_id["server.network.firewall_controls"]

    assert sockets.severity is Severity.INFO
    assert sockets.evidence["observed_socket_count"] == 3
    assert sockets.evidence["network_reachable_count"] == 2
    assert sockets.evidence["loopback_count"] == 1
    assert sockets.evidence["network_reachable"][0]["port"] == 22
    assert sockets.evidence["network_reachable"][0]["scope"] == "all_interfaces"
    assert firewall.severity is Severity.PASS
    assert firewall.evidence["backends"]["ufw"] == "active"


def test_network_scanner_reports_medium_when_supported_firewalls_show_no_input_filter():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_TOOL=ss\n"
            "tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*",
            "",
        ),
        CommandResult(0, "Status: inactive", ""),
        CommandResult(252, "", "not running"),
        CommandResult(0, "table inet local { }", ""),
        CommandResult(0, "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT", ""),
    )

    findings_by_id = _by_id(findings)
    assert findings_by_id["server.network.listening_sockets"].severity is Severity.PASS

    firewall = findings_by_id["server.network.firewall_controls"]
    assert firewall.severity is Severity.MEDIUM
    assert firewall.evidence["backends"] == {
        "ufw": "inactive",
        "firewalld": "inactive",
        "nftables": "no-input-filter-observed",
        "iptables": "no-input-filter-observed",
    }


def test_network_scanner_marks_firewall_state_unknown_when_backend_is_unreadable():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "BLACKLIGHT_TOOL=ss", ""),
        CommandResult(1, "", "ERROR: You need to be root to run this script"),
        CommandResult(127, "", ""),
        CommandResult(127, "", ""),
        CommandResult(127, "", ""),
    )

    firewall = _by_id(findings)["server.network.firewall_controls"]
    assert firewall.severity is Severity.ERROR
    assert firewall.evidence["backends"]["ufw"] == "unreadable"


def test_network_scanner_marks_socket_coverage_gap_when_no_socket_tool_exists():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(127, "BLACKLIGHT_TOOL=none", ""),
        CommandResult(0, "Status: active", ""),
        CommandResult(127, "", ""),
        CommandResult(127, "", ""),
        CommandResult(127, "", ""),
    )

    findings_by_id = _by_id(findings)
    assert findings_by_id["server.network.listening_sockets"].severity is Severity.ERROR
    assert findings_by_id["server.network.firewall_controls"].severity is Severity.PASS


def test_network_scanner_accepts_nft_input_hook_as_observed_filtering():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "BLACKLIGHT_TOOL=ss", ""),
        CommandResult(127, "", ""),
        CommandResult(127, "", ""),
        CommandResult(
            0,
            "table inet filter {\n"
            " chain input {\n"
            "  type filter hook input priority filter; policy drop;\n"
            " }\n"
            "}",
            "",
        ),
        CommandResult(127, "", ""),
    )

    firewall = _by_id(findings)["server.network.firewall_controls"]
    assert firewall.severity is Severity.PASS
    assert firewall.evidence["backends"]["nftables"] == "input-filter-observed"


def test_network_scanner_parses_netstat_ipv4_and_ipv6_bindings():
    scanner = ServerNetworkScanner(ServerScanTarget(host="server.example"))
    sockets = scanner._parse_sockets(
        "netstat",
        "Proto Recv-Q Send-Q Local Address Foreign Address State\n"
        "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN\n"
        "tcp6 0 0 :::443 :::* LISTEN\n"
        "tcp 0 0 127.0.0.1:5432 0.0.0.0:* LISTEN",
    )

    assert [(item.address, item.port, item.scope) for item in sockets] == [
        ("0.0.0.0", 22, "all_interfaces"),
        ("::", 443, "all_interfaces"),
        ("127.0.0.1", 5432, "loopback"),
    ]


def test_network_scanner_rejects_non_linux_target():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nFreeBSD\nedge-1", "")
    )

    assert len(findings) == 1
    assert findings[0].severity is Severity.ERROR
    assert findings[0].check_id == "server.network.unsupported_platform"
