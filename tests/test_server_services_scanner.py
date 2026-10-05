from __future__ import annotations

from blacklight_security.models import Severity
from blacklight_security.scanners.server.linux import CommandResult, ServerScanTarget
from blacklight_security.scanners.server.services import ServerServicesScanner


class SequenceExecutor:
    def __init__(self, results):
        self.results = list(results)

    def run(self, command):
        return self.results.pop(0)


def _scan_with(*results):
    target = ServerScanTarget(
        host="server.example",
        user="audit",
        executor=SequenceExecutor(results),
    )
    return ServerServicesScanner(target).scan()


def _by_id(findings):
    return {finding.check_id: finding for finding in findings}


def test_services_scanner_flags_legacy_remote_access_and_tftp():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_SYSTEMCTL=present\n"
            "BLACKLIGHT_ACTIVE=telnet.socket\n"
            "BLACKLIGHT_ACTIVE=rsh.service\n"
            "BLACKLIGHT_ACTIVE=tftp.service\n"
            "BLACKLIGHT_ACTIVE=vsftpd.service\n"
            "BLACKLIGHT_ACTIVE=xinetd.service",
            "",
        ),
    )

    by_id = _by_id(findings)
    assert by_id["server.services.legacy_remote_access"].severity is Severity.HIGH
    assert by_id["server.services.tftp"].severity is Severity.MEDIUM
    assert by_id["server.services.ftp"].severity is Severity.INFO
    assert by_id["server.services.legacy_multiplexer"].severity is Severity.INFO
    assert by_id["server.services.legacy_remote_access"].evidence["active_units"] == [
        "rsh.service",
        "telnet.socket",
    ]


def test_services_scanner_passes_selected_legacy_service_checks_when_inactive():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "BLACKLIGHT_SYSTEMCTL=present", ""),
    )

    by_id = _by_id(findings)
    assert by_id["server.services.legacy_remote_access"].severity is Severity.PASS
    assert by_id["server.services.tftp"].severity is Severity.PASS
    assert by_id["server.services.ftp"].severity is Severity.INFO
    assert by_id["server.services.legacy_multiplexer"].severity is Severity.INFO


def test_services_scanner_reports_info_without_systemctl():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "BLACKLIGHT_SYSTEMCTL=missing", ""),
    )

    assert len(findings) == 1
    assert findings[0].check_id == "server.services.inventory"
    assert findings[0].severity is Severity.INFO
