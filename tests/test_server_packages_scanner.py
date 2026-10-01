from __future__ import annotations

from blacklight_security.models import Severity
from blacklight_security.scanners.server.linux import CommandResult, ServerScanTarget
from blacklight_security.scanners.server.packages import ServerPackagesScanner


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
    return ServerPackagesScanner(target).scan()


def _by_id(findings):
    return {finding.check_id: finding for finding in findings}


def test_apt_package_scanner_reports_cached_security_updates_without_refreshing():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "apt", ""),
        CommandResult(
            0,
            "BLACKLIGHT_FAMILY=apt\n"
            "BLACKLIGHT_CACHE_AGE=3600\n"
            "BLACKLIGHT_RC=0\n"
            "BLACKLIGHT_UPDATE=Inst openssl [3.0.1] (3.0.2 Ubuntu:24.04/noble-security [amd64])\n"
            "BLACKLIGHT_UPDATE=Inst curl [8.0] (8.1 Ubuntu:24.04/noble-updates [amd64])",
            "",
        ),
    )

    by_id = _by_id(findings)
    assert by_id["server.packages.pending_updates"].severity is Severity.INFO
    assert by_id["server.packages.pending_updates"].evidence["pending_count"] == 2
    assert by_id["server.packages.pending_updates"].evidence["repository_metadata_refreshed"] is False

    security = by_id["server.packages.security_updates"]
    assert security.severity is Severity.MEDIUM
    assert security.evidence["security_update_count"] == 1
    assert security.evidence["packages"][0]["package"] == "openssl"


def test_dnf_package_scanner_accepts_check_update_exit_100():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "dnf", ""),
        CommandResult(
            0,
            "BLACKLIGHT_FAMILY=dnf\n"
            "BLACKLIGHT_RC=100\n"
            "BLACKLIGHT_UPDATE=openssl.x86_64 3.2.1-4.el9 baseos\n"
            "BLACKLIGHT_UPDATE=curl.x86_64 8.0.1-2.el9 appstream",
            "",
        ),
    )

    by_id = _by_id(findings)
    assert by_id["server.packages.pending_updates"].severity is Severity.INFO
    assert by_id["server.packages.pending_updates"].evidence["pending_count"] == 2
    assert by_id["server.packages.security_updates"].severity is Severity.INFO


def test_package_scanner_reports_error_when_cached_package_command_fails():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "apt", ""),
        CommandResult(
            0,
            "BLACKLIGHT_FAMILY=apt\nBLACKLIGHT_CACHE_AGE=unknown\nBLACKLIGHT_RC=100",
            "",
        ),
    )

    assert len(findings) == 1
    assert findings[0].check_id == "server.packages.pending_updates"
    assert findings[0].severity is Severity.ERROR


def test_package_scanner_reports_info_when_no_supported_manager_exists():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "none", ""),
    )

    assert len(findings) == 1
    assert findings[0].check_id == "server.packages.package_manager"
    assert findings[0].severity is Severity.INFO
