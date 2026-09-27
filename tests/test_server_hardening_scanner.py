from __future__ import annotations

from blacklight_security.models import Severity
from blacklight_security.scanners.server.hardening import ServerHardeningScanner
from blacklight_security.scanners.server.linux import CommandResult, ServerScanTarget


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
    return ServerHardeningScanner(target).scan()


def _by_id(findings):
    return {finding.check_id: finding for finding in findings}


def test_hardening_scanner_detects_unsafe_sensitive_and_ssh_permissions():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1\naudit", ""),
        CommandResult(
            0,
            "/etc/passwd|644|root|root\n"
            "/etc/group|644|root|root\n"
            "/etc/shadow|666|root|shadow\n"
            "/etc/sudoers|664|root|root",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_USER=audit\n"
            "BLACKLIGHT_HOME=/home/audit\n"
            "/home/audit|755|audit|audit\n"
            "/home/audit/.ssh|777|audit|audit\n"
            "/home/audit/.ssh/authorized_keys|666|audit|audit",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_FAMILY=apt\n"
            'BLACKLIGHT_CONFIG=APT::Periodic::Unattended-Upgrade "0";\n'
            "BLACKLIGHT_TIMER=disabled",
            "",
        ),
    )

    by_id = _by_id(findings)
    assert by_id["server.hardening.sensitive_file_permissions"].severity is Severity.HIGH
    assert by_id["server.hardening.ssh_key_permissions"].severity is Severity.HIGH
    assert by_id["server.hardening.automatic_security_updates"].severity is Severity.MEDIUM


def test_hardening_scanner_passes_observed_safe_permissions_and_enabled_updates():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1\naudit", ""),
        CommandResult(
            0,
            "/etc/passwd|644|root|root\n"
            "/etc/group|644|root|root\n"
            "/etc/shadow|640|root|shadow\n"
            "/etc/sudoers|440|root|root",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_USER=audit\n"
            "BLACKLIGHT_HOME=/home/audit\n"
            "/home/audit|755|audit|audit\n"
            "/home/audit/.ssh|700|audit|audit\n"
            "/home/audit/.ssh/authorized_keys|600|audit|audit",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_FAMILY=apt\n"
            'BLACKLIGHT_CONFIG=APT::Periodic::Unattended-Upgrade "1";\n'
            "BLACKLIGHT_TIMER=enabled",
            "",
        ),
    )

    by_id = _by_id(findings)
    assert by_id["server.hardening.sensitive_file_permissions"].severity is Severity.PASS
    assert by_id["server.hardening.ssh_key_permissions"].severity is Severity.PASS
    assert by_id["server.hardening.automatic_security_updates"].severity is Severity.PASS


def test_hardening_scanner_uses_info_for_unknown_patch_management():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1\naudit", ""),
        CommandResult(
            0,
            "/etc/passwd|644|root|root\n"
            "/etc/group|644|root|root\n"
            "/etc/shadow|640|root|shadow",
            "",
        ),
        CommandResult(0, "BLACKLIGHT_USER=audit\nBLACKLIGHT_HOME=/home/audit", ""),
        CommandResult(0, "BLACKLIGHT_FAMILY=unknown", ""),
    )

    by_id = _by_id(findings)
    assert by_id["server.hardening.automatic_security_updates"].severity is Severity.INFO
