from __future__ import annotations

from blacklight_security.models import Severity
from blacklight_security.scanners.server.accounts import ServerAccountsScanner
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
    return ServerAccountsScanner(target).scan()


def _by_id(findings):
    return {finding.check_id: finding for finding in findings}


def test_accounts_scanner_detects_duplicate_uid_system_shell_and_broad_privilege():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_UID_MIN=1000\n"
            "BLACKLIGHT_UID_MIN_SOURCE=login.defs\n"
            "BLACKLIGHT_SHELL=/bin/bash\n"
            "BLACKLIGHT_SHELL=/bin/sh\n"
            "BLACKLIGHT_PASSWD_BEGIN\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "backup-root:x:0:0:backup:/root:/bin/bash\n"
            "legacy-daemon:x:200:200:legacy:/srv/legacy:/bin/bash\n"
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_GROUP=sudo:x:27:alice\n"
            "BLACKLIGHT_GROUP=docker:x:999:alice",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_SUDO_READABLE=/etc/sudoers\n"
            "BLACKLIGHT_SUDO_RULE=/etc/sudoers|alice ALL=(ALL:ALL) NOPASSWD: ALL\n"
            "BLACKLIGHT_SUDO_UNREADABLE=/etc/sudoers.d/private",
            "",
        ),
    )

    by_id = _by_id(findings)
    assert by_id["server.accounts.duplicate_uids"].severity is Severity.HIGH
    assert by_id["server.accounts.system_login_shells"].severity is Severity.MEDIUM
    assert by_id["server.accounts.privileged_groups"].severity is Severity.MEDIUM
    assert by_id["server.accounts.broad_nopasswd_sudo"].severity is Severity.HIGH
    assert by_id["server.accounts.sudoers_readability"].severity is Severity.ERROR


def test_accounts_scanner_passes_clean_observed_account_state():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_UID_MIN=1000\n"
            "BLACKLIGHT_UID_MIN_SOURCE=login.defs\n"
            "BLACKLIGHT_SHELL=/bin/bash\n"
            "BLACKLIGHT_SHELL=/bin/sh\n"
            "BLACKLIGHT_PASSWD_BEGIN\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_GROUP=sudo:x:27:alice",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_SUDO_READABLE=/etc/sudoers\n"
            "BLACKLIGHT_SUDO_RULE=/etc/sudoers|alice ALL=(root) /usr/bin/systemctl status *",
            "",
        ),
    )

    by_id = _by_id(findings)
    assert by_id["server.accounts.duplicate_uids"].severity is Severity.PASS
    assert by_id["server.accounts.system_login_shells"].severity is Severity.PASS
    assert by_id["server.accounts.privileged_groups"].severity is Severity.INFO
    assert by_id["server.accounts.broad_nopasswd_sudo"].severity is Severity.PASS
    assert by_id["server.accounts.sudoers_readability"].severity is Severity.PASS


def test_accounts_scanner_uses_info_when_login_shell_inventory_is_unavailable():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_UID_MIN=1000\n"
            "BLACKLIGHT_UID_MIN_SOURCE=fallback\n"
            "BLACKLIGHT_PASSWD_BEGIN\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/bin/bash",
            "",
        ),
        CommandResult(0, "", ""),
        CommandResult(
            0,
            "BLACKLIGHT_SUDO_UNREADABLE=/etc/sudoers",
            "",
        ),
    )

    by_id = _by_id(findings)
    assert by_id["server.accounts.system_login_shells"].severity is Severity.INFO
    assert by_id["server.accounts.broad_nopasswd_sudo"].severity is Severity.INFO
    assert by_id["server.accounts.sudoers_readability"].severity is Severity.ERROR


def test_accounts_scanner_counts_primary_gid_membership_for_docker_group():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_UID_MIN=1000\n"
            "BLACKLIGHT_UID_MIN_SOURCE=login.defs\n"
            "BLACKLIGHT_SHELL=/bin/bash\n"
            "BLACKLIGHT_PASSWD_BEGIN\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "alice:x:1000:999:Alice:/home/alice:/bin/bash",
            "",
        ),
        CommandResult(0, "BLACKLIGHT_GROUP=docker:x:999:", ""),
        CommandResult(0, "BLACKLIGHT_SUDO_READABLE=/etc/sudoers", ""),
    )

    finding = _by_id(findings)["server.accounts.privileged_groups"]
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["root_equivalent_groups"][0]["members"] == ["alice"]
