from __future__ import annotations

from blacklight_security.models import Severity
from blacklight_security.scanners.server.auth import ServerAuthenticationScanner
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
    return ServerAuthenticationScanner(target).scan()


def _by_id(findings):
    return {finding.check_id: finding for finding in findings}


def test_auth_scanner_detects_pam_bypass_and_empty_login_password_without_hashes():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_PAM_READABLE=/etc/pam.d/sshd\n"
            "BLACKLIGHT_PAM_READABLE=/etc/pam.d/common-auth\n"
            "BLACKLIGHT_PAM_PERMIT=/etc/pam.d/sshd|auth required pam_permit.so\n"
            "BLACKLIGHT_PAM_NULLOK=/etc/pam.d/common-auth|"
            "auth required pam_unix.so nullok",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_UID_MIN=1000\n"
            "BLACKLIGHT_UID_MIN_SOURCE=login.defs\n"
            "BLACKLIGHT_SHELL=/bin/bash\n"
            "BLACKLIGHT_SHELL=/bin/sh\n"
            "BLACKLIGHT_PASSWD_BEGIN\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
            "BLACKLIGHT_PASSWD_END\n"
            "BLACKLIGHT_SELF_PASSWD=audit NP 2026-09-30 0 99999 7 -1\n"
            "BLACKLIGHT_SHADOW_READABLE=1\n"
            "BLACKLIGHT_SHADOW_ACCOUNT=root|locked|20000|99999||\n"
            "BLACKLIGHT_SHADOW_ACCOUNT=daemon|empty|20000|99999||\n"
            "BLACKLIGHT_SHADOW_ACCOUNT=alice|empty|20000|99999||",
            "",
        ),
    )

    by_id = _by_id(findings)

    assert by_id["server.auth.pam_permit_auth"].severity is Severity.HIGH
    assert by_id["server.auth.pam_null_passwords"].severity is Severity.HIGH
    assert by_id["server.auth.connected_password_state"].severity is Severity.HIGH
    assert by_id["server.auth.empty_password_accounts"].severity is Severity.HIGH
    assert by_id["server.auth.shadow_visibility"].severity is Severity.INFO

    empty_evidence = by_id["server.auth.empty_password_accounts"].evidence
    assert empty_evidence["password_hashes_returned"] is False
    assert empty_evidence["empty_password_accounts"][1]["username"] == "alice"
    assert empty_evidence["empty_password_accounts"][1]["login_capable_shell"] is True

    shadow_evidence = by_id["server.auth.shadow_visibility"].evidence
    assert shadow_evidence["password_hashes_returned"] is False


def test_auth_scanner_does_not_claim_whole_host_password_state_without_shadow_access():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_PAM_READABLE=/etc/pam.d/sshd\n"
            "BLACKLIGHT_PAM_READABLE=/etc/pam.d/common-auth",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_UID_MIN=1000\n"
            "BLACKLIGHT_UID_MIN_SOURCE=login.defs\n"
            "BLACKLIGHT_SHELL=/bin/bash\n"
            "BLACKLIGHT_PASSWD_BEGIN\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "audit:x:1000:1000:Audit:/home/audit:/bin/bash\n"
            "BLACKLIGHT_PASSWD_END\n"
            "BLACKLIGHT_SELF_PASSWD=audit L 2026-09-30 0 99999 7 -1\n"
            "BLACKLIGHT_SHADOW_READABLE=0",
            "",
        ),
    )

    by_id = _by_id(findings)

    assert by_id["server.auth.pam_permit_auth"].severity is Severity.INFO
    assert by_id["server.auth.pam_null_passwords"].severity is Severity.INFO
    assert by_id["server.auth.connected_password_state"].severity is Severity.PASS
    assert by_id["server.auth.empty_password_accounts"].severity is Severity.INFO
    assert by_id["server.auth.shadow_visibility"].evidence["shadow_readable"] is False


def test_auth_scanner_marks_empty_password_on_non_login_account_medium():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "BLACKLIGHT_PAM_READABLE=/etc/pam.d/sshd", ""),
        CommandResult(
            0,
            "BLACKLIGHT_UID_MIN=1000\n"
            "BLACKLIGHT_UID_MIN_SOURCE=login.defs\n"
            "BLACKLIGHT_SHELL=/bin/bash\n"
            "BLACKLIGHT_PASSWD_BEGIN\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "BLACKLIGHT_PASSWD_END\n"
            "BLACKLIGHT_SELF_PASSWD=audit P 2026-09-30 0 99999 7 -1\n"
            "BLACKLIGHT_SHADOW_READABLE=1\n"
            "BLACKLIGHT_SHADOW_ACCOUNT=root|locked|20000|99999||\n"
            "BLACKLIGHT_SHADOW_ACCOUNT=daemon|empty|20000|99999||",
            "",
        ),
    )

    finding = _by_id(findings)["server.auth.empty_password_accounts"]
    assert finding.severity is Severity.MEDIUM


def test_auth_scanner_records_partial_pam_visibility_without_calling_it_safe():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_PAM_READABLE=/etc/pam.d/sshd\n"
            "BLACKLIGHT_PAM_UNREADABLE=/etc/pam.d/system-auth",
            "",
        ),
        CommandResult(
            0,
            "BLACKLIGHT_UID_MIN=1000\n"
            "BLACKLIGHT_UID_MIN_SOURCE=fallback\n"
            "BLACKLIGHT_PASSWD_BEGIN\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "BLACKLIGHT_PASSWD_END\n"
            "BLACKLIGHT_SHADOW_READABLE=0",
            "",
        ),
    )

    finding = _by_id(findings)["server.auth.pam_policy_visibility"]
    assert finding.severity is Severity.INFO
    assert "/etc/pam.d/system-auth" in finding.evidence["unreadable_files"]
