from __future__ import annotations

from blacklight_security.models import Severity
from blacklight_security.scanners.server.linux import CommandResult, ServerScanTarget
from blacklight_security.scanners.server.sshd_effective import ServerSSHDEffectiveScanner


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
    return ServerSSHDEffectiveScanner(target).scan()


def _by_id(findings):
    return {finding.check_id: finding for finding in findings}


def test_sshd_scanner_detects_effective_legacy_crypto_and_risky_settings():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_SSHD_BACKEND=openssh\n"
            "BLACKLIGHT_SSHD_RC=0\n"
            "BLACKLIGHT_SSHD=strictmodes no\n"
            "BLACKLIGHT_SSHD=gatewayports clientspecified\n"
            "BLACKLIGHT_SSHD=allowtcpforwarding yes\n"
            "BLACKLIGHT_SSHD=permituserenvironment yes\n"
            "BLACKLIGHT_SSHD=hostbasedauthentication yes\n"
            "BLACKLIGHT_SSHD=ciphers chacha20-poly1305@openssh.com,aes128-cbc\n"
            "BLACKLIGHT_SSHD=macs hmac-sha2-256,hmac-md5\n"
            "BLACKLIGHT_SSHD=kexalgorithms curve25519-sha256,diffie-hellman-group1-sha1\n"
            "BLACKLIGHT_SSHD=hostkeyalgorithms ssh-ed25519,ssh-rsa\n"
            "BLACKLIGHT_SSHD=pubkeyacceptedalgorithms ssh-ed25519,ssh-rsa",
            "",
        ),
    )

    by_id = _by_id(findings)
    assert by_id["server.sshd.weak_crypto"].severity is Severity.MEDIUM
    assert by_id["server.sshd.strict_modes"].severity is Severity.MEDIUM
    assert by_id["server.sshd.gateway_ports"].severity is Severity.MEDIUM
    assert by_id["server.sshd.user_environment"].severity is Severity.MEDIUM
    assert by_id["server.sshd.hostbased_authentication"].severity is Severity.MEDIUM

    weak = by_id["server.sshd.weak_crypto"].evidence["weak_algorithms"]
    assert weak["ciphers"] == ["aes128-cbc"]
    assert weak["macs"] == ["hmac-md5"]
    assert weak["kex_algorithms"] == ["diffie-hellman-group1-sha1"]
    assert weak["hostkey_algorithms"] == ["ssh-rsa"]


def test_sshd_scanner_passes_selected_safe_effective_settings():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_SSHD_BACKEND=openssh\n"
            "BLACKLIGHT_SSHD_RC=0\n"
            "BLACKLIGHT_SSHD=strictmodes yes\n"
            "BLACKLIGHT_SSHD=gatewayports no\n"
            "BLACKLIGHT_SSHD=allowtcpforwarding yes\n"
            "BLACKLIGHT_SSHD=permituserenvironment no\n"
            "BLACKLIGHT_SSHD=hostbasedauthentication no\n"
            "BLACKLIGHT_SSHD=ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
            "BLACKLIGHT_SSHD=macs hmac-sha2-256-etm@openssh.com\n"
            "BLACKLIGHT_SSHD=kexalgorithms curve25519-sha256\n"
            "BLACKLIGHT_SSHD=hostkeyalgorithms ssh-ed25519\n"
            "BLACKLIGHT_SSHD=pubkeyacceptedalgorithms ssh-ed25519",
            "",
        ),
    )

    assert all(finding.severity is Severity.PASS for finding in findings)


def test_sshd_scanner_reports_info_when_openssh_backend_is_missing():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(0, "BLACKLIGHT_SSHD_BACKEND=missing", ""),
    )

    assert len(findings) == 1
    assert findings[0].check_id == "server.sshd.effective_config"
    assert findings[0].severity is Severity.INFO


def test_sshd_scanner_records_effective_config_failure_as_error():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_SSHD_BACKEND=openssh\n"
            "BLACKLIGHT_SSHD_RC=1\n"
            "BLACKLIGHT_SSHD_ERROR=Could not load host key",
            "",
        ),
    )

    assert len(findings) == 1
    assert findings[0].check_id == "server.sshd.effective_config"
    assert findings[0].severity is Severity.ERROR
    assert "Could not load host key" in findings[0].evidence["error"]
