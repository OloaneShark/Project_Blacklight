from __future__ import annotations

from blacklight_security.models import Severity
from blacklight_security.scanners.server.linux import CommandResult, ServerScanTarget
from blacklight_security.scanners.server.tls import ServerTLSScanner


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
    return ServerTLSScanner(target).scan()


def test_tls_scanner_reports_expired_and_self_signed_independently():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_OPENSSL=present\n"
            "BLACKLIGHT_TIMEOUT=present\n"
            "BLACKLIGHT_LISTENER_BACKEND=ss\n"
            "BLACKLIGHT_TLS_PORT=443\n"
            "BLACKLIGHT_TLS_META=443|subject=CN = legacy.example\n"
            "BLACKLIGHT_TLS_META=443|issuer=CN = legacy.example\n"
            "BLACKLIGHT_TLS_META=443|notBefore=Jan  1 00:00:00 1999 GMT\n"
            "BLACKLIGHT_TLS_META=443|notAfter=Jan  1 00:00:00 2000 GMT\n"
            "BLACKLIGHT_TLS_META=443|sha256 Fingerprint=AA:BB:CC",
            "",
        ),
    )

    assert len(findings) == 2
    expiry = next(item for item in findings if item.check_id == "server.tls.certificate_expiry")
    self_signed = next(
        item for item in findings if item.check_id == "server.tls.self_signed_certificate"
    )
    assert expiry.severity is Severity.HIGH
    assert self_signed.severity is Severity.INFO
    assert expiry.evidence["port"] == 443
    assert expiry.evidence["hostname_match_evaluated"] is False


def test_tls_scanner_passes_far_future_ca_issued_certificate():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_OPENSSL=present\n"
            "BLACKLIGHT_TIMEOUT=present\n"
            "BLACKLIGHT_LISTENER_BACKEND=ss\n"
            "BLACKLIGHT_TLS_PORT=8443\n"
            "BLACKLIGHT_TLS_META=8443|subject=CN = app.example\n"
            "BLACKLIGHT_TLS_META=8443|issuer=CN = Example CA\n"
            "BLACKLIGHT_TLS_META=8443|notBefore=Jan  1 00:00:00 2026 GMT\n"
            "BLACKLIGHT_TLS_META=8443|notAfter=Jan  1 00:00:00 2099 GMT\n"
            "BLACKLIGHT_TLS_META=8443|sha256 Fingerprint=11:22:33",
            "",
        ),
    )

    assert len(findings) == 1
    assert findings[0].check_id == "server.tls.certificate_expiry"
    assert findings[0].severity is Severity.PASS
    assert findings[0].evidence["self_signed"] is False


def test_tls_scanner_reports_unverified_common_tls_listener_as_info():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_OPENSSL=present\n"
            "BLACKLIGHT_TIMEOUT=present\n"
            "BLACKLIGHT_LISTENER_BACKEND=ss\n"
            "BLACKLIGHT_TLS_PORT=9443\n"
            "BLACKLIGHT_TLS_NO_CERT=9443",
            "",
        ),
    )

    assert len(findings) == 1
    assert findings[0].check_id == "server.tls.unverified_listener"
    assert findings[0].severity is Severity.INFO
    assert findings[0].evidence["ports"] == [9443]


def test_tls_scanner_does_not_probe_without_timeout_tooling():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\nprod-1", ""),
        CommandResult(
            0,
            "BLACKLIGHT_OPENSSL=present\nBLACKLIGHT_TIMEOUT=missing",
            "",
        ),
    )

    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "timeout" in findings[0].title.lower()
