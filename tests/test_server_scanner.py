from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from blacklight_security.models import Severity
from blacklight_security.scanners.server.linux import (
    CommandResult,
    SSHCommandRunner,
    ServerBaselineScanner,
    ServerScanTarget,
)


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
    return ServerBaselineScanner(target).scan()


def _by_id(findings):
    return {finding.check_id: finding for finding in findings}


def test_server_baseline_detects_explicit_insecure_linux_settings():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\n6.8.0\nprod-1", ""),
        CommandResult(
            0,
            "/etc/ssh/sshd_config:PermitRootLogin yes\n"
            "/etc/ssh/sshd_config.d/10-auth.conf:PasswordAuthentication yes\n"
            "/etc/ssh/sshd_config:PermitEmptyPasswords yes",
            "",
        ),
        CommandResult(0, "666 root root", ""),
        CommandResult(0, "root\nbackup-root", ""),
        CommandResult(0, "666 root docker", ""),
    )

    findings_by_id = _by_id(findings)
    assert findings_by_id["server.baseline.ssh_root_login"].severity is Severity.HIGH
    assert (
        findings_by_id["server.baseline.ssh_password_authentication"].severity
        is Severity.MEDIUM
    )
    assert findings_by_id["server.baseline.ssh_empty_passwords"].severity is Severity.CRITICAL
    assert findings_by_id["server.baseline.ssh_config_permissions"].severity is Severity.HIGH
    assert findings_by_id["server.baseline.uid_zero_accounts"].severity is Severity.HIGH
    assert (
        findings_by_id["server.baseline.docker_socket_permissions"].severity
        is Severity.HIGH
    )


def test_server_baseline_reports_safe_observed_permissions_without_overclaiming_sshd_defaults():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nLinux\n6.8.0\nprod-1", ""),
        CommandResult(
            0,
            "/etc/ssh/sshd_config:PermitRootLogin no\n"
            "/etc/ssh/sshd_config:PasswordAuthentication no\n"
            "/etc/ssh/sshd_config:PermitEmptyPasswords no",
            "",
        ),
        CommandResult(0, "600 root root", ""),
        CommandResult(0, "root", ""),
        CommandResult(0, "660 root docker", ""),
    )

    findings_by_id = _by_id(findings)
    assert findings_by_id["server.baseline.ssh_connection"].severity is Severity.PASS
    assert findings_by_id["server.baseline.ssh_root_login"].severity is Severity.INFO
    assert findings_by_id["server.baseline.ssh_password_authentication"].severity is Severity.INFO
    assert findings_by_id["server.baseline.ssh_empty_passwords"].severity is Severity.INFO
    assert findings_by_id["server.baseline.ssh_config_permissions"].severity is Severity.PASS
    assert findings_by_id["server.baseline.uid_zero_accounts"].severity is Severity.PASS
    assert (
        findings_by_id["server.baseline.docker_socket_permissions"].severity
        is Severity.PASS
    )


def test_server_baseline_rejects_non_linux_target():
    findings = _scan_with(
        CommandResult(0, "BLACKLIGHT_OK\nFreeBSD\n14.1\nedge-1", "")
    )

    assert len(findings) == 1
    assert findings[0].severity is Severity.ERROR
    assert findings[0].check_id == "server.baseline.unsupported_platform"


def test_server_target_validates_port_timeout_host_and_user():
    with pytest.raises(ValueError):
        ServerScanTarget(host="-bad")
    with pytest.raises(ValueError):
        ServerScanTarget(host="example.com", user="bad user")
    with pytest.raises(ValueError):
        ServerScanTarget(host="example.com", port=0)
    with pytest.raises(ValueError):
        ServerScanTarget(host="example.com", connect_timeout=61)


def test_ssh_runner_uses_argument_list_batch_mode_and_never_shell(tmp_path):
    key = tmp_path / "audit key"
    target = ServerScanTarget(
        host="server.example",
        user="audit",
        port=2222,
        identity_file=key,
        connect_timeout=7,
    )
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="ok\n",
        stderr="",
    )

    with patch("blacklight_security.scanners.server.linux.subprocess.run", return_value=completed) as run:
        result = SSHCommandRunner(target).run("uname -s")

    assert result.stdout == "ok"
    argv = run.call_args.args[0]
    assert argv[:3] == ["ssh", "-o", "BatchMode=yes"]
    assert ["-p", "2222"] == argv[5:7]
    assert ["-i", str(Path(key))] == argv[7:9]
    assert argv[-2:] == ["audit@server.example", "uname -s"]
    assert run.call_args.kwargs["shell"] is False
