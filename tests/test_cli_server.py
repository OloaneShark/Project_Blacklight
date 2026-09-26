from __future__ import annotations

import subprocess
from unittest.mock import patch

from blacklight_security.cli import main


def _ssh_result(command):
    if "BLACKLIGHT_OK" in command:
        return subprocess.CompletedProcess([], 0, "BLACKLIGHT_OK\nLinux\n6.8.0\nprod-1\n", "")
    if "PermitRootLogin" in command:
        return subprocess.CompletedProcess(
            [],
            0,
            "/etc/ssh/sshd_config:PermitRootLogin yes\n"
            "/etc/ssh/sshd_config:PasswordAuthentication no\n"
            "/etc/ssh/sshd_config:PermitEmptyPasswords no\n",
            "",
        )
    if "sshd_config" in command and "stat -c" in command:
        return subprocess.CompletedProcess([], 0, "600 root root\n", "")
    if "/etc/passwd" in command:
        return subprocess.CompletedProcess([], 0, "root\n", "")
    if "docker.sock" in command:
        return subprocess.CompletedProcess([], 0, "", "")
    raise AssertionError(f"unexpected SSH command: {command}")


def test_server_cli_runs_baseline_and_security_gate(capsys):
    def fake_run(argv, **kwargs):
        return _ssh_result(argv[-1])

    with patch("blacklight_security.scanners.server.linux.subprocess.run", side_effect=fake_run):
        exit_code = main(
            [
                "scan",
                "server",
                "--host",
                "server.example",
                "--user",
                "audit",
                "--fail-on",
                "high",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Provider: server" in output.out
    assert "SSH configuration explicitly permits root login" in output.out


def test_server_cli_rejects_invalid_target(capsys):
    exit_code = main(["scan", "server", "--host", "bad host"])

    output = capsys.readouterr()
    assert exit_code == 2
    assert "Blacklight server target error" in output.err
