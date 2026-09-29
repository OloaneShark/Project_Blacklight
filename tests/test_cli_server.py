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
                "--service",
                "baseline",
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


def test_server_cli_can_run_network_scanner_and_gate_firewall_gap(capsys):
    def fake_run(argv, **kwargs):
        command = argv[-1]
        if "BLACKLIGHT_OK" in command:
            return subprocess.CompletedProcess([], 0, "BLACKLIGHT_OK\nLinux\nprod-1\n", "")
        if "ss -H -lntu" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                "BLACKLIGHT_TOOL=ss\n"
                "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n",
                "",
            )
        if "ufw status" in command:
            return subprocess.CompletedProcess([], 0, "Status: inactive\n", "")
        if "firewall-cmd --state" in command:
            return subprocess.CompletedProcess([], 252, "", "not running")
        if "nft list ruleset" in command:
            return subprocess.CompletedProcess([], 0, "table inet local { }\n", "")
        if "iptables -S" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
                "",
            )
        raise AssertionError(f"unexpected SSH command: {command}")

    with patch("blacklight_security.scanners.server.linux.subprocess.run", side_effect=fake_run):
        exit_code = main(
            [
                "scan",
                "server",
                "--host",
                "server.example",
                "--service",
                "network",
                "--fail-on",
                "medium",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Scanners: network" in output.out
    assert "No active supported local firewall control was observed" in output.out


def test_server_cli_can_run_accounts_scanner_and_gate_broad_nopasswd(capsys):
    def fake_run(argv, **kwargs):
        command = argv[-1]
        if "BLACKLIGHT_OK" in command:
            return subprocess.CompletedProcess([], 0, "BLACKLIGHT_OK\nLinux\nprod-1\n", "")
        if "BLACKLIGHT_UID_MIN" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                "BLACKLIGHT_UID_MIN=1000\n"
                "BLACKLIGHT_UID_MIN_SOURCE=login.defs\n"
                "BLACKLIGHT_SHELL=/bin/bash\n"
                "BLACKLIGHT_PASSWD_BEGIN\n"
                "root:x:0:0:root:/root:/bin/bash\n"
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
                "",
            )
        if "BLACKLIGHT_GROUP" in command:
            return subprocess.CompletedProcess([], 0, "BLACKLIGHT_GROUP=sudo:x:27:alice\n", "")
        if "BLACKLIGHT_SUDO" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                "BLACKLIGHT_SUDO_READABLE=/etc/sudoers\n"
                "BLACKLIGHT_SUDO_RULE=/etc/sudoers|alice ALL=(ALL:ALL) NOPASSWD: ALL\n",
                "",
            )
        raise AssertionError(f"unexpected SSH command: {command}")

    with patch("blacklight_security.scanners.server.linux.subprocess.run", side_effect=fake_run):
        exit_code = main(
            [
                "scan",
                "server",
                "--host",
                "server.example",
                "--service",
                "accounts",
                "--fail-on",
                "high",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Scanners: accounts" in output.out
    assert "Broad passwordless sudo rules were observed" in output.out
