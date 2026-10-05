from __future__ import annotations

import json
import subprocess
from pathlib import Path
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


def test_server_cli_can_run_auth_scanner_and_gate_null_password_policy(capsys):
    def fake_run(argv, **kwargs):
        command = argv[-1]
        if "BLACKLIGHT_OK" in command:
            return subprocess.CompletedProcess([], 0, "BLACKLIGHT_OK\nLinux\nprod-1\n", "")
        if "BLACKLIGHT_PAM_READABLE" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                "BLACKLIGHT_PAM_READABLE=/etc/pam.d/common-auth\n"
                "BLACKLIGHT_PAM_NULLOK=/etc/pam.d/common-auth|"
                "auth required pam_unix.so nullok\n",
                "",
            )
        if "BLACKLIGHT_UID_MIN" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                "BLACKLIGHT_UID_MIN=1000\n"
                "BLACKLIGHT_UID_MIN_SOURCE=login.defs\n"
                "BLACKLIGHT_SHELL=/bin/bash\n"
                "BLACKLIGHT_PASSWD_BEGIN\n"
                "root:x:0:0:root:/root:/bin/bash\n"
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
                "BLACKLIGHT_PASSWD_END\n"
                "BLACKLIGHT_SELF_PASSWD=alice P 2026-09-30 0 99999 7 -1\n"
                "BLACKLIGHT_SHADOW_READABLE=1\n"
                "BLACKLIGHT_SHADOW_ACCOUNT=root|locked|20000|99999||\n"
                "BLACKLIGHT_SHADOW_ACCOUNT=alice|empty|20000|99999||\n",
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
                "auth",
                "--fail-on",
                "high",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Scanners: auth" in output.out
    assert "PAM explicitly allows null passwords" in output.out


def test_server_cli_can_run_package_scanner_and_gate_security_updates(capsys):
    def fake_run(argv, **kwargs):
        command = argv[-1]
        if "BLACKLIGHT_OK" in command:
            return subprocess.CompletedProcess([], 0, "BLACKLIGHT_OK\nLinux\nprod-1\n", "")
        if "command -v apt-get" in command and "command -v dnf" in command:
            return subprocess.CompletedProcess([], 0, "apt\n", "")
        if "apt-get -s" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                "BLACKLIGHT_FAMILY=apt\n"
                "BLACKLIGHT_CACHE_AGE=1200\n"
                "BLACKLIGHT_RC=0\n"
                "BLACKLIGHT_UPDATE=Inst openssl [3.0.1] "
                "(3.0.2 Ubuntu:24.04/noble-security [amd64])\n",
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
                "packages",
                "--fail-on",
                "medium",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Scanners: packages" in output.out
    assert "pending security-origin updates" in output.out


def test_server_cli_loads_target_profile_and_preserves_scan_context(tmp_path, capsys):
    profile_file = tmp_path / "targets.toml"
    profile_file.write_text(
        """
[targets.prod]
host = "server.example"
user = "audit"
port = 2222
identity_file = "~/.ssh/blacklight_audit"
connect_timeout = 7
""".strip()
        + "\n",
        encoding="utf-8",
    )

    def fake_run(argv, **kwargs):
        return _ssh_result(argv[-1])

    with patch(
        "blacklight_security.scanners.server.linux.subprocess.run",
        side_effect=fake_run,
    ) as run:
        exit_code = main(
            [
                "scan",
                "server",
                "--target-profile",
                "prod",
                "--targets-file",
                str(profile_file),
                "--service",
                "baseline",
                "--format",
                "json",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(output.out)
    assert payload["scan"]["context"]["profile"] == "prod"

    argv = run.call_args_list[0].args[0]
    assert ["-p", "2222"] == argv[5:7]
    assert "audit@server.example" == argv[-2]
    assert str((Path("~/.ssh/blacklight_audit").expanduser())) in argv


def test_server_cli_profile_values_can_be_overridden(tmp_path, capsys):
    profile_file = tmp_path / "targets.toml"
    profile_file.write_text(
        """
[targets.prod]
host = "server.example"
user = "audit"
port = 2222
connect_timeout = 7
""".strip()
        + "\n",
        encoding="utf-8",
    )

    def fake_run(argv, **kwargs):
        return _ssh_result(argv[-1])

    with patch(
        "blacklight_security.scanners.server.linux.subprocess.run",
        side_effect=fake_run,
    ) as run:
        exit_code = main(
            [
                "scan",
                "server",
                "--target-profile",
                "prod",
                "--targets-file",
                str(profile_file),
                "--host",
                "override.example",
                "--user",
                "override-user",
                "--port",
                "2200",
                "--connect-timeout",
                "9",
                "--service",
                "baseline",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 0
    assert "Target profile: prod" in output.out
    argv = run.call_args_list[0].args[0]
    assert ["-p", "2200"] == argv[5:7]
    assert "ConnectTimeout=9" in argv
    assert argv[-2] == "override-user@override.example"


def test_server_cli_requires_host_or_target_profile(capsys):
    exit_code = main(["scan", "server", "--service", "baseline"])

    output = capsys.readouterr()
    assert exit_code == 2
    assert "either --host or --target-profile is required" in output.err


def test_server_cli_can_run_services_scanner_and_gate_legacy_remote_access(capsys):
    def fake_run(argv, **kwargs):
        command = argv[-1]
        if "BLACKLIGHT_OK" in command:
            return subprocess.CompletedProcess([], 0, "BLACKLIGHT_OK\nLinux\nprod-1\n", "")
        if "BLACKLIGHT_SYSTEMCTL" in command:
            return subprocess.CompletedProcess(
                [],
                0,
                "BLACKLIGHT_SYSTEMCTL=present\n"
                "BLACKLIGHT_ACTIVE=telnet.service\n",
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
                "services",
                "--fail-on",
                "high",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Scanners: services" in output.out
    assert "Legacy cleartext remote-access services are active" in output.out
