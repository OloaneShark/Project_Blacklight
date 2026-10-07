import json
import subprocess
from unittest.mock import patch

from blacklight_security.cli import main

def test_docker_cli_scans_dockerfile_and_returns_security_gate_failure(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:latest\nUSER root\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            "docker",
            "--path",
            str(tmp_path),
            "--fail-on",
            "high",
        ]
    )

    assert exit_code == 1


def test_docker_cli_returns_two_when_no_dockerfile_exists(tmp_path):
    exit_code = main(["scan", "docker", "--path", str(tmp_path)])

    assert exit_code == 2


def test_docker_cli_json_output_contains_docker_provider(tmp_path, capsys):
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:3.21\nUSER 1000\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            "docker",
            "--path",
            str(tmp_path),
            "--format",
            "json",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert '"provider": "docker"' in output
    assert '"service": "dockerfile"' in output


def test_docker_cli_does_not_create_aws_session(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:3.21\nUSER 1000\n",
        encoding="utf-8",
    )

    with patch("blacklight_security.cli.boto3.Session") as aws_session:
        exit_code = main(["scan", "docker", "--path", str(tmp_path)])

    assert exit_code == 0
    aws_session.assert_not_called()


def test_docker_console_does_not_render_aws_identity_fields(tmp_path, capsys):
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:3.21\nUSER 1000\n",
        encoding="utf-8",
    )

    exit_code = main(["scan", "docker", "--path", str(tmp_path)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Provider: docker" in output
    assert "AWS Account" not in output
    assert "Principal:" not in output


def test_docker_cli_can_run_live_daemon_scanner_and_gate_privileged_container(capsys):
    container = {
        "Id": "a" * 64,
        "Name": "/app",
        "HostConfig": {
            "Privileged": True,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "CapAdd": None,
            "SecurityOpt": [],
        },
        "Config": {"User": "1000"},
        "Mounts": [],
        "NetworkSettings": {"Ports": {}},
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"Version":"28.0"}', ""),
        subprocess.CompletedProcess([], 0, "a" * 64, ""),
        subprocess.CompletedProcess([], 0, json.dumps([container]), ""),
    ]

    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=responses,
    ) as run:
        exit_code = main(
            [
                "scan",
                "docker",
                "--service",
                "daemon",
                "--fail-on",
                "critical",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Scanners: daemon" in output.out
    assert "Running Docker container is privileged" in output.out
    assert all(call.kwargs["shell"] is False for call in run.call_args_list)


def test_docker_cli_default_remains_static_dockerfile_scan(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:3.21\nUSER 1000\n",
        encoding="utf-8",
    )

    with patch("blacklight_security.scanners.docker.daemon.subprocess.run") as docker_run:
        exit_code = main(["scan", "docker", "--path", str(tmp_path)])

    assert exit_code == 0
    docker_run.assert_not_called()


def test_docker_cli_can_gate_writable_sensitive_host_mount(capsys):
    container = {
        "Id": "a" * 64,
        "Name": "/app",
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "CapAdd": None,
            "SecurityOpt": [],
            "Devices": [],
        },
        "Config": {"User": "1000"},
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/etc",
                "Destination": "/host-etc",
                "RW": True,
            }
        ],
        "NetworkSettings": {"Ports": {}},
    }
    responses = [
        subprocess.CompletedProcess([], 0, '{"Version":"28.0"}', ""),
        subprocess.CompletedProcess([], 0, "a" * 64, ""),
        subprocess.CompletedProcess([], 0, json.dumps([container]), ""),
    ]

    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=responses,
    ):
        exit_code = main(
            [
                "scan",
                "docker",
                "--service",
                "daemon",
                "--fail-on",
                "high",
            ]
        )

    output = capsys.readouterr()
    assert exit_code == 1
    assert "writable sensitive host-path mounts" in output.out
