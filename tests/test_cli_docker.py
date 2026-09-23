from unittest.mock import patch

from blacklight_security.cli import main
from blacklight_security.models import Severity


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
