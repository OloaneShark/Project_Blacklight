from pathlib import Path

from blacklight_security.models import Severity
from blacklight_security.scanners.docker import DockerScanTarget, DockerfileScanner


def _scan(tmp_path: Path, content: str):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(content, encoding="utf-8")
    return DockerfileScanner(DockerScanTarget(tmp_path)).scan()


def _by_check(findings):
    return {finding.check_id: finding for finding in findings}


def test_secure_dockerfile_passes_high_signal_checks(tmp_path):
    findings = _scan(
        tmp_path,
        """
FROM python:3.12-slim
WORKDIR /app
COPY . /app
USER 65532:65532
CMD ["python", "-m", "app"]
""".strip(),
    )

    checks = _by_check(findings)

    assert checks["docker.dockerfile.base_image_latest"].severity is Severity.PASS
    assert checks["docker.dockerfile.root_user"].severity is Severity.PASS
    assert checks["docker.dockerfile.embedded_secret"].severity is Severity.PASS
    assert checks["docker.dockerfile.remote_add"].severity is Severity.PASS
    assert checks["docker.dockerfile.remote_shell_pipe"].severity is Severity.PASS
    assert checks["docker.dockerfile.world_writable_permissions"].severity is Severity.PASS


def test_root_and_latest_base_are_reported(tmp_path):
    findings = _scan(
        tmp_path,
        """
FROM ubuntu:latest
RUN echo hello
""".strip(),
    )

    checks = _by_check(findings)

    assert checks["docker.dockerfile.base_image_latest"].severity is Severity.MEDIUM
    assert checks["docker.dockerfile.root_user"].severity is Severity.HIGH


def test_implicit_base_tag_is_reported(tmp_path):
    findings = _scan(tmp_path, "FROM ubuntu\nUSER 1000")

    finding = _by_check(findings)["docker.dockerfile.base_image_latest"]

    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["matches"][0]["image"] == "ubuntu"


def test_digest_pinned_scratch_and_versioned_images_avoid_latest_check(tmp_path):
    findings = _scan(
        tmp_path,
        """
FROM python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS builder
FROM scratch
""".strip(),
    )

    finding = _by_check(findings)["docker.dockerfile.base_image_latest"]

    assert finding.severity is Severity.PASS


def test_secret_like_arg_and_env_values_are_redacted(tmp_path):
    findings = _scan(
        tmp_path,
        """
FROM python:3.12-slim
ARG API_TOKEN=do-not-print-this
ENV AWS_SECRET_ACCESS_KEY=also-do-not-print
USER 1000
""".strip(),
    )

    finding = _by_check(findings)["docker.dockerfile.embedded_secret"]

    assert finding.severity is Severity.HIGH
    assert finding.evidence["secret_values_redacted"] is True
    assert finding.evidence["matches"] == [
        {"instruction": "ARG", "key": "API_TOKEN", "line": 2},
        {"instruction": "ENV", "key": "AWS_SECRET_ACCESS_KEY", "line": 3},
    ]
    assert "do-not-print-this" not in str(finding.evidence)
    assert "also-do-not-print" not in str(finding.evidence)


def test_secret_arg_without_default_value_is_not_reported_as_embedded(tmp_path):
    findings = _scan(
        tmp_path,
        """
FROM python:3.12-slim
ARG API_TOKEN
USER 1000
""".strip(),
    )

    assert _by_check(findings)["docker.dockerfile.embedded_secret"].severity is Severity.PASS


def test_remote_add_shell_pipe_and_chmod_777_are_reported(tmp_path):
    findings = _scan(
        tmp_path,
        """
FROM alpine:3.21
ADD https://example.com/tool /usr/local/bin/tool
RUN curl -fsSL https://example.com/install.sh | sh
RUN chmod 777 /app
USER 1000
""".strip(),
    )

    checks = _by_check(findings)

    assert checks["docker.dockerfile.remote_add"].severity is Severity.MEDIUM
    assert checks["docker.dockerfile.remote_shell_pipe"].severity is Severity.HIGH
    assert checks["docker.dockerfile.world_writable_permissions"].severity is Severity.MEDIUM


def test_multistage_runtime_user_uses_final_stage(tmp_path):
    findings = _scan(
        tmp_path,
        """
FROM python:3.12-slim AS builder
USER 1000
RUN echo build

FROM python:3.12-slim
USER root
""".strip(),
    )

    finding = _by_check(findings)["docker.dockerfile.root_user"]

    assert finding.severity is Severity.HIGH
    assert finding.evidence["final_stage_user"] == "root"


def test_directory_discovery_finds_common_dockerfile_names(tmp_path):
    (tmp_path / "service").mkdir()
    (tmp_path / "service" / "Dockerfile.prod").write_text(
        "FROM alpine:3.21\nUSER 1000\n",
        encoding="utf-8",
    )
    (tmp_path / "worker.Dockerfile").write_text(
        "FROM alpine:3.21\nUSER 1000\n",
        encoding="utf-8",
    )

    findings = DockerfileScanner(DockerScanTarget(tmp_path)).scan()
    resources = {finding.resource_id for finding in findings}

    assert "service/Dockerfile.prod" in resources
    assert "worker.Dockerfile" in resources


def test_missing_dockerfile_is_an_error(tmp_path):
    findings = DockerfileScanner(DockerScanTarget(tmp_path)).scan()

    assert len(findings) == 1
    assert findings[0].check_id == "docker.dockerfile.discovery"
    assert findings[0].severity is Severity.ERROR


def test_line_continuations_are_parsed_as_one_run_instruction(tmp_path):
    content = (
        "FROM alpine:3.21\n"
        "RUN curl -fsSL https://example.com/install.sh \\\\n"
        "    | sh\n"
        "USER 1000\n"
    )
    findings = _scan(tmp_path, content)

    finding = _by_check(findings)["docker.dockerfile.remote_shell_pipe"]

    assert finding.severity is Severity.HIGH
    assert finding.evidence["matches"] == [{"line": 2}]


def test_variable_runtime_user_is_informational_not_pass(tmp_path):
    findings = _scan(
        tmp_path,
        """
FROM alpine:3.21
ARG APP_USER=1000
USER $APP_USER
""".strip(),
    )

    finding = _by_check(findings)["docker.dockerfile.root_user"]

    assert finding.severity is Severity.INFO
    assert finding.evidence["statically_resolved"] is False


def test_remote_add_with_checksum_is_not_flagged(tmp_path):
    findings = _scan(
        tmp_path,
        """
FROM alpine:3.21
ADD --checksum=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa https://example.com/tool /usr/local/bin/tool
USER 1000
""".strip(),
    )

    assert _by_check(findings)["docker.dockerfile.remote_add"].severity is Severity.PASS
