from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from blacklight_security.models import Severity
from blacklight_security.scanners.docker.daemon import DockerDaemonScanner
from blacklight_security.scanners.docker.dockerfile import DockerScanTarget


def _container(**overrides):
    base = {
        "Id": "a" * 64,
        "Name": "/app",
        "HostConfig": {
            "Privileged": False,
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
    base.update(overrides)
    return base


def test_live_docker_scanner_detects_high_risk_runtime_configuration():
    container = _container(
        HostConfig={
            "Privileged": True,
            "NetworkMode": "host",
            "PidMode": "host",
            "IpcMode": "host",
            "CapAdd": ["ALL"],
            "SecurityOpt": ["seccomp=unconfined"],
        },
        Config={"User": ""},
        Mounts=[
            {
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        ],
        NetworkSettings={
            "Ports": {
                "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]
            }
        },
    )

    responses = [
        subprocess.CompletedProcess([], 0, '{"Version":"28.0"}', ""),
        subprocess.CompletedProcess([], 0, "a" * 64, ""),
        subprocess.CompletedProcess([], 0, json.dumps([container]), ""),
    ]

    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=responses,
    ):
        findings = DockerDaemonScanner(DockerScanTarget(path=".")).scan()

    by_id = {finding.check_id: finding for finding in findings}
    assert by_id["docker.daemon.privileged"].severity is Severity.CRITICAL
    assert by_id["docker.daemon.host_namespace"].severity is Severity.HIGH
    assert by_id["docker.daemon.docker_socket_mount"].severity is Severity.CRITICAL
    assert by_id["docker.daemon.capabilities_all"].severity is Severity.HIGH
    assert by_id["docker.daemon.unconfined_security"].severity is Severity.HIGH
    assert by_id["docker.daemon.root_user"].severity is Severity.HIGH
    assert by_id["docker.daemon.nonloopback_publish"].severity is Severity.LOW


def test_live_docker_scanner_passes_selected_safe_runtime_configuration():
    responses = [
        subprocess.CompletedProcess([], 0, '{"Version":"28.0"}', ""),
        subprocess.CompletedProcess([], 0, "a" * 64, ""),
        subprocess.CompletedProcess([], 0, json.dumps([_container()]), ""),
    ]

    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=responses,
    ):
        findings = DockerDaemonScanner(DockerScanTarget(path=".")).scan()

    assert all(finding.severity is Severity.PASS for finding in findings)


def test_live_docker_scanner_reports_info_when_cli_is_missing():
    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=FileNotFoundError,
    ):
        findings = DockerDaemonScanner(DockerScanTarget(path=".")).scan()

    assert len(findings) == 1
    assert findings[0].check_id == "docker.daemon.connection"
    assert findings[0].severity is Severity.INFO


def test_live_docker_scanner_reports_no_running_containers_as_info():
    responses = [
        subprocess.CompletedProcess([], 0, '{"Version":"28.0"}', ""),
        subprocess.CompletedProcess([], 0, "", ""),
    ]

    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=responses,
    ):
        findings = DockerDaemonScanner(DockerScanTarget(path=".")).scan()

    assert len(findings) == 1
    assert findings[0].check_id == "docker.daemon.running_containers"
    assert findings[0].severity is Severity.INFO


def test_live_docker_scanner_flags_sensitive_host_mounts_by_write_access():
    writable = _container(
        Mounts=[
            {
                "Type": "bind",
                "Source": "/etc",
                "Destination": "/host-etc",
                "RW": True,
            }
        ]
    )
    readonly = _container(
        Id="b" * 64,
        Name="/reader",
        Mounts=[
            {
                "Type": "bind",
                "Source": "/var/lib/kubelet",
                "Destination": "/kubelet",
                "RW": False,
            }
        ],
    )

    responses = [
        subprocess.CompletedProcess([], 0, '{"Version":"28.0"}', ""),
        subprocess.CompletedProcess([], 0, ("a" * 64) + "\n" + ("b" * 64), ""),
        subprocess.CompletedProcess([], 0, json.dumps([writable, readonly]), ""),
    ]

    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=responses,
    ):
        findings = DockerDaemonScanner(DockerScanTarget(path=".")).scan()

    mount_findings = [
        finding
        for finding in findings
        if finding.check_id == "docker.daemon.sensitive_host_mount"
    ]
    assert {finding.severity for finding in mount_findings} == {
        Severity.HIGH,
        Severity.MEDIUM,
    }
    writable_finding = next(
        finding for finding in mount_findings if finding.severity is Severity.HIGH
    )
    assert writable_finding.evidence["writable_mounts"][0]["source"] == "/etc"


def test_live_docker_scanner_flags_individual_dangerous_capabilities():
    high = _container(
        HostConfig={
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "CapAdd": ["SYS_ADMIN"],
            "SecurityOpt": [],
        }
    )
    medium = _container(
        Id="b" * 64,
        Name="/net",
        HostConfig={
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "CapAdd": ["NET_ADMIN"],
            "SecurityOpt": [],
        },
    )

    responses = [
        subprocess.CompletedProcess([], 0, '{"Version":"28.0"}', ""),
        subprocess.CompletedProcess([], 0, ("a" * 64) + "\n" + ("b" * 64), ""),
        subprocess.CompletedProcess([], 0, json.dumps([high, medium]), ""),
    ]

    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=responses,
    ):
        findings = DockerDaemonScanner(DockerScanTarget(path=".")).scan()

    capability_findings = [
        finding
        for finding in findings
        if finding.check_id == "docker.daemon.dangerous_capability"
    ]
    assert {finding.severity for finding in capability_findings} == {
        Severity.HIGH,
        Severity.MEDIUM,
    }


def test_live_docker_scanner_flags_host_device_passthrough():
    high = _container(
        HostConfig={
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "CapAdd": None,
            "SecurityOpt": [],
            "Devices": [
                {
                    "PathOnHost": "/dev/sda",
                    "PathInContainer": "/dev/sda",
                    "CgroupPermissions": "rwm",
                }
            ],
        }
    )
    medium = _container(
        Id="b" * 64,
        Name="/camera",
        HostConfig={
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "CapAdd": None,
            "SecurityOpt": [],
            "Devices": [
                {
                    "PathOnHost": "/dev/video0",
                    "PathInContainer": "/dev/video0",
                    "CgroupPermissions": "r",
                }
            ],
        },
    )

    responses = [
        subprocess.CompletedProcess([], 0, '{"Version":"28.0"}', ""),
        subprocess.CompletedProcess([], 0, ("a" * 64) + "\n" + ("b" * 64), ""),
        subprocess.CompletedProcess([], 0, json.dumps([high, medium]), ""),
    ]

    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=responses,
    ):
        findings = DockerDaemonScanner(DockerScanTarget(path=".")).scan()

    device_findings = [
        finding
        for finding in findings
        if finding.check_id == "docker.daemon.device_access"
    ]
    assert {finding.severity for finding in device_findings} == {
        Severity.HIGH,
        Severity.MEDIUM,
    }


def test_live_docker_scanner_includes_uts_and_cgroup_host_namespaces():
    container = _container(
        HostConfig={
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "host",
            "CgroupnsMode": "host",
            "CapAdd": None,
            "SecurityOpt": [],
        }
    )
    responses = [
        subprocess.CompletedProcess([], 0, '{"Version":"28.0"}', ""),
        subprocess.CompletedProcess([], 0, "a" * 64, ""),
        subprocess.CompletedProcess([], 0, json.dumps([container]), ""),
    ]

    with patch(
        "blacklight_security.scanners.docker.daemon.subprocess.run",
        side_effect=responses,
    ):
        findings = DockerDaemonScanner(DockerScanTarget(path=".")).scan()

    finding = next(
        item for item in findings if item.check_id == "docker.daemon.host_namespace"
    )
    assert finding.severity is Severity.HIGH
    assert finding.evidence["enabled"] == ["uts", "cgroup"]
