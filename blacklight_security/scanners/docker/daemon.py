from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

from blacklight_security.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class DockerCommandResult:
    returncode: int
    stdout: str
    stderr: str


class DockerCommandError(RuntimeError):
    pass


class DockerCLI:
    def run(self, args: list[str], timeout: int = 10) -> DockerCommandResult:
        try:
            completed = subprocess.run(
                ["docker", *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except FileNotFoundError as error:
            raise DockerCommandError("docker CLI was not found") from error
        except subprocess.TimeoutExpired as error:
            raise DockerCommandError("docker command timed out") from error

        return DockerCommandResult(
            completed.returncode,
            completed.stdout.strip(),
            completed.stderr.strip(),
        )


class DockerDaemonScanner:
    """Read-only inspection of currently running Docker containers."""

    def __init__(self, target: Any):
        self.target = target
        self.cli = DockerCLI()

    def scan(self) -> list[Finding]:
        try:
            version = self.cli.run(["version", "--format", "{{json .Server}}"])
        except DockerCommandError as error:
            return [self._availability_info(str(error))]

        if version.returncode != 0:
            return [
                self._finding(
                    "docker-daemon",
                    "docker.daemon.connection",
                    Severity.INFO,
                    "Docker daemon is not available to the current user",
                    (
                        "The Docker CLI was available, but Blacklight could not read the local "
                        "daemon API through the current Docker context."
                    ),
                    evidence={"stderr": version.stderr[:500]},
                )
            ]

        try:
            ps = self.cli.run(["ps", "-q", "--no-trunc"])
        except DockerCommandError as error:
            return [self._error("container_inventory", str(error))]

        if ps.returncode != 0:
            return [
                self._error(
                    "container_inventory",
                    ps.stderr[:500] or "docker ps returned a non-zero exit status",
                )
            ]

        ids = [line.strip() for line in ps.stdout.splitlines() if line.strip()]
        if not ids:
            return [
                self._finding(
                    "docker-daemon",
                    "docker.daemon.running_containers",
                    Severity.INFO,
                    "No running Docker containers were observed",
                    "The local Docker daemon returned an empty running-container inventory.",
                    evidence={"running_container_count": 0},
                )
            ]

        try:
            inspect = self.cli.run(["inspect", *ids], timeout=20)
        except DockerCommandError as error:
            return [self._error("container_inspect", str(error))]

        if inspect.returncode != 0:
            return [
                self._error(
                    "container_inspect",
                    inspect.stderr[:500] or "docker inspect returned a non-zero exit status",
                )
            ]

        try:
            payload = json.loads(inspect.stdout)
        except json.JSONDecodeError as error:
            return [self._error("container_inspect", f"invalid Docker inspect JSON: {error}")]

        if not isinstance(payload, list):
            return [self._error("container_inspect", "Docker inspect JSON was not a list")]

        findings: list[Finding] = []
        for container in payload:
            if not isinstance(container, dict):
                continue
            findings.extend(self._scan_container(container))

        if not findings:
            findings.append(
                self._finding(
                    "docker-daemon",
                    "docker.daemon.container_inspect",
                    Severity.ERROR,
                    "Docker returned no inspectable running container records",
                    "Blacklight received no usable container objects from docker inspect.",
                )
            )
        return findings

    def _scan_container(self, container: dict[str, Any]) -> list[Finding]:
        container_id = str(container.get("Id") or "unknown")
        name = str(container.get("Name") or "").lstrip("/") or container_id[:12]
        resource_id = f"container/{name}/{container_id[:12]}"

        host_config = container.get("HostConfig")
        if not isinstance(host_config, dict):
            host_config = {}
        config = container.get("Config")
        if not isinstance(config, dict):
            config = {}
        network = container.get("NetworkSettings")
        if not isinstance(network, dict):
            network = {}

        return [
            self._check_privileged(resource_id, host_config),
            self._check_host_namespaces(resource_id, host_config),
            self._check_docker_socket(resource_id, container),
            self._check_capabilities(resource_id, host_config),
            self._check_unconfined_security(resource_id, host_config),
            self._check_runtime_user(resource_id, config),
            self._check_published_ports(resource_id, network),
        ]

    def _check_privileged(self, resource_id: str, host_config: dict[str, Any]) -> Finding:
        privileged = host_config.get("Privileged") is True
        if privileged:
            return self._finding(
                resource_id,
                "docker.daemon.privileged",
                Severity.CRITICAL,
                "Running Docker container is privileged",
                (
                    "Docker inspect reports HostConfig.Privileged=true. Privileged containers "
                    "receive broad device and capability access to the host."
                ),
                "Remove privileged mode and grant only the specific host access the workload requires.",
                {"privileged": True},
            )
        return self._pass(
            resource_id,
            "docker.daemon.privileged",
            "Running container is not configured as privileged",
        )

    def _check_host_namespaces(
        self,
        resource_id: str,
        host_config: dict[str, Any],
    ) -> Finding:
        enabled: list[str] = []
        if str(host_config.get("NetworkMode") or "").lower() == "host":
            enabled.append("network")
        if str(host_config.get("PidMode") or "").lower() == "host":
            enabled.append("pid")
        if str(host_config.get("IpcMode") or "").lower() == "host":
            enabled.append("ipc")

        if enabled:
            return self._finding(
                resource_id,
                "docker.daemon.host_namespace",
                Severity.HIGH,
                "Running Docker container shares host namespaces",
                "Docker inspect reports one or more host namespace modes.",
                "Avoid host namespace sharing unless it is required and tightly controlled.",
                {"enabled": enabled},
            )
        return self._pass(
            resource_id,
            "docker.daemon.host_namespace",
            "Running container does not share selected host namespaces",
        )

    def _check_docker_socket(
        self,
        resource_id: str,
        container: dict[str, Any],
    ) -> Finding:
        mounts = container.get("Mounts")
        if not isinstance(mounts, list):
            mounts = []

        matches: list[dict[str, Any]] = []
        for mount in mounts:
            if not isinstance(mount, dict):
                continue
            source = str(mount.get("Source") or "")
            destination = str(mount.get("Destination") or "")
            if source in {"/var/run/docker.sock", "/run/docker.sock"}:
                matches.append(
                    {
                        "source": source,
                        "destination": destination,
                        "read_write": bool(mount.get("RW")),
                    }
                )

        writable = [item for item in matches if item["read_write"]]
        if writable:
            return self._finding(
                resource_id,
                "docker.daemon.docker_socket_mount",
                Severity.CRITICAL,
                "Running container has writable Docker daemon socket access",
                (
                    "The container mounts the local Docker socket read-write. A process with "
                    "daemon access can commonly create host-mounted privileged containers and "
                    "gain host-equivalent control."
                ),
                "Remove the Docker socket mount or replace it with a narrowly scoped broker/proxy.",
                {"mounts": writable},
            )
        if matches:
            return self._finding(
                resource_id,
                "docker.daemon.docker_socket_mount",
                Severity.HIGH,
                "Running container mounts the Docker daemon socket read-only",
                (
                    "The container can read the Docker daemon socket path. Filesystem read-only "
                    "mount mode does not prove that the daemon API itself cannot receive requests."
                ),
                "Avoid exposing the Docker daemon socket directly to application containers.",
                {"mounts": matches},
            )
        return self._pass(
            resource_id,
            "docker.daemon.docker_socket_mount",
            "Running container does not mount the selected Docker daemon socket paths",
        )

    def _check_capabilities(
        self,
        resource_id: str,
        host_config: dict[str, Any],
    ) -> Finding:
        values = host_config.get("CapAdd")
        if not isinstance(values, list):
            values = []
        added = sorted({str(item).upper() for item in values if item})
        if "ALL" in added:
            return self._finding(
                resource_id,
                "docker.daemon.capabilities_all",
                Severity.HIGH,
                "Running Docker container adds all Linux capabilities",
                "Docker inspect reports CapAdd containing ALL.",
                "Drop ALL capabilities and add back only the specific capabilities required.",
                {"cap_add": added},
            )
        return self._pass(
            resource_id,
            "docker.daemon.capabilities_all",
            "Running container does not add the ALL capability set",
        )

    def _check_unconfined_security(
        self,
        resource_id: str,
        host_config: dict[str, Any],
    ) -> Finding:
        values = host_config.get("SecurityOpt")
        if not isinstance(values, list):
            values = []
        normalized = {str(item).lower() for item in values}
        matches = sorted(
            item
            for item in normalized
            if item in {
                "seccomp=unconfined",
                "seccomp:unconfined",
                "apparmor=unconfined",
                "apparmor:unconfined",
            }
        )
        if matches:
            return self._finding(
                resource_id,
                "docker.daemon.unconfined_security",
                Severity.HIGH,
                "Running Docker container disables a runtime confinement profile",
                "Docker inspect reports an unconfined seccomp or AppArmor security option.",
                "Use Docker's default confinement or a reviewed workload-specific profile.",
                {"security_options": matches},
            )
        return self._pass(
            resource_id,
            "docker.daemon.unconfined_security",
            "No selected unconfined Docker security option was observed",
        )

    def _check_runtime_user(
        self,
        resource_id: str,
        config: dict[str, Any],
    ) -> Finding:
        value = str(config.get("User") or "").strip()
        user = value.split(":", 1)[0].lower()
        if not user or user in {"0", "root"}:
            return self._finding(
                resource_id,
                "docker.daemon.root_user",
                Severity.HIGH,
                "Running Docker container is configured with the default/root user",
                (
                    "Docker inspect reports an empty, root, or UID 0 Config.User. The process can "
                    "still voluntarily drop privileges internally, so Blacklight reports the "
                    "container configuration rather than claiming every process remains root."
                ),
                "Configure the image/container to start as a dedicated non-root user.",
                {"configured_user": value or None},
            )
        return self._pass(
            resource_id,
            "docker.daemon.root_user",
            "Running container is configured with a non-root user",
        )

    def _check_published_ports(
        self,
        resource_id: str,
        network: dict[str, Any],
    ) -> Finding:
        ports = network.get("Ports")
        if not isinstance(ports, dict):
            ports = {}

        matches: list[dict[str, str]] = []
        for container_port, bindings in ports.items():
            if not isinstance(bindings, list):
                continue
            for binding in bindings:
                if not isinstance(binding, dict):
                    continue
                host_ip = str(binding.get("HostIp") or "")
                host_port = str(binding.get("HostPort") or "")
                if host_ip in {"", "0.0.0.0", "::"}:
                    matches.append(
                        {
                            "container_port": str(container_port),
                            "host_ip": host_ip or "all",
                            "host_port": host_port,
                        }
                    )

        if matches:
            return self._finding(
                resource_id,
                "docker.daemon.nonloopback_publish",
                Severity.LOW,
                "Running Docker container publishes ports on non-loopback interfaces",
                (
                    "Docker inspect reports one or more published ports bound to all host "
                    "interfaces. This is exposure inventory, not proof that the service is "
                    "reachable from the internet or vulnerable."
                ),
                "Confirm each published host port is intentional and constrained by host/network controls.",
                {"bindings": matches},
            )
        return self._pass(
            resource_id,
            "docker.daemon.nonloopback_publish",
            "No selected non-loopback Docker port publication was observed",
        )

    def _availability_info(self, message: str) -> Finding:
        return self._finding(
            "docker-daemon",
            "docker.daemon.connection",
            Severity.INFO,
            "Docker live-daemon inspection is not available",
            (
                "Blacklight could not use the local Docker CLI. Static Dockerfile scanning "
                "remains available independently."
            ),
            evidence={"reason": message},
        )

    def _error(self, stage: str, message: str) -> Finding:
        return self._finding(
            "docker-daemon",
            f"docker.daemon.{stage}",
            Severity.ERROR,
            f"Blacklight could not complete Docker {stage.replace('_', ' ')}",
            message,
            "Verify local Docker CLI/daemon access and retry the live daemon scan.",
        )

    @staticmethod
    def _pass(resource_id: str, check_id: str, title: str) -> Finding:
        return DockerDaemonScanner._finding(
            resource_id,
            check_id,
            Severity.PASS,
            title,
            title + ".",
        )

    @staticmethod
    def _finding(
        resource_id: str,
        check_id: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            provider="docker",
            service="daemon",
            resource_type="docker_container",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
