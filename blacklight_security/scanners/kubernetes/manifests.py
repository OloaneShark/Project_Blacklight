from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from blacklight_security.models import Finding, Severity


_SECRET_NAME_RE = re.compile(
    r"(?:^|_)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|AUTH_TOKEN)(?:$|_)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class KubernetesScanTarget:
    """Local Kubernetes manifest scan target passed through the shared runner."""

    path: Path
    region_name: None = None
    profile_name: None = None


class KubernetesManifestScanner:
    """Deterministic static checks for local Kubernetes YAML manifests."""

    def __init__(self, target: Any):
        self.target = Path(getattr(target, "path", target)).expanduser()

    def scan(self) -> list[Finding]:
        manifests = self._discover_manifests()
        if not manifests:
            return [
                self._finding(
                    str(self.target),
                    "kubernetes.manifest.discovery",
                    Severity.ERROR,
                    "Blacklight could not find Kubernetes YAML to inspect",
                    (
                        f"No .yaml or .yml manifest was found at or below {self.target}. "
                        "Use --path to select a manifest or project directory."
                    ),
                    "Point Blacklight at Kubernetes YAML or a directory containing manifests.",
                    {"scan_path": str(self.target)},
                )
            ]

        findings: list[Finding] = []
        for path in manifests:
            findings.extend(self._scan_file(path))
        return findings

    def _discover_manifests(self) -> list[Path]:
        if self.target.is_file():
            return [self.target] if self.target.suffix.lower() in {".yaml", ".yml"} else []
        if not self.target.exists() or not self.target.is_dir():
            return []

        ignored_dirs = {
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "build",
            "dist",
            "__pycache__",
            ".terraform",
            "vendor",
        }
        matches: list[Path] = []
        for path in self.target.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
                continue
            if any(part in ignored_dirs for part in path.parts):
                continue
            matches.append(path)
        return sorted(set(matches))

    def _scan_file(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            return [
                self._finding(
                    self._file_id(path),
                    "kubernetes.manifest.read",
                    Severity.ERROR,
                    "Blacklight could not read this Kubernetes manifest",
                    f"{type(error).__name__}: {error}",
                    "Verify the manifest is readable UTF-8 text and retry.",
                    {"path": str(path)},
                )
            ]

        try:
            documents = list(yaml.safe_load_all(text))
        except yaml.YAMLError as error:
            return [
                self._finding(
                    self._file_id(path),
                    "kubernetes.manifest.parse",
                    Severity.ERROR,
                    "Blacklight could not parse this Kubernetes manifest",
                    f"YAML parser error: {error}",
                    "Fix the YAML syntax and retry the Kubernetes scan.",
                    {"path": str(path)},
                )
            ]

        findings: list[Finding] = []
        for document in self._expand_documents(documents):
            pod_spec = self._pod_spec(document)
            if pod_spec is None:
                continue
            resource_id = self._resource_id(document, path)
            findings.extend(self._check_resource(resource_id, pod_spec))

        return findings

    @staticmethod
    def _expand_documents(documents: list[Any]) -> list[dict[str, Any]]:
        expanded: list[dict[str, Any]] = []
        for document in documents:
            if not isinstance(document, dict):
                continue
            if document.get("kind") == "List" and isinstance(document.get("items"), list):
                expanded.extend(item for item in document["items"] if isinstance(item, dict))
            else:
                expanded.append(document)
        return expanded

    @staticmethod
    def _pod_spec(document: dict[str, Any]) -> dict[str, Any] | None:
        kind = str(document.get("kind", ""))
        spec = document.get("spec")
        if not isinstance(spec, dict):
            return None

        if kind == "Pod":
            return spec
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController"}:
            template = spec.get("template", {})
            pod_spec = template.get("spec") if isinstance(template, dict) else None
            return pod_spec if isinstance(pod_spec, dict) else None
        if kind == "Job":
            template = spec.get("template", {})
            pod_spec = template.get("spec") if isinstance(template, dict) else None
            return pod_spec if isinstance(pod_spec, dict) else None
        if kind == "CronJob":
            job_template = spec.get("jobTemplate", {})
            job_spec = job_template.get("spec", {}) if isinstance(job_template, dict) else {}
            template = job_spec.get("template", {}) if isinstance(job_spec, dict) else {}
            pod_spec = template.get("spec") if isinstance(template, dict) else None
            return pod_spec if isinstance(pod_spec, dict) else None
        return None

    def _check_resource(
        self,
        resource_id: str,
        pod_spec: dict[str, Any],
    ) -> list[Finding]:
        containers = self._containers(pod_spec)
        return [
            self._check_privileged(resource_id, containers),
            self._check_root_user(resource_id, pod_spec, containers),
            self._check_privilege_escalation(resource_id, containers),
            self._check_host_namespaces(resource_id, pod_spec),
            self._check_host_path(resource_id, pod_spec),
            self._check_capabilities(resource_id, containers),
            self._check_seccomp(resource_id, pod_spec, containers),
            self._check_host_ports(resource_id, containers),
            self._check_images(resource_id, containers),
            self._check_literal_secret_env(resource_id, containers),
        ]

    @staticmethod
    def _containers(pod_spec: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        containers: list[tuple[str, dict[str, Any]]] = []
        for field in ("containers", "initContainers", "ephemeralContainers"):
            values = pod_spec.get(field, [])
            if not isinstance(values, list):
                continue
            for index, container in enumerate(values):
                if not isinstance(container, dict):
                    continue
                name = str(container.get("name") or f"{field}[{index}]")
                containers.append((name, container))
        return containers

    def _check_privileged(
        self,
        resource_id: str,
        containers: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        matches = [
            name
            for name, container in containers
            if self._security_context(container).get("privileged") is True
        ]
        if matches:
            return self._finding(
                resource_id,
                "kubernetes.manifest.privileged_container",
                Severity.CRITICAL,
                "Kubernetes workload contains a privileged container",
                "One or more containers explicitly set securityContext.privileged: true.",
                "Remove privileged mode and grant only the specific capabilities the workload requires.",
                {"containers": matches},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.privileged_container",
            "No explicitly privileged container was detected",
        )

    def _check_root_user(
        self,
        resource_id: str,
        pod_spec: dict[str, Any],
        containers: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        pod_security = pod_spec.get("securityContext", {})
        pod_root = isinstance(pod_security, dict) and pod_security.get("runAsUser") == 0
        matches = [
            name
            for name, container in containers
            if self._security_context(container).get("runAsUser") == 0
        ]
        if pod_root or matches:
            return self._finding(
                resource_id,
                "kubernetes.manifest.root_user",
                Severity.HIGH,
                "Kubernetes workload explicitly runs as UID 0",
                "The pod or one or more containers explicitly configure runAsUser: 0.",
                "Run the workload as a dedicated non-root UID and set runAsNonRoot where appropriate.",
                {"pod_run_as_user_zero": pod_root, "containers": matches},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.root_user",
            "No explicit runAsUser: 0 was detected",
        )

    def _check_privilege_escalation(
        self,
        resource_id: str,
        containers: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        matches = [
            name
            for name, container in containers
            if self._security_context(container).get("allowPrivilegeEscalation") is True
        ]
        if matches:
            return self._finding(
                resource_id,
                "kubernetes.manifest.privilege_escalation",
                Severity.HIGH,
                "Kubernetes workload explicitly allows privilege escalation",
                "One or more containers set allowPrivilegeEscalation: true.",
                "Set allowPrivilegeEscalation: false unless the workload has a documented requirement.",
                {"containers": matches},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.privilege_escalation",
            "No explicit allowPrivilegeEscalation: true was detected",
        )

    def _check_host_namespaces(
        self,
        resource_id: str,
        pod_spec: dict[str, Any],
    ) -> Finding:
        enabled = [
            field
            for field in ("hostNetwork", "hostPID", "hostIPC")
            if pod_spec.get(field) is True
        ]
        if enabled:
            return self._finding(
                resource_id,
                "kubernetes.manifest.host_namespace",
                Severity.HIGH,
                "Kubernetes workload shares host namespaces",
                "The pod explicitly enables one or more host namespace settings.",
                "Disable host namespace sharing unless it is required and tightly controlled.",
                {"enabled": enabled},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.host_namespace",
            "No host namespace sharing was explicitly enabled",
        )

    def _check_host_path(
        self,
        resource_id: str,
        pod_spec: dict[str, Any],
    ) -> Finding:
        volumes = pod_spec.get("volumes", [])
        matches: list[dict[str, str]] = []
        if isinstance(volumes, list):
            for volume in volumes:
                if not isinstance(volume, dict) or not isinstance(volume.get("hostPath"), dict):
                    continue
                matches.append(
                    {
                        "name": str(volume.get("name", "unnamed")),
                        "path": str(volume["hostPath"].get("path", "")),
                    }
                )
        if matches:
            return self._finding(
                resource_id,
                "kubernetes.manifest.host_path",
                Severity.HIGH,
                "Kubernetes workload mounts host filesystem paths",
                "One or more pod volumes use hostPath and can expose node filesystem content.",
                "Avoid hostPath where possible; otherwise restrict the path and mount permissions.",
                {"volumes": matches},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.host_path",
            "No hostPath volume was detected",
        )

    def _check_capabilities(
        self,
        resource_id: str,
        containers: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        matches: list[str] = []
        for name, container in containers:
            capabilities = self._security_context(container).get("capabilities", {})
            added = capabilities.get("add", []) if isinstance(capabilities, dict) else []
            if isinstance(added, list) and any(str(value).upper() == "ALL" for value in added):
                matches.append(name)
        if matches:
            return self._finding(
                resource_id,
                "kubernetes.manifest.capabilities_all",
                Severity.HIGH,
                "Kubernetes workload adds all Linux capabilities",
                "One or more containers explicitly add the ALL Linux capability set.",
                "Drop ALL capabilities and add back only the minimal capabilities required.",
                {"containers": matches},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.capabilities_all",
            "No container explicitly adds the ALL capability set",
        )

    def _check_seccomp(
        self,
        resource_id: str,
        pod_spec: dict[str, Any],
        containers: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        matches: list[str] = []
        pod_security = pod_spec.get("securityContext", {})
        pod_profile = pod_security.get("seccompProfile", {}) if isinstance(pod_security, dict) else {}
        if isinstance(pod_profile, dict) and str(pod_profile.get("type", "")).lower() == "unconfined":
            matches.append("pod")

        for name, container in containers:
            profile = self._security_context(container).get("seccompProfile", {})
            if isinstance(profile, dict) and str(profile.get("type", "")).lower() == "unconfined":
                matches.append(name)

        if matches:
            return self._finding(
                resource_id,
                "kubernetes.manifest.seccomp_unconfined",
                Severity.HIGH,
                "Kubernetes workload explicitly disables seccomp confinement",
                "The pod or a container explicitly selects seccompProfile.type: Unconfined.",
                "Use RuntimeDefault or a reviewed Localhost seccomp profile.",
                {"matches": matches},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.seccomp_unconfined",
            "No explicit Unconfined seccomp profile was detected",
        )

    def _check_host_ports(
        self,
        resource_id: str,
        containers: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        matches: list[dict[str, object]] = []
        for name, container in containers:
            ports = container.get("ports", [])
            if not isinstance(ports, list):
                continue
            for port in ports:
                if not isinstance(port, dict):
                    continue
                host_port = port.get("hostPort")
                if isinstance(host_port, int) and host_port > 0:
                    matches.append({"container": name, "hostPort": host_port})
        if matches:
            return self._finding(
                resource_id,
                "kubernetes.manifest.host_port",
                Severity.MEDIUM,
                "Kubernetes workload binds container ports directly to the node",
                "One or more containers explicitly configure hostPort.",
                "Prefer a Kubernetes Service unless direct node port binding is required.",
                {"matches": matches},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.host_port",
            "No explicit hostPort binding was detected",
        )

    def _check_images(
        self,
        resource_id: str,
        containers: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        matches: list[dict[str, str]] = []
        for name, container in containers:
            image = container.get("image")
            if not isinstance(image, str) or not image:
                continue
            if self._uses_implicit_or_latest_tag(image):
                matches.append({"container": name, "image": image})
        if matches:
            return self._finding(
                resource_id,
                "kubernetes.manifest.image_latest",
                Severity.MEDIUM,
                "Kubernetes workload uses an implicit or latest image tag",
                "One or more container images omit a tag or use the mutable latest tag.",
                "Pin workload images to an explicit version or immutable digest.",
                {"matches": matches},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.image_latest",
            "No implicit or latest container image tag was detected",
        )

    def _check_literal_secret_env(
        self,
        resource_id: str,
        containers: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        matches: list[dict[str, str]] = []
        for name, container in containers:
            env = container.get("env", [])
            if not isinstance(env, list):
                continue
            for item in env:
                if not isinstance(item, dict):
                    continue
                key = item.get("name")
                value = item.get("value")
                if (
                    isinstance(key, str)
                    and isinstance(value, str)
                    and value
                    and _SECRET_NAME_RE.search(key)
                ):
                    matches.append({"container": name, "name": key})

        if matches:
            return self._finding(
                resource_id,
                "kubernetes.manifest.literal_secret_env",
                Severity.HIGH,
                "Kubernetes workload embeds secret-like environment values",
                (
                    "One or more secret-like environment variable names use a literal value "
                    "instead of an external secret reference."
                ),
                "Use Secret/secretKeyRef or another external secret-injection mechanism.",
                {"matches": matches, "secret_values_redacted": True},
            )
        return self._pass(
            resource_id,
            "kubernetes.manifest.literal_secret_env",
            "No literal secret-like environment value was detected",
        )

    @staticmethod
    def _security_context(container: dict[str, Any]) -> dict[str, Any]:
        value = container.get("securityContext", {})
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _uses_implicit_or_latest_tag(image: str) -> bool:
        if "@" in image:
            return False
        final_component = image.rsplit("/", 1)[-1]
        if ":" not in final_component:
            return True
        return final_component.rsplit(":", 1)[1].lower() == "latest"

    def _file_id(self, path: Path) -> str:
        try:
            base = self.target if self.target.is_dir() else self.target.parent
            return str(path.resolve().relative_to(base.resolve()))
        except (OSError, ValueError):
            return str(path)

    def _resource_id(self, document: dict[str, Any], path: Path) -> str:
        metadata = document.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        kind = str(document.get("kind") or "Unknown")
        name = str(metadata.get("name") or self._file_id(path))
        namespace = str(metadata.get("namespace") or "default")
        return f"{kind}/{namespace}/{name}"

    @staticmethod
    def _pass(resource_id: str, check_id: str, title: str) -> Finding:
        return KubernetesManifestScanner._finding(
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
            provider="kubernetes",
            service="manifest",
            resource_type="kubernetes_workload",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
