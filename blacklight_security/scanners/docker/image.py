from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.docker.dockerfile import DockerScanTarget
from blacklight_security.scanners.docker.sbom import DockerSBOMScanner, SBOMPackage


_IMAGE_TIMEOUT = 20
_SYFT_TIMEOUT = 180
_MAX_SBOM_CHARS = 50_000_000


class DockerImageScanner:
    """Generate an SBOM from a local Docker image and match packages with OSV."""

    def __init__(self, target: Any):
        self.image_ref = getattr(target, "image_ref", None)
        self.matcher = DockerSBOMScanner(DockerScanTarget(path=Path(".")))

    def scan(self) -> list[Finding]:
        image_ref = self.image_ref
        if not isinstance(image_ref, str) or not image_ref.strip():
            return [self._error(
                "target",
                "Docker image reference is required",
                "Select an existing local image with --image.",
            )]
        image_ref = image_ref.strip()
        if image_ref.startswith("-") or any(ch.isspace() or ord(ch) < 32 for ch in image_ref):
            return [self._error(
                "target",
                "Docker image reference is not valid",
                "Use a Docker image reference without whitespace or leading options.",
            )]

        # Checking local availability before Syft prevents an implicit registry pull.
        try:
            inspected = self._run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
                _IMAGE_TIMEOUT,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
            return [self._tool_error("docker", error)]

        if inspected.returncode != 0:
            return [self._error(
                "local_image",
                "Docker image is not available locally",
                (
                    "The local Docker daemon could not inspect the requested image. "
                    "Build or pull it explicitly before scanning; Blacklight will not pull it."
                ),
                {"image": image_ref, "exit_code": inspected.returncode},
            )]

        image_id = inspected.stdout.strip()
        if not image_id.startswith("sha256:") or len(image_id) != 71:
            return [self._error(
                "image_id",
                "Docker image identity could not be verified",
                "docker image inspect returned no usable sha256 image ID.",
                {"image": image_ref},
            )]

        try:
            result = self._run(
                ["syft", "scan", image_ref, "--from", "docker",
                 "--output", "cyclonedx-json", "--quiet"],
                _SYFT_TIMEOUT,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
            return [self._tool_error("syft", error, image_ref=image_ref, image_id=image_id)]

        if result.returncode != 0:
            return [self._error(
                "inventory",
                "Syft could not inventory the selected Docker image",
                "Local image package discovery did not complete. No vulnerability-clean claim was made.",
                {"image": image_ref, "image_id": image_id, "exit_code": result.returncode},
            )]
        if len(result.stdout) > _MAX_SBOM_CHARS:
            return [self._error(
                "inventory",
                "Generated image SBOM exceeds the supported size limit",
                "The generated CycloneDX document was too large to process safely.",
                {"image": image_ref, "image_id": image_id},
            )]
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return [self._error(
                "inventory",
                "Syft returned invalid CycloneDX JSON",
                "The image package inventory could not be parsed. No clean result was inferred.",
                {"image": image_ref, "image_id": image_id},
            )]

        if not isinstance(payload, dict) or str(payload.get("bomFormat") or "").lower() != "cyclonedx":
            return [self._error(
                "inventory",
                "Syft did not return a CycloneDX SBOM",
                "The generated payload is not a supported CycloneDX JSON object.",
                {"image": image_ref, "image_id": image_id},
            )]

        components = payload.get("components")
        if not isinstance(components, list):
            return [self._error(
                "inventory",
                "Generated CycloneDX SBOM lacks a package component list",
                "Blacklight cannot establish package inventory coverage without a components array.",
                {"image": image_ref, "image_id": image_id},
            )]

        package_source = f"image:{image_id}"
        packages, skipped = self.matcher._parse_cyclonedx(payload, Path(package_source))
        unique = {package.query_key: package for package in packages}

        matched = self.matcher.scan_packages(
            list(unique.values()),
            skipped_components=skipped,
            sources=[package_source],
            source_label=package_source,
        )
        return [
            self._image_finding(finding, image_ref=image_ref, image_id=image_id)
            for finding in matched
        ]

    @staticmethod
    def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            check=False, shell=False,
        )

    def _tool_error(
        self,
        tool: str,
        error: Exception,
        *,
        image_ref: str | None = None,
        image_id: str | None = None,
    ) -> Finding:
        problem = (
            "not installed or not available on PATH"
            if isinstance(error, FileNotFoundError)
            else "timed out" if isinstance(error, subprocess.TimeoutExpired)
            else "could not be started"
        )
        return self._error(
            "tooling",
            f"{tool} {problem}",
            (
                "This scan requires a working local Docker daemon and the Syft CLI. "
                "Image inventory could not be completed; no vulnerability-clean claim was made."
            ),
            {"tool": tool, "image": image_ref, "image_id": image_id, "reason": problem},
        )

    @staticmethod
    def _image_finding(finding: Finding, *, image_ref: str, image_id: str) -> Finding:
        is_package = finding.check_id == "docker.sbom.known_vulnerabilities"
        resource_id = (
            f"{image_id}/{finding.resource_id}"
            if is_package and finding.resource_id not in {"SBOM", "osv.dev"}
            else image_id
        )
        return replace(
            finding,
            service="image",
            check_id=finding.check_id.replace("docker.sbom.", "docker.image.", 1),
            resource_type="docker_image_package" if is_package else "docker_image",
            resource_id=resource_id,
            evidence={
                **finding.evidence,
                "image": image_ref,
                "image_id": image_id,
                "inventory_generator": "syft",
            },
        )

    @staticmethod
    def _error(
        stage: str,
        title: str,
        description: str,
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            check_id=f"docker.image.{stage}",
            provider="docker",
            service="image",
            resource_type="docker_image",
            resource_id=str((evidence or {}).get("image_id") or (evidence or {}).get("image") or "local-image"),
            severity=Severity.ERROR,
            title=title,
            description=description,
            remediation="Verify Docker, install Syft, and rerun the image scan.",
            evidence=evidence or {},
        )
