from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blacklight_security.models import Finding, Severity


_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|AUTH_TOKEN)(?:$|_)",
    re.IGNORECASE,
)
_REMOTE_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_REMOTE_SHELL_RE = re.compile(
    r"(?:curl|wget)\b[^|;&]*\|\s*(?:/bin/)?(?:ba)?sh\b",
    re.IGNORECASE,
)
_CHMOD_777_RE = re.compile(r"\bchmod\b[^;&|\n]*\b777\b", re.IGNORECASE)


@dataclass(slots=True)
class DockerScanTarget:
    """Local Docker scan target passed through the shared Blacklight runner."""

    path: Path
    region_name: None = None
    profile_name: None = None


@dataclass(frozen=True, slots=True)
class DockerInstruction:
    name: str
    value: str
    line: int


class DockerfileScanner:
    """Deterministic static checks for local Dockerfiles."""

    def __init__(self, target: Any):
        self.target = Path(getattr(target, "path", target)).expanduser()

    def scan(self) -> list[Finding]:
        dockerfiles = self._discover_dockerfiles()
        if not dockerfiles:
            return [
                self._finding(
                    resource_id=str(self.target),
                    check_id="docker.dockerfile.discovery",
                    severity=Severity.ERROR,
                    title="Blacklight could not find a Dockerfile to inspect",
                    description=(
                        f"No Dockerfile was found at or below {self.target}. "
                        "Use --path to select a Dockerfile or project directory."
                    ),
                    remediation="Point Blacklight at a Dockerfile or a directory containing one.",
                    evidence={"scan_path": str(self.target)},
                )
            ]

        findings: list[Finding] = []
        for dockerfile in dockerfiles:
            findings.extend(self._scan_file(dockerfile))
        return findings

    def _discover_dockerfiles(self) -> list[Path]:
        if self.target.is_file():
            return [self.target]
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
        }
        matches: list[Path] = []
        for path in self.target.rglob("*"):
            if not path.is_file():
                continue
            if any(part in ignored_dirs for part in path.parts):
                continue
            name = path.name
            if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
                matches.append(path)
        return sorted(set(matches))

    def _scan_file(self, path: Path) -> list[Finding]:
        resource_id = self._resource_id(path)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            return [
                self._finding(
                    resource_id,
                    "docker.dockerfile.read",
                    Severity.ERROR,
                    "Blacklight could not read this Dockerfile",
                    f"{type(error).__name__}: {error}",
                    "Verify the file is readable UTF-8 text and retry the scan.",
                    {"path": str(path)},
                )
            ]

        instructions = self._parse_instructions(text)
        findings: list[Finding] = []
        findings.extend(self._check_base_images(resource_id, instructions))
        findings.append(self._check_runtime_user(resource_id, instructions))
        findings.extend(self._check_embedded_secrets(resource_id, instructions))
        findings.extend(self._check_remote_add(resource_id, instructions))
        findings.extend(self._check_remote_shell_pipe(resource_id, instructions))
        findings.extend(self._check_world_writable(resource_id, instructions))
        return findings

    def _resource_id(self, path: Path) -> str:
        try:
            base = self.target if self.target.is_dir() else self.target.parent
            return str(path.resolve().relative_to(base.resolve()))
        except (OSError, ValueError):
            return str(path)

    @staticmethod
    def _parse_instructions(text: str) -> list[DockerInstruction]:
        logical_lines: list[tuple[int, str]] = []
        current = ""
        start_line = 1

        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not current and (not stripped or stripped.startswith("#")):
                continue

            if not current:
                start_line = line_number

            continued = stripped.endswith("\\")
            piece = stripped[:-1].rstrip() if continued else stripped
            current = f"{current} {piece}".strip()

            if not continued:
                if current and not current.startswith("#"):
                    logical_lines.append((start_line, current))
                current = ""

        if current:
            logical_lines.append((start_line, current))

        instructions: list[DockerInstruction] = []
        for line_number, line in logical_lines:
            parts = line.split(None, 1)
            name = parts[0].upper()
            value = parts[1].strip() if len(parts) > 1 else ""
            instructions.append(DockerInstruction(name, value, line_number))
        return instructions

    def _check_base_images(
        self,
        resource_id: str,
        instructions: list[DockerInstruction],
    ) -> list[Finding]:
        from_instructions = [item for item in instructions if item.name == "FROM"]
        if not from_instructions:
            return [
                self._finding(
                    resource_id,
                    "docker.dockerfile.base_image",
                    Severity.ERROR,
                    "Dockerfile has no FROM instruction",
                    "Blacklight could not identify a container base image.",
                    "Add a valid FROM instruction and retry the scan.",
                )
            ]

        findings: list[Finding] = []
        risky: list[dict[str, object]] = []
        for instruction in from_instructions:
            image = self._from_image(instruction.value)
            if not image or image.lower() == "scratch":
                continue
            if self._uses_implicit_or_latest_tag(image):
                risky.append({"image": image, "line": instruction.line})

        if risky:
            findings.append(
                self._finding(
                    resource_id,
                    "docker.dockerfile.base_image_latest",
                    Severity.MEDIUM,
                    "Dockerfile uses an implicit or latest base-image tag",
                    (
                        "One or more FROM instructions use an image without an explicit tag "
                        "or use the mutable latest tag."
                    ),
                    (
                        "Pin each base image to an explicit version tag or, for stronger "
                        "reproducibility, an immutable digest."
                    ),
                    {"matches": risky},
                )
            )
        else:
            findings.append(
                self._finding(
                    resource_id,
                    "docker.dockerfile.base_image_latest",
                    Severity.PASS,
                    "Dockerfile avoids implicit and latest base-image tags",
                    "Blacklight did not find an implicit or latest tag in FROM instructions.",
                )
            )
        return findings

    @staticmethod
    def _from_image(value: str) -> str | None:
        try:
            tokens = shlex.split(value)
        except ValueError:
            tokens = value.split()

        for token in tokens:
            if token.startswith("--"):
                continue
            return token
        return None

    @staticmethod
    def _uses_implicit_or_latest_tag(image: str) -> bool:
        if "@" in image:
            return False
        final_component = image.rsplit("/", 1)[-1]
        if ":" not in final_component:
            return True
        return final_component.rsplit(":", 1)[1].lower() == "latest"

    def _check_runtime_user(
        self,
        resource_id: str,
        instructions: list[DockerInstruction],
    ) -> Finding:
        final_from_index = max(
            (index for index, item in enumerate(instructions) if item.name == "FROM"),
            default=-1,
        )
        final_stage = instructions[final_from_index + 1 :]
        user_instructions = [item for item in final_stage if item.name == "USER"]

        if not user_instructions:
            return self._finding(
                resource_id,
                "docker.dockerfile.root_user",
                Severity.HIGH,
                "Final container stage runs as root by default",
                (
                    "The final Dockerfile stage has no USER instruction. Docker therefore "
                    "runs the container as root unless runtime configuration overrides it."
                ),
                "Add a dedicated non-root USER in the final image stage.",
                {"final_stage_user": None},
            )

        final_user = user_instructions[-1]
        user_value = final_user.value.split(":", 1)[0].strip().lower()
        if user_value in {"root", "0"}:
            return self._finding(
                resource_id,
                "docker.dockerfile.root_user",
                Severity.HIGH,
                "Final container stage explicitly runs as root",
                f"The final USER instruction selects {final_user.value!r}.",
                "Run the final image as a dedicated non-root user.",
                {"final_stage_user": final_user.value, "line": final_user.line},
            )

        if "$" in user_value:
            return self._finding(
                resource_id,
                "docker.dockerfile.root_user",
                Severity.INFO,
                "Final container user is resolved from a variable",
                (
                    f"The final USER instruction selects {final_user.value!r}. "
                    "Blacklight cannot prove the resolved runtime user from static Dockerfile text."
                ),
                evidence={
                    "final_stage_user": final_user.value,
                    "line": final_user.line,
                    "statically_resolved": False,
                },
            )

        return self._finding(
            resource_id,
            "docker.dockerfile.root_user",
            Severity.PASS,
            "Final container stage selects a non-root user",
            f"The final USER instruction selects {final_user.value!r}.",
            evidence={"final_stage_user": final_user.value, "line": final_user.line},
        )

    def _check_embedded_secrets(
        self,
        resource_id: str,
        instructions: list[DockerInstruction],
    ) -> list[Finding]:
        matches: list[dict[str, object]] = []
        for instruction in instructions:
            if instruction.name == "ARG":
                key, value = self._arg_key_value(instruction.value)
                if key and value and _SECRET_KEY_RE.search(key):
                    matches.append(
                        {
                            "instruction": "ARG",
                            "key": key,
                            "line": instruction.line,
                        }
                    )
            elif instruction.name == "ENV":
                for key, value in self._env_key_values(instruction.value):
                    if value and _SECRET_KEY_RE.search(key):
                        matches.append(
                            {
                                "instruction": "ENV",
                                "key": key,
                                "line": instruction.line,
                            }
                        )

        if matches:
            return [
                self._finding(
                    resource_id,
                    "docker.dockerfile.embedded_secret",
                    Severity.HIGH,
                    "Dockerfile may embed secret material through ARG or ENV",
                    (
                        "Blacklight found secret-like ARG/ENV keys with values in the Dockerfile. "
                        "Build arguments and environment instructions can persist sensitive data "
                        "in image metadata or layers."
                    ),
                    (
                        "Use runtime secret injection or BuildKit secret mounts instead of placing "
                        "credentials in Dockerfile ARG/ENV values."
                    ),
                    {"matches": matches, "secret_values_redacted": True},
                )
            ]

        return [
            self._finding(
                resource_id,
                "docker.dockerfile.embedded_secret",
                Severity.PASS,
                "No secret-like ARG or ENV values were detected",
                "Blacklight did not find populated secret-like keys in ARG or ENV instructions.",
            )
        ]

    @staticmethod
    def _arg_key_value(value: str) -> tuple[str | None, str | None]:
        if "=" not in value:
            key = value.strip()
            return (key or None, None)
        key, raw_value = value.split("=", 1)
        return (key.strip() or None, raw_value.strip() or None)

    @staticmethod
    def _env_key_values(value: str) -> list[tuple[str, str]]:
        try:
            tokens = shlex.split(value)
        except ValueError:
            tokens = value.split()

        pairs: list[tuple[str, str]] = []
        if any("=" in token for token in tokens):
            for token in tokens:
                if "=" not in token:
                    continue
                key, raw_value = token.split("=", 1)
                if key:
                    pairs.append((key, raw_value))
            return pairs

        if len(tokens) >= 2:
            pairs.append((tokens[0], " ".join(tokens[1:])))
        return pairs

    def _check_remote_add(
        self,
        resource_id: str,
        instructions: list[DockerInstruction],
    ) -> list[Finding]:
        matches: list[dict[str, object]] = []
        for instruction in instructions:
            if instruction.name != "ADD":
                continue
            try:
                tokens = shlex.split(instruction.value)
            except ValueError:
                tokens = instruction.value.split()
            if any(token.startswith("--checksum=") for token in tokens):
                continue
            for token in tokens[:-1]:
                if _REMOTE_URL_RE.match(token):
                    matches.append({"source": token, "line": instruction.line})

        if matches:
            return [
                self._finding(
                    resource_id,
                    "docker.dockerfile.remote_add",
                    Severity.MEDIUM,
                    "Dockerfile ADD fetches remote content",
                    "ADD downloads one or more HTTP(S) resources during the image build.",
                    (
                        "Download and verify remote artifacts explicitly, preferably with a "
                        "cryptographic checksum, before copying them into the image."
                    ),
                    {"matches": matches},
                )
            ]

        return [
            self._finding(
                resource_id,
                "docker.dockerfile.remote_add",
                Severity.PASS,
                "No remote ADD source was detected",
                "Blacklight did not find HTTP(S) sources in ADD instructions.",
            )
        ]

    def _check_remote_shell_pipe(
        self,
        resource_id: str,
        instructions: list[DockerInstruction],
    ) -> list[Finding]:
        matches = [
            {"line": item.line}
            for item in instructions
            if item.name == "RUN" and _REMOTE_SHELL_RE.search(item.value)
        ]
        if matches:
            return [
                self._finding(
                    resource_id,
                    "docker.dockerfile.remote_shell_pipe",
                    Severity.HIGH,
                    "Dockerfile pipes a remote download directly into a shell",
                    (
                        "A RUN instruction downloads content with curl/wget and pipes it directly "
                        "to sh/bash, executing remote content without an explicit integrity check."
                    ),
                    (
                        "Download the artifact first, verify its expected checksum/signature, "
                        "then execute the verified local file."
                    ),
                    {"matches": matches},
                )
            ]

        return [
            self._finding(
                resource_id,
                "docker.dockerfile.remote_shell_pipe",
                Severity.PASS,
                "No direct remote-download-to-shell pipeline was detected",
                "Blacklight did not find curl/wget output piped directly into sh/bash.",
            )
        ]

    def _check_world_writable(
        self,
        resource_id: str,
        instructions: list[DockerInstruction],
    ) -> list[Finding]:
        matches = [
            {"line": item.line}
            for item in instructions
            if item.name == "RUN" and _CHMOD_777_RE.search(item.value)
        ]
        if matches:
            return [
                self._finding(
                    resource_id,
                    "docker.dockerfile.world_writable_permissions",
                    Severity.MEDIUM,
                    "Dockerfile creates world-writable permissions",
                    "A RUN instruction applies chmod 777.",
                    (
                        "Grant only the owner/group permissions required by the application "
                        "instead of world-write access."
                    ),
                    {"matches": matches},
                )
            ]

        return [
            self._finding(
                resource_id,
                "docker.dockerfile.world_writable_permissions",
                Severity.PASS,
                "No chmod 777 instruction was detected",
                "Blacklight did not find world-writable chmod 777 commands.",
            )
        ]

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
            service="dockerfile",
            resource_type="dockerfile",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
