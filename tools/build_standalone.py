from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

from blacklight_security import __version__


ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = ROOT / "build" / "standalone"
PYINSTALLER_DIST = BUILD_ROOT / "pyinstaller-dist"
PYINSTALLER_WORK = BUILD_ROOT / "pyinstaller-work"
PYINSTALLER_SPEC = BUILD_ROOT / "pyinstaller-spec"
BUNDLE_ROOT = BUILD_ROOT / "bundle"
OUTPUT_ROOT = ROOT / "standalone-dist"
ENTRYPOINT = ROOT / "tools" / "standalone_entry.py"


def _platform_name() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system in {"windows", "linux"}:
        return system
    return system.replace(" ", "-")


def _architecture() -> str:
    machine = platform.machine().lower()
    aliases = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    return aliases.get(machine, machine.replace(" ", "-"))


def _run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def _executable_path() -> Path:
    name = "blacklight.exe" if os.name == "nt" else "blacklight"
    return PYINSTALLER_DIST / name


def _write_standalone_readme(path: Path) -> None:
    path.write_text(
        f"""Project Blacklight {__version__} standalone build

This archive contains a self-contained Project Blacklight command-line executable.
Python is not required on the target machine.

Quick start:
  blacklight --version
  blacklight scan aws

AWS authentication still uses the normal boto3/AWS credential chain. Configure
credentials through an AWS profile, environment variables, an instance/role
identity, or another supported boto3 credential source.

Examples:
  blacklight scan aws --profile blacklight-audit
  blacklight scan aws --fail-on high --require-full-coverage
  blacklight scan aws --format html --output blacklight-report.html

These early-alpha executables are not code-signed. Windows SmartScreen or macOS
Gatekeeper may therefore display a warning. Verify the release checksum before
running a downloaded artifact.

Repository:
  https://github.com/OloaneShark/Project_Blacklight
""",
        encoding="utf-8",
    )


def _archive_bundle(bundle_dir: Path, platform_name: str, architecture: str) -> Path:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    platform_label = {
        "windows": "Windows",
        "linux": "Linux",
        "macos": "MacOS",
    }.get(platform_name, platform_name.title())
    architecture_label = {
        "x86_64": "x64",
        "arm64": "ARM64",
    }.get(architecture, architecture)
    base_name = f"Project-Blacklight-{platform_label}-{architecture_label}"

    if platform_name == "windows":
        archive = OUTPUT_ROOT / f"{base_name}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
            for path in sorted(bundle_dir.rglob("*")):
                if path.is_file():
                    zip_file.write(path, Path(bundle_dir.name) / path.relative_to(bundle_dir))
        return archive

    archive = OUTPUT_ROOT / f"{base_name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar_file:
        tar_file.add(bundle_dir, arcname=bundle_dir.name)
    return archive


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    shutil.rmtree(BUILD_ROOT, ignore_errors=True)
    shutil.rmtree(OUTPUT_ROOT, ignore_errors=True)

    _run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onefile",
            "--noupx",
            "--name",
            "blacklight",
            "--distpath",
            str(PYINSTALLER_DIST),
            "--workpath",
            str(PYINSTALLER_WORK),
            "--specpath",
            str(PYINSTALLER_SPEC),
            "--collect-submodules",
            "blacklight_security",
            "--collect-all",
            "boto3",
            "--collect-all",
            "botocore",
            str(ENTRYPOINT),
        ]
    )

    executable = _executable_path()
    if not executable.exists():
        raise RuntimeError(f"PyInstaller did not create {executable}")

    if os.name != "nt":
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    expected_version = f"Project Blacklight {__version__}"
    completed = subprocess.run(
        [str(executable), "--version"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    actual_version = completed.stdout.strip()
    if actual_version != expected_version:
        raise RuntimeError(
            f"Standalone smoke test returned {actual_version!r}; expected {expected_version!r}"
        )

    platform_name = _platform_name()
    architecture = _architecture()
    bundle_dir = BUNDLE_ROOT / f"project-blacklight-{__version__}"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(executable, bundle_dir / executable.name)
    shutil.copy2(ROOT / "LICENSE", bundle_dir / "LICENSE")
    _write_standalone_readme(bundle_dir / "README-STANDALONE.txt")

    archive = _archive_bundle(bundle_dir, platform_name, architecture)
    checksum = _sha256(archive)

    print(f"Standalone executable: {executable}")
    print(f"Standalone archive: {archive}")
    print(f"SHA256: {checksum}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as output:
            output.write(f"archive={archive.as_posix()}\n")
            output.write(f"archive_name={archive.name}\n")
            output.write(f"platform={platform_name}\n")
            output.write(f"architecture={architecture}\n")
            output.write(f"sha256={checksum}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
