from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from blacklight_security import __version__


ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = ROOT / "build" / "desktop"
PYINSTALLER_DIST = BUILD_ROOT / "pyinstaller-dist"
PYINSTALLER_WORK = BUILD_ROOT / "pyinstaller-work"
PYINSTALLER_SPEC = BUILD_ROOT / "pyinstaller-spec"
OUTPUT_ROOT = ROOT / "desktop-dist"
ENTRYPOINT = ROOT / "tools" / "desktop_entry.py"


def _platform_name() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "MacOS"
    if system == "windows":
        return "Windows"
    if system == "linux":
        return "Linux"
    return platform.system().replace(" ", "-")


def _architecture() -> str:
    machine = platform.machine().lower()
    aliases = {
        "amd64": "x64",
        "x86_64": "x64",
        "aarch64": "ARM64",
        "arm64": "ARM64",
    }
    return aliases.get(machine, machine.replace(" ", "-"))


def _run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def _built_executable() -> Path:
    name = "Project-Blacklight-Desktop.exe" if os.name == "nt" else "Project-Blacklight-Desktop"
    return PYINSTALLER_DIST / name


def main() -> int:
    shutil.rmtree(BUILD_ROOT, ignore_errors=True)
    shutil.rmtree(OUTPUT_ROOT, ignore_errors=True)
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--noupx",
        "--name",
        "Project-Blacklight-Desktop",
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
    _run(command)

    executable = _built_executable()
    if not executable.exists():
        raise RuntimeError(f"PyInstaller did not create {executable}")

    if os.name != "nt":
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    env = os.environ.copy()
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    subprocess.run(
        [str(executable), "--smoke-test"],
        cwd=ROOT,
        env=env,
        check=True,
        timeout=90,
    )

    platform_name = _platform_name()
    architecture = _architecture()
    suffix = ".exe" if os.name == "nt" else ""
    output = OUTPUT_ROOT / f"Project-Blacklight-Desktop-{platform_name}-{architecture}{suffix}"
    shutil.copy2(executable, output)

    print(f"Desktop executable: {output}")
    print(f"Desktop version: {__version__}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as handle:
            handle.write(f"artifact={output.as_posix()}\n")
            handle.write(f"artifact_name={output.name}\n")
            handle.write(f"platform={platform_name}\n")
            handle.write(f"architecture={architecture}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
