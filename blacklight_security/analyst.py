from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


class AnalystError(RuntimeError):
    """Raised when an optional external analyst cannot be executed safely."""


def load_report(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AnalystError(f"Could not read Blacklight JSON report: {error}") from error

    if not isinstance(payload, dict):
        raise AnalystError("Blacklight analyst input must be a JSON object.")
    if payload.get("tool") != "project-blacklight":
        raise AnalystError("Input is not a Project Blacklight JSON report.")
    if not isinstance(payload.get("findings"), list):
        raise AnalystError("Blacklight JSON report is missing the findings list.")
    return payload


def run_external_analyst(
    payload: dict[str, Any],
    command: str,
    arguments: list[str] | None = None,
    timeout_seconds: int = 60,
) -> str:
    if timeout_seconds < 1 or timeout_seconds > 600:
        raise AnalystError("Analyst timeout must be between 1 and 600 seconds.")

    executable = shutil.which(command)
    if executable is None:
        candidate = Path(command).expanduser()
        if candidate.is_file():
            executable = str(candidate)
        else:
            raise AnalystError(f"Analyst command was not found: {command}")

    argv = [executable, *(arguments or [])]
    report_json = json.dumps(payload, indent=2, sort_keys=True)

    try:
        completed = subprocess.run(
            argv,
            input=report_json,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as error:
        raise AnalystError(
            f"Analyst command exceeded the {timeout_seconds}-second timeout."
        ) from error
    except OSError as error:
        raise AnalystError(f"Could not start analyst command: {error}") from error

    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit code {completed.returncode}"
        raise AnalystError(f"Analyst command failed: {detail}")

    output = completed.stdout.strip()
    if not output:
        raise AnalystError("Analyst command returned no output.")
    return output
