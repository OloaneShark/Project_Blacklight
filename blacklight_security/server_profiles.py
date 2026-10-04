from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_SERVER_TARGETS_FILE = Path.home() / ".blacklight" / "server-targets.toml"

_ALLOWED_PROFILE_KEYS = {
    "host",
    "user",
    "port",
    "identity_file",
    "connect_timeout",
}
_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


@dataclass(frozen=True, slots=True)
class ServerTargetProfile:
    name: str
    host: str
    user: str | None = None
    port: int = 22
    identity_file: Path | None = None
    connect_timeout: int = 10


class ServerTargetProfileError(ValueError):
    """Raised when a reusable server target profile is missing or invalid."""


def load_server_target_profile(
    name: str,
    path: Path | None = None,
) -> ServerTargetProfile:
    profile_name = name.strip()
    if not profile_name or not _PROFILE_NAME_RE.fullmatch(profile_name):
        raise ServerTargetProfileError(
            "server target profile names may contain only letters, numbers, dot, dash, and underscore"
        )

    profile_path = (path or DEFAULT_SERVER_TARGETS_FILE).expanduser()
    if not profile_path.is_file():
        raise ServerTargetProfileError(
            f"server target profile file not found: {profile_path}"
        )

    try:
        with profile_path.open("rb") as handle:
            payload = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise ServerTargetProfileError(
            f"invalid TOML in server target profile file {profile_path}: {error}"
        ) from error
    except OSError as error:
        raise ServerTargetProfileError(
            f"could not read server target profile file {profile_path}: {error}"
        ) from error

    targets = payload.get("targets")
    if not isinstance(targets, dict):
        raise ServerTargetProfileError(
            f"server target profile file {profile_path} must contain a [targets.<name>] table"
        )

    raw_profile = targets.get(profile_name)
    if not isinstance(raw_profile, dict):
        available = ", ".join(sorted(str(item) for item in targets)) or "none"
        raise ServerTargetProfileError(
            f"server target profile '{profile_name}' was not found in {profile_path}; "
            f"available profiles: {available}"
        )

    unknown = sorted(set(raw_profile) - _ALLOWED_PROFILE_KEYS)
    if unknown:
        raise ServerTargetProfileError(
            f"server target profile '{profile_name}' contains unsupported key(s): "
            f"{', '.join(unknown)}. Profiles may contain connection metadata only; "
            "passwords, secrets, private-key contents, and arbitrary SSH options are not supported."
        )

    host = _required_string(raw_profile, "host", profile_name)
    user = _optional_string(raw_profile, "user", profile_name)
    port = _bounded_int(raw_profile, "port", profile_name, default=22, minimum=1, maximum=65535)
    timeout = _bounded_int(
        raw_profile,
        "connect_timeout",
        profile_name,
        default=10,
        minimum=1,
        maximum=60,
    )

    identity_value = _optional_string(raw_profile, "identity_file", profile_name)
    identity_file = Path(identity_value).expanduser() if identity_value else None

    return ServerTargetProfile(
        name=profile_name,
        host=host,
        user=user,
        port=port,
        identity_file=identity_file,
        connect_timeout=timeout,
    )


def _required_string(payload: dict[str, Any], key: str, profile_name: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ServerTargetProfileError(
            f"server target profile '{profile_name}' requires a non-empty string '{key}'"
        )
    return value.strip()


def _optional_string(
    payload: dict[str, Any],
    key: str,
    profile_name: str,
) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ServerTargetProfileError(
            f"server target profile '{profile_name}' field '{key}' must be a non-empty string"
        )
    return value.strip()


def _bounded_int(
    payload: dict[str, Any],
    key: str,
    profile_name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    value = payload.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ServerTargetProfileError(
            f"server target profile '{profile_name}' field '{key}' must be an integer"
        )
    if not minimum <= value <= maximum:
        raise ServerTargetProfileError(
            f"server target profile '{profile_name}' field '{key}' must be between "
            f"{minimum} and {maximum}"
        )
    return value
