from __future__ import annotations

from pathlib import Path

import pytest

from blacklight_security.server_profiles import (
    ServerTargetProfileError,
    load_server_target_profile,
)


def test_load_server_target_profile_reads_connection_metadata(tmp_path):
    profile_file = tmp_path / "targets.toml"
    profile_file.write_text(
        """
[targets.prod]
host = "server.example.com"
user = "blacklight-audit"
port = 2222
identity_file = "~/.ssh/blacklight_audit"
connect_timeout = 7
""".strip()
        + "\n",
        encoding="utf-8",
    )

    profile = load_server_target_profile("prod", profile_file)

    assert profile.name == "prod"
    assert profile.host == "server.example.com"
    assert profile.user == "blacklight-audit"
    assert profile.port == 2222
    assert profile.identity_file == Path("~/.ssh/blacklight_audit").expanduser()
    assert profile.connect_timeout == 7


def test_server_target_profile_rejects_secret_or_unknown_keys(tmp_path):
    profile_file = tmp_path / "targets.toml"
    profile_file.write_text(
        """
[targets.prod]
host = "server.example.com"
password = "do-not-store-this"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ServerTargetProfileError, match="unsupported key"):
        load_server_target_profile("prod", profile_file)


def test_server_target_profile_reports_available_names(tmp_path):
    profile_file = tmp_path / "targets.toml"
    profile_file.write_text(
        """
[targets.prod]
host = "prod.example.com"

[targets.staging]
host = "staging.example.com"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ServerTargetProfileError, match="prod, staging"):
        load_server_target_profile("missing", profile_file)


def test_server_target_profile_validates_bounds(tmp_path):
    profile_file = tmp_path / "targets.toml"
    profile_file.write_text(
        """
[targets.prod]
host = "server.example.com"
port = 70000
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ServerTargetProfileError, match="between 1 and 65535"):
        load_server_target_profile("prod", profile_file)
