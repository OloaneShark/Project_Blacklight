from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from blacklight_security.models import Severity
from blacklight_security.scanners.docker.dockerfile import DockerScanTarget
from blacklight_security.scanners.docker.image import DockerImageScanner
from blacklight_security.scanners.docker.sbom import OSVClient, OSVClientError


IMAGE_ID = "sha256:" + "a" * 64
IMAGE_REF = "example/app:1.2.3"


def _result(output: str, code: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, output, "")


def _sbom(*components: dict) -> str:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": list(components),
        }
    )


def _component() -> dict:
    return {
        "type": "library",
        "name": "example",
        "purl": "pkg:pypi/example",
        "version": "1.0.0",
    }


def _scanner(image_ref: str | None = IMAGE_REF) -> DockerImageScanner:
    return DockerImageScanner(DockerScanTarget(path=Path("."), image_ref=image_ref))


def test_image_scan_inventories_local_image_and_reuses_osv_matching():
    responses = [_result(IMAGE_ID), _result(_sbom(_component()))]
    record = {
        "id": "GHSA-example",
        "database_specific": {"severity": "HIGH"},
        "summary": "Test CVE",
    }
    with (
        patch(
            "blacklight_security.scanners.docker.image.subprocess.run",
            side_effect=responses,
        ) as run,
        patch.object(OSVClient, "query_batch", return_value=[{"GHSA-example"}]) as query,
        patch.object(
            OSVClient,
            "fetch_records",
            return_value=({"GHSA-example": record}, {}),
        ),
    ):
        findings = _scanner().scan()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.service == "image"
    assert finding.check_id == "docker.image.known_vulnerabilities"
    assert finding.resource_id == f"{IMAGE_ID}/pkg:pypi/example@1.0.0"
    assert finding.evidence["image"] == IMAGE_REF
    assert finding.evidence["image_id"] == IMAGE_ID
    assert finding.evidence["inventory_generator"] == "syft"
    query.assert_called_once_with(
        [{"package": {"purl": "pkg:pypi/example"}, "version": "1.0.0"}]
    )
    commands = [call.args[0] for call in run.call_args_list]
    assert commands == [
        ["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE_REF],
        ["syft", "scan", IMAGE_REF, "--from", "docker", "--output", "cyclonedx-json", "--quiet"],
    ]
    assert all(call.kwargs["shell"] is False for call in run.call_args_list)
    assert all(call.kwargs["timeout"] > 0 for call in run.call_args_list)
    assert not any(command[1:3] == ["image", "pull"] for command in commands)


def test_image_scan_no_known_matches_is_scoped_pass():
    with (
        patch(
            "blacklight_security.scanners.docker.image.subprocess.run",
            side_effect=[_result(IMAGE_ID), _result(_sbom(_component()))],
        ),
        patch.object(OSVClient, "query_batch", return_value=[set()]),
        patch.object(OSVClient, "fetch_records", return_value=({}, {})),
    ):
        findings = _scanner().scan()

    assert len(findings) == 1
    assert findings[0].check_id == "docker.image.known_vulnerabilities"
    assert findings[0].severity is Severity.PASS
    assert findings[0].resource_id == IMAGE_ID


def test_image_scan_requires_local_image_and_does_not_run_syft_when_missing():
    with patch(
        "blacklight_security.scanners.docker.image.subprocess.run",
        return_value=_result("", code=1),
    ) as run:
        findings = _scanner().scan()

    assert findings[0].check_id == "docker.image.local_image"
    assert findings[0].severity is Severity.ERROR
    assert run.call_count == 1


def test_image_scan_missing_syft_reports_error():
    with patch(
        "blacklight_security.scanners.docker.image.subprocess.run",
        side_effect=[_result(IMAGE_ID), FileNotFoundError],
    ):
        findings = _scanner().scan()

    assert findings[0].check_id == "docker.image.tooling"
    assert findings[0].severity is Severity.ERROR
    assert findings[0].evidence["tool"] == "syft"


def test_image_scan_malformed_or_incomplete_cyclonedx_is_not_clean():
    for payload in ("not-json", '{"bomFormat":"CycloneDX"}', '{"bomFormat":"SPDX","components":[]}'):
        with patch(
            "blacklight_security.scanners.docker.image.subprocess.run",
            side_effect=[_result(IMAGE_ID), _result(payload)],
        ):
            findings = _scanner().scan()

        assert len(findings) == 1
        assert findings[0].check_id == "docker.image.inventory"
        assert findings[0].severity is Severity.ERROR


def test_image_scan_partial_package_coordinates_remain_visible():
    with (
        patch(
            "blacklight_security.scanners.docker.image.subprocess.run",
            side_effect=[
                _result(IMAGE_ID),
                _result(_sbom(_component(), {"type": "library", "name": "unknown"})),
            ],
        ),
        patch.object(OSVClient, "query_batch", return_value=[set()]),
        patch.object(OSVClient, "fetch_records", return_value=({}, {})),
    ):
        findings = _scanner().scan()

    by_id = {finding.check_id: finding for finding in findings}
    assert by_id["docker.image.known_vulnerabilities"].severity is Severity.PASS
    assert by_id["docker.image.unqueryable_components"].severity is Severity.INFO
    assert by_id["docker.image.unqueryable_components"].evidence["skipped_components"] == 1


def test_image_scan_osv_failure_is_coverage_error():
    with (
        patch(
            "blacklight_security.scanners.docker.image.subprocess.run",
            side_effect=[_result(IMAGE_ID), _result(_sbom(_component()))],
        ),
        patch.object(OSVClient, "query_batch", side_effect=OSVClientError("offline")),
    ):
        findings = _scanner().scan()

    assert findings[0].severity is Severity.ERROR
    assert findings[0].check_id == "docker.image.osv_query"


def test_image_scan_no_image_in_all_mode_is_non_scoring_info():
    with patch("blacklight_security.scanners.docker.image.subprocess.run") as run:
        findings = _scanner(None).scan()

    assert findings[0].severity is Severity.INFO
    assert findings[0].check_id == "docker.image.target"
    run.assert_not_called()


def test_image_scan_rejects_option_like_image_reference():
    with patch("blacklight_security.scanners.docker.image.subprocess.run") as run:
        findings = _scanner("--help").scan()

    assert findings[0].severity is Severity.ERROR
    run.assert_not_called()
