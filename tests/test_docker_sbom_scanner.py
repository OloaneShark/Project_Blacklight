from __future__ import annotations

import json
from unittest.mock import patch

from blacklight_security.models import Severity
from blacklight_security.scanners.docker.dockerfile import DockerScanTarget
from blacklight_security.scanners.docker.sbom import (
    DockerSBOMScanner,
    OSVClient,
    OSVClientError,
)


def _cyclonedx(component):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [component],
    }


def test_sbom_scanner_queries_cyclonedx_package_and_maps_high_severity(tmp_path):
    path = tmp_path / "app.cdx.json"
    path.write_text(
        json.dumps(
            _cyclonedx(
                {
                    "type": "library",
                    "name": "jinja2",
                    "version": "2.4.1",
                    "purl": "pkg:pypi/jinja2",
                }
            )
        ),
        encoding="utf-8",
    )

    record = {
        "id": "GHSA-test",
        "summary": "Example vulnerability",
        "database_specific": {"severity": "HIGH"},
        "aliases": ["CVE-2099-0001"],
        "modified": "2099-01-01T00:00:00Z",
    }

    with (
        patch.object(OSVClient, "query_batch", return_value=[{"GHSA-test"}]) as query,
        patch.object(
            OSVClient,
            "fetch_records",
            return_value=({"GHSA-test": record}, {}),
        ),
    ):
        findings = DockerSBOMScanner(DockerScanTarget(path=path)).scan()

    finding = next(
        item
        for item in findings
        if item.check_id == "docker.sbom.known_vulnerabilities"
    )
    assert finding.severity is Severity.HIGH
    assert finding.resource_id == "pkg:pypi/jinja2@2.4.1"
    assert finding.evidence["vulnerability_count"] == 1
    assert finding.evidence["vulnerabilities"][0]["id"] == "GHSA-test"

    query.assert_called_once_with(
        [{"package": {"purl": "pkg:pypi/jinja2"}, "version": "2.4.1"}]
    )


def test_sbom_scanner_does_not_send_duplicate_version_for_versioned_purl(tmp_path):
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            _cyclonedx(
                {
                    "type": "library",
                    "name": "jinja2",
                    "version": "2.4.1",
                    "purl": "pkg:pypi/jinja2@2.4.1",
                }
            )
        ),
        encoding="utf-8",
    )

    with (
        patch.object(OSVClient, "query_batch", return_value=[set()]) as query,
        patch.object(OSVClient, "fetch_records", return_value=({}, {})),
    ):
        findings = DockerSBOMScanner(DockerScanTarget(path=path)).scan()

    query.assert_called_once_with(
        [{"package": {"purl": "pkg:pypi/jinja2@2.4.1"}}]
    )
    assert any(
        item.check_id == "docker.sbom.known_vulnerabilities"
        and item.severity is Severity.PASS
        for item in findings
    )


def test_sbom_scanner_reads_spdx_purl(tmp_path):
    path = tmp_path / "image.spdx.json"
    path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "requests",
                        "versionInfo": "2.31.0",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/requests",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with (
        patch.object(OSVClient, "query_batch", return_value=[set()]) as query,
        patch.object(OSVClient, "fetch_records", return_value=({}, {})),
    ):
        DockerSBOMScanner(DockerScanTarget(path=path)).scan()

    query.assert_called_once_with(
        [{"package": {"purl": "pkg:pypi/requests"}, "version": "2.31.0"}]
    )


def test_sbom_scanner_reports_info_when_no_sbom_exists(tmp_path):
    findings = DockerSBOMScanner(DockerScanTarget(path=tmp_path)).scan()

    assert len(findings) == 1
    assert findings[0].check_id == "docker.sbom.discovery"
    assert findings[0].severity is Severity.INFO


def test_sbom_scanner_reports_osv_query_failure_as_error(tmp_path):
    path = tmp_path / "sbom.json"
    path.write_text(
        json.dumps(
            _cyclonedx(
                {
                    "type": "library",
                    "name": "jinja2",
                    "version": "2.4.1",
                    "purl": "pkg:pypi/jinja2",
                }
            )
        ),
        encoding="utf-8",
    )

    with patch.object(
        OSVClient,
        "query_batch",
        side_effect=OSVClientError("network unavailable"),
    ):
        findings = DockerSBOMScanner(DockerScanTarget(path=path)).scan()

    finding = next(item for item in findings if item.check_id == "docker.sbom.osv_query")
    assert finding.severity is Severity.ERROR


def test_sbom_scanner_keeps_matched_ids_when_details_are_unavailable(tmp_path):
    path = tmp_path / "sbom.json"
    path.write_text(
        json.dumps(
            _cyclonedx(
                {
                    "type": "library",
                    "name": "jinja2",
                    "version": "2.4.1",
                    "purl": "pkg:pypi/jinja2",
                }
            )
        ),
        encoding="utf-8",
    )

    with (
        patch.object(OSVClient, "query_batch", return_value=[{"GHSA-test"}]),
        patch.object(
            OSVClient,
            "fetch_records",
            return_value=({}, {"GHSA-test": "detail unavailable"}),
        ),
    ):
        findings = DockerSBOMScanner(DockerScanTarget(path=path)).scan()

    assert any(
        item.check_id == "docker.sbom.osv_details"
        and item.severity is Severity.ERROR
        for item in findings
    )
    package = next(
        item
        for item in findings
        if item.check_id == "docker.sbom.known_vulnerabilities"
    )
    assert package.severity is Severity.INFO
    assert package.evidence["vulnerabilities"][0]["id"] == "GHSA-test"
    assert package.evidence["vulnerabilities"][0]["details_available"] is False


def test_osv_batch_pagination_accumulates_ids():
    client = OSVClient()
    query = {"package": {"purl": "pkg:pypi/example@1.0"}}

    with patch.object(
        client,
        "_request_json",
        side_effect=[
            {
                "results": [
                    {
                        "vulns": [{"id": "OSV-1"}],
                        "next_page_token": "next",
                    }
                ]
            },
            {
                "results": [
                    {
                        "vulns": [{"id": "OSV-2"}],
                    }
                ]
            },
        ],
    ) as request:
        results = client.query_batch([query])

    assert results == [{"OSV-1", "OSV-2"}]
    assert request.call_count == 2
    second_payload = request.call_args_list[1].args[1]
    assert second_payload["queries"][0]["page_token"] == "next"
