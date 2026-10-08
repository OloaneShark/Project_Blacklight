from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from blacklight_security.models import Finding, Severity


_OSV_BASE_URL = "https://api.osv.dev"
_SBOM_NAMES = {
    "bom.json",
    "sbom.json",
}
_IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "build",
    "dist",
    "__pycache__",
}
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class SBOMPackage:
    purl: str
    version: str | None
    source: str

    @property
    def query_key(self) -> str:
        if _purl_has_version(self.purl) or not self.version:
            return self.purl
        return _purl_with_version(self.purl, self.version)


class OSVClientError(RuntimeError):
    pass


class OSVClient:
    """Small stdlib-only OSV client used for deterministic package-version queries."""

    def __init__(self, base_url: str = _OSV_BASE_URL, timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def query_batch(self, queries: list[dict[str, Any]]) -> list[set[str]]:
        results: list[set[str]] = [set() for _ in queries]

        for offset in range(0, len(queries), 500):
            chunk = queries[offset : offset + 500]
            payload = self._request_json(
                "/v1/querybatch",
                {"queries": chunk},
            )
            response_results = payload.get("results")
            if not isinstance(response_results, list) or len(response_results) != len(chunk):
                raise OSVClientError("OSV querybatch returned an unexpected result shape")

            pending: list[tuple[int, dict[str, Any], str]] = []
            for index, item in enumerate(response_results):
                if not isinstance(item, dict):
                    raise OSVClientError("OSV querybatch returned a non-object result")
                absolute_index = offset + index
                results[absolute_index].update(self._vulnerability_ids(item))
                token = item.get("next_page_token")
                if isinstance(token, str) and token:
                    pending.append((absolute_index, chunk[index], token))

            page_count = 0
            while pending:
                page_count += 1
                if page_count > 10:
                    raise OSVClientError("OSV querybatch pagination exceeded the safety limit")

                page_queries = []
                for _, original, token in pending:
                    query = dict(original)
                    query["page_token"] = token
                    page_queries.append(query)

                page_payload = self._request_json(
                    "/v1/querybatch",
                    {"queries": page_queries},
                )
                page_results = page_payload.get("results")
                if not isinstance(page_results, list) or len(page_results) != len(pending):
                    raise OSVClientError("OSV querybatch pagination returned an unexpected result shape")

                next_pending: list[tuple[int, dict[str, Any], str]] = []
                for page_item, (absolute_index, original, _) in zip(
                    page_results,
                    pending,
                    strict=True,
                ):
                    if not isinstance(page_item, dict):
                        raise OSVClientError("OSV querybatch pagination returned a non-object result")
                    results[absolute_index].update(self._vulnerability_ids(page_item))
                    token = page_item.get("next_page_token")
                    if isinstance(token, str) and token:
                        next_pending.append((absolute_index, original, token))
                pending = next_pending

        return results

    def fetch_records(
        self,
        vulnerability_ids: set[str],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        records: dict[str, dict[str, Any]] = {}
        errors: dict[str, str] = {}
        if not vulnerability_ids:
            return records, errors

        def fetch_one(vulnerability_id: str) -> tuple[str, dict[str, Any]]:
            payload = self._request_json(
                f"/v1/vulns/{quote(vulnerability_id, safe='')}",
                None,
            )
            return vulnerability_id, payload

        workers = min(8, max(1, len(vulnerability_ids)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(fetch_one, vulnerability_id): vulnerability_id
                for vulnerability_id in sorted(vulnerability_ids)
            }
            for future in as_completed(futures):
                vulnerability_id = futures[future]
                try:
                    record_id, payload = future.result()
                except OSVClientError as error:
                    errors[vulnerability_id] = str(error)
                    continue
                records[record_id] = payload

        return records, errors

    @staticmethod
    def _vulnerability_ids(payload: dict[str, Any]) -> set[str]:
        vulns = payload.get("vulns")
        if not isinstance(vulns, list):
            return set()
        return {
            str(item.get("id"))
            for item in vulns
            if isinstance(item, dict) and item.get("id")
        }

    def _request_json(
        self,
        path: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        data = None
        headers = {
            "Accept": "application/json",
            "User-Agent": "Project-Blacklight/OSV",
        }
        method = "GET"

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
            method = "POST"

        request = Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise OSVClientError(f"OSV request failed: {type(error).__name__}: {error}") from error

        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise OSVClientError(f"OSV returned invalid JSON: {error}") from error
        if not isinstance(parsed, dict):
            raise OSVClientError("OSV returned a non-object JSON response")
        return parsed


class DockerSBOMScanner:
    """Scan versioned SBOM package coordinates against OSV.dev."""

    def __init__(self, target: Any):
        self.target = Path(getattr(target, "path", target)).expanduser()
        self.osv = OSVClient()

    def scan(self) -> list[Finding]:
        sbom_files = self._discover_sboms()
        if not sbom_files:
            return [
                self._finding(
                    str(self.target),
                    "docker.sbom.discovery",
                    Severity.INFO,
                    "No supported SBOM file was found",
                    (
                        "Blacklight did not find a CycloneDX/SPDX JSON SBOM at the selected path. "
                        "No vulnerability-clean claim was made."
                    ),
                    evidence={"scan_path": str(self.target)},
                )
            ]

        findings: list[Finding] = []
        packages_by_key: dict[str, SBOMPackage] = {}
        skipped_components = 0

        for path in sbom_files:
            try:
                packages, skipped = self._parse_sbom(path)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
                findings.append(
                    self._finding(
                        str(path),
                        "docker.sbom.parse",
                        Severity.ERROR,
                        "Blacklight could not parse this SBOM",
                        f"{type(error).__name__}: {error}",
                        "Verify the SBOM is valid CycloneDX or SPDX JSON and retry.",
                        {"path": str(path)},
                    )
                )
                continue

            skipped_components += skipped
            for package in packages:
                packages_by_key.setdefault(package.query_key, package)

        packages = list(packages_by_key.values())
        if not packages:
            findings.append(
                self._finding(
                    str(self.target),
                    "docker.sbom.packages",
                    Severity.INFO,
                    "SBOM contains no queryable versioned package URLs",
                    (
                        "Blacklight found SBOM input but no package coordinates it can safely "
                        "submit to OSV. No vulnerability-clean claim was made."
                    ),
                    evidence={
                        "sbom_files": [str(path) for path in sbom_files],
                        "skipped_components": skipped_components,
                    },
                )
            )
            return findings

        queries = [self._osv_query(package) for package in packages]
        try:
            vulnerability_sets = self.osv.query_batch(queries)
        except OSVClientError as error:
            findings.append(
                self._finding(
                    "osv.dev",
                    "docker.sbom.osv_query",
                    Severity.ERROR,
                    "Blacklight could not query OSV vulnerability data",
                    str(error),
                    "Verify network access to api.osv.dev and retry the SBOM scan.",
                    {
                        "package_count": len(packages),
                        "sbom_files": [str(path) for path in sbom_files],
                    },
                )
            )
            return findings

        all_ids = set().union(*vulnerability_sets) if vulnerability_sets else set()
        records, record_errors = self.osv.fetch_records(all_ids)

        if record_errors:
            findings.append(
                self._finding(
                    "osv.dev",
                    "docker.sbom.osv_details",
                    Severity.ERROR,
                    "Blacklight could not retrieve some OSV vulnerability details",
                    (
                        "OSV package matching completed, but one or more vulnerability detail "
                        "records could not be retrieved. Matching IDs are still reported, but "
                        "their severity may remain unscored."
                    ),
                    "Retry when OSV detail records are reachable.",
                    {
                        "failed_ids": sorted(record_errors),
                        "failed_count": len(record_errors),
                    },
                )
            )

        vulnerable_packages = 0
        for package, vulnerability_ids in zip(
            packages,
            vulnerability_sets,
            strict=True,
        ):
            if not vulnerability_ids:
                continue
            vulnerable_packages += 1
            findings.append(
                self._package_finding(
                    package,
                    vulnerability_ids,
                    records,
                )
            )

        if vulnerable_packages == 0:
            findings.append(
                self._finding(
                    "SBOM",
                    "docker.sbom.known_vulnerabilities",
                    Severity.PASS,
                    "OSV returned no known vulnerabilities for queryable SBOM packages",
                    (
                        "OSV returned no vulnerability IDs for the exact package coordinates "
                        "Blacklight submitted from the selected SBOM files."
                    ),
                    evidence={
                        "package_count": len(packages),
                        "sbom_files": [str(path) for path in sbom_files],
                    },
                )
            )

        if skipped_components:
            findings.append(
                self._finding(
                    "SBOM",
                    "docker.sbom.unqueryable_components",
                    Severity.INFO,
                    "Some SBOM components could not be queried against OSV",
                    (
                        "Blacklight skipped components that lacked a package URL or usable version "
                        "coordinate. They are not included in the vulnerability-clean result."
                    ),
                    evidence={"skipped_components": skipped_components},
                )
            )

        return findings

    def _package_finding(
        self,
        package: SBOMPackage,
        vulnerability_ids: set[str],
        records: dict[str, dict[str, Any]],
    ) -> Finding:
        details: list[dict[str, Any]] = []
        highest = Severity.INFO

        for vulnerability_id in sorted(vulnerability_ids):
            record = records.get(vulnerability_id)
            if record is None:
                details.append(
                    {
                        "id": vulnerability_id,
                        "severity": "UNKNOWN",
                        "details_available": False,
                    }
                )
                continue

            severity = self._record_severity(record)
            if _SEVERITY_RANK[severity] > _SEVERITY_RANK[highest]:
                highest = severity
            aliases = record.get("aliases")
            if not isinstance(aliases, list):
                aliases = []
            details.append(
                {
                    "id": vulnerability_id,
                    "aliases": sorted(str(item) for item in aliases if item),
                    "severity": severity.value,
                    "summary": str(record.get("summary") or "")[:300],
                    "modified": str(record.get("modified") or ""),
                    "details_available": True,
                }
            )

        shown = details[:100]
        resource_id = package.query_key
        return self._finding(
            resource_id,
            "docker.sbom.known_vulnerabilities",
            highest,
            "SBOM package matches known OSV vulnerability records",
            (
                "OSV returned one or more vulnerability records for this exact SBOM package "
                "coordinate. Blacklight severity uses explicit categorical/numeric severity "
                "data when available; otherwise the match remains INFO."
            ),
            (
                "Review the reported OSV IDs and upgrade or replace the package with a version "
                "that is no longer affected."
            ),
            {
                "purl": package.purl,
                "version": package.version,
                "source": package.source,
                "vulnerability_count": len(details),
                "vulnerabilities": shown,
                "vulnerability_details_truncated": max(0, len(details) - len(shown)),
            },
        )

    def _discover_sboms(self) -> list[Path]:
        if self.target.is_file():
            return [self.target]
        if not self.target.exists() or not self.target.is_dir():
            return []

        matches: list[Path] = []
        for path in self.target.rglob("*.json"):
            if not path.is_file():
                continue
            if any(part in _IGNORED_DIRS for part in path.parts):
                continue
            name = path.name.lower()
            if (
                name in _SBOM_NAMES
                or name.endswith(".cdx.json")
                or name.endswith(".cyclonedx.json")
                or name.endswith(".spdx.json")
            ):
                matches.append(path)
        return sorted(set(matches))

    def _parse_sbom(self, path: Path) -> tuple[list[SBOMPackage], int]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("SBOM root must be a JSON object")

        if str(payload.get("bomFormat") or "").lower() == "cyclonedx":
            return self._parse_cyclonedx(payload, path)
        if payload.get("spdxVersion"):
            return self._parse_spdx(payload, path)
        raise ValueError("unsupported SBOM JSON format")

    def _parse_cyclonedx(
        self,
        payload: dict[str, Any],
        path: Path,
    ) -> tuple[list[SBOMPackage], int]:
        components = payload.get("components")
        if not isinstance(components, list):
            return [], 0

        packages: list[SBOMPackage] = []
        skipped = 0
        for component in components:
            if not isinstance(component, dict):
                skipped += 1
                continue
            purl = str(component.get("purl") or "").strip()
            version = str(component.get("version") or "").strip() or None
            if not purl.startswith("pkg:") or (not version and not _purl_has_version(purl)):
                skipped += 1
                continue
            packages.append(SBOMPackage(purl, version, str(path)))
        return packages, skipped

    def _parse_spdx(
        self,
        payload: dict[str, Any],
        path: Path,
    ) -> tuple[list[SBOMPackage], int]:
        raw_packages = payload.get("packages")
        if not isinstance(raw_packages, list):
            return [], 0

        packages: list[SBOMPackage] = []
        skipped = 0
        for package in raw_packages:
            if not isinstance(package, dict):
                skipped += 1
                continue
            purl = self._spdx_purl(package)
            version = str(package.get("versionInfo") or "").strip() or None
            if not purl or (not version and not _purl_has_version(purl)):
                skipped += 1
                continue
            packages.append(SBOMPackage(purl, version, str(path)))
        return packages, skipped

    @staticmethod
    def _spdx_purl(package: dict[str, Any]) -> str | None:
        refs = package.get("externalRefs")
        if not isinstance(refs, list):
            return None
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            ref_type = str(ref.get("referenceType") or "").lower()
            locator = str(ref.get("referenceLocator") or "").strip()
            if "purl" in ref_type and locator.startswith("pkg:"):
                return locator
        return None

    @staticmethod
    def _osv_query(package: SBOMPackage) -> dict[str, Any]:
        if _purl_has_version(package.purl):
            return {"package": {"purl": package.purl}}

        if not package.version:
            raise ValueError("OSV query requires a versioned package coordinate")
        return {
            "package": {"purl": package.purl},
            "version": package.version,
        }

    @staticmethod
    def _record_severity(record: dict[str, Any]) -> Severity:
        values: list[Any] = []

        database_specific = record.get("database_specific")
        if isinstance(database_specific, dict):
            values.append(database_specific.get("severity"))

        affected = record.get("affected")
        if isinstance(affected, list):
            for item in affected:
                if not isinstance(item, dict):
                    continue
                ecosystem_specific = item.get("ecosystem_specific")
                if isinstance(ecosystem_specific, dict):
                    values.append(ecosystem_specific.get("severity"))
                affected_database = item.get("database_specific")
                if isinstance(affected_database, dict):
                    values.append(affected_database.get("severity"))

        categorical = DockerSBOMScanner._categorical_severity(values)
        if categorical is not Severity.INFO:
            return categorical

        raw_severity = record.get("severity")
        if isinstance(raw_severity, list):
            numeric_scores: list[float] = []
            for item in raw_severity:
                if not isinstance(item, dict):
                    continue
                score = item.get("score")
                try:
                    numeric_scores.append(float(score))
                except (TypeError, ValueError):
                    continue
            if numeric_scores:
                score = max(numeric_scores)
                if score >= 9.0:
                    return Severity.CRITICAL
                if score >= 7.0:
                    return Severity.HIGH
                if score >= 4.0:
                    return Severity.MEDIUM
                if score > 0:
                    return Severity.LOW

        return Severity.INFO

    @staticmethod
    def _categorical_severity(values: list[Any]) -> Severity:
        best = Severity.INFO
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        for value in values:
            if not isinstance(value, str):
                continue
            candidate = mapping.get(value.strip().upper(), Severity.INFO)
            if _SEVERITY_RANK[candidate] > _SEVERITY_RANK[best]:
                best = candidate
        return best

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
            service="sbom",
            resource_type="sbom_package",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )


def _purl_has_version(purl: str) -> bool:
    core = purl.split("#", 1)[0].split("?", 1)[0]
    return core.rfind("@") > core.rfind("/")


def _purl_with_version(purl: str, version: str) -> str:
    fragment = ""
    if "#" in purl:
        purl, raw_fragment = purl.split("#", 1)
        fragment = f"#{raw_fragment}"

    qualifiers = ""
    if "?" in purl:
        purl, raw_qualifiers = purl.split("?", 1)
        qualifiers = f"?{raw_qualifiers}"

    return f"{purl}@{version}{qualifiers}{fragment}"
