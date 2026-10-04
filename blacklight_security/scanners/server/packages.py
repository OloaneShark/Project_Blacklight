from __future__ import annotations

import re
from typing import Any

from blacklight_security.models import Finding, Severity
from blacklight_security.scanners.server.linux import (
    CommandResult,
    SSHCommandRunner,
    SSHExecutionError,
    ServerScanTarget,
)


_PACKAGE_PROBE_COMMAND = "printf 'BLACKLIGHT_OK\\n'; uname -s; hostname"
_PACKAGE_MANAGER_COMMAND = (
    "if command -v apt-get >/dev/null 2>&1; then printf 'apt\\n'; "
    "elif command -v dnf >/dev/null 2>&1; then printf 'dnf\\n'; "
    "else printf 'none\\n'; fi"
)
_APT_UPDATES_COMMAND = (
    "printf 'BLACKLIGHT_FAMILY=apt\\n'; "
    "now=$(date +%s 2>/dev/null || true); "
    "newest=$(find /var/lib/apt/lists -maxdepth 1 -type f -printf '%T@\\n' "
    "2>/dev/null | sort -nr | head -n 1 | cut -d. -f1); "
    "if [ -n \"$now\" ] && [ -n \"$newest\" ]; then "
    "printf 'BLACKLIGHT_CACHE_AGE=%s\\n' \"$((now-newest))\"; "
    "else printf 'BLACKLIGHT_CACHE_AGE=unknown\\n'; fi; "
    "out=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>&1); rc=$?; "
    "printf 'BLACKLIGHT_RC=%s\\n' \"$rc\"; "
    "printf '%s\\n' \"$out\" | awk '/^Inst / {print \"BLACKLIGHT_UPDATE=\" $0}'"
)
_DNF_UPDATES_COMMAND = (
    "printf 'BLACKLIGHT_FAMILY=dnf\\n'; "
    "out=$(dnf -q --cacheonly check-update 2>&1); rc=$?; "
    "printf 'BLACKLIGHT_RC=%s\\n' \"$rc\"; "
    "printf '%s\\n' \"$out\" | awk '"
    "NF >= 3 && $1 !~ /^Last/ && $1 !~ /^Obsoleting/ "
    "{print \"BLACKLIGHT_UPDATE=\" $0}'"
)
_DNF_SECURITY_ADVISORIES_COMMAND = (
    "out=$(dnf -q --cacheonly updateinfo list --security 2>&1); rc=$?; "
    "printf 'BLACKLIGHT_ADVISORY_RC=%s\\n' \"$rc\"; "
    "printf '%s\\n' \"$out\" | awk '"
    "NF >= 3 && $2 ~ /\\/Sec[.]$/ "
    "{print \"BLACKLIGHT_SECURITY_ADVISORY=\" $0}'"
)

_APT_PACKAGE_RE = re.compile(r"^Inst\s+(?P<package>\S+)")


class ServerPackagesScanner:
    """Read-only cached package-update visibility for remote Linux servers."""

    def __init__(self, target: ServerScanTarget):
        self.target = target
        self.executor = target.executor or SSHCommandRunner(target)

    def scan(self) -> list[Finding]:
        try:
            probe = self.executor.run(_PACKAGE_PROBE_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("package_probe", error)]

        lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
        if probe.returncode != 0 or len(lines) < 3 or lines[0] != "BLACKLIGHT_OK":
            return [
                self._error(
                    "server.packages.platform_probe",
                    "Blacklight could not identify the remote package target",
                    "The SSH session opened, but the fixed package probe did not return expected metadata.",
                    {"returncode": probe.returncode, "stderr": probe.stderr[:500]},
                )
            ]
        if lines[1].lower() != "linux":
            return [
                self._error(
                    "server.packages.unsupported_platform",
                    "Remote package target platform is not supported",
                    "The server package scanner currently supports Linux targets only.",
                    {"platform": lines[1], "hostname": lines[2]},
                )
            ]

        try:
            manager_result = self.executor.run(_PACKAGE_MANAGER_COMMAND)
        except SSHExecutionError as error:
            return [self._transport_error("package_manager", error)]

        manager = manager_result.stdout.strip().lower()
        if manager_result.returncode != 0 or manager not in {"apt", "dnf", "none"}:
            return [
                self._error(
                    "server.packages.package_manager",
                    "Blacklight could not identify a supported package manager",
                    "The fixed package-manager probe returned an unexpected result.",
                    {"returncode": manager_result.returncode, "stdout": manager_result.stdout[:200]},
                )
            ]

        if manager == "none":
            return [
                self._finding(
                    "server.packages.package_manager",
                    Severity.INFO,
                    "No supported cached package-update backend was observed",
                    "Blacklight currently supports cache-only APT and DNF package visibility.",
                    evidence={"supported_backends": ["apt", "dnf"]},
                )
            ]

        command = _APT_UPDATES_COMMAND if manager == "apt" else _DNF_UPDATES_COMMAND
        try:
            result = self.executor.run(command)
        except SSHExecutionError as error:
            return [self._transport_error("pending_updates", error)]

        return self._check_updates(manager, result)

    def _check_updates(self, manager: str, result: CommandResult) -> list[Finding]:
        family = manager
        command_rc: int | None = None
        cache_age: int | None = None
        updates: list[str] = []

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BLACKLIGHT_FAMILY="):
                family = line.split("=", 1)[1].strip().lower() or manager
            elif line.startswith("BLACKLIGHT_RC="):
                value = line.split("=", 1)[1].strip()
                if value.isdigit():
                    command_rc = int(value)
            elif line.startswith("BLACKLIGHT_CACHE_AGE="):
                value = line.split("=", 1)[1].strip()
                if value.isdigit():
                    cache_age = int(value)
            elif line.startswith("BLACKLIGHT_UPDATE="):
                updates.append(line.split("=", 1)[1].strip())

        valid_rc = command_rc == 0 or (manager == "dnf" and command_rc == 100)
        if result.returncode != 0 or not valid_rc:
            return [
                self._error(
                    "server.packages.pending_updates",
                    "Blacklight could not inspect cached pending package updates",
                    (
                        "The cache-only package command did not complete successfully. Blacklight "
                        "did not refresh repository metadata or infer that the host is up to date."
                    ),
                    {
                        "manager": manager,
                        "wrapper_returncode": result.returncode,
                        "package_command_returncode": command_rc,
                        "stderr": result.stderr[:500],
                    },
                )
            ]

        parsed = self._parse_updates(manager, updates)
        evidence = {
            "manager": family,
            "pending_count": len(parsed),
            "packages": parsed[:100],
            "evidence_truncated": len(parsed) > 100,
            "cache_age_seconds": cache_age,
            "repository_metadata_refreshed": False,
        }

        findings = [
            self._finding(
                "server.packages.pending_updates",
                Severity.INFO if parsed else Severity.PASS,
                (
                    "Cached package metadata reports pending updates"
                    if parsed
                    else "Cached package metadata reports no pending updates"
                ),
                (
                    "This inventory uses only package metadata already present on the host. "
                    "Blacklight does not refresh repositories, so newer updates may exist upstream."
                ),
                evidence=evidence,
            )
        ]

        if manager == "apt":
            security = [item for item in parsed if item["security_origin"]]
            findings.append(
                self._finding(
                    "server.packages.security_updates",
                    Severity.MEDIUM if security else Severity.PASS,
                    (
                        "Cached APT metadata reports pending security-origin updates"
                        if security
                        else "No pending security-origin APT updates were observed in cached metadata"
                    ),
                    (
                        "Blacklight classifies an APT update as security-origin only when the "
                        "simulated candidate line explicitly references a repository containing "
                        "'-security'. It does not infer CVE severity."
                    ),
                    remediation=(
                        "Review and apply the listed security-origin updates through the host's "
                        "approved patch-management process."
                        if security
                        else ""
                    ),
                    evidence={
                        "manager": "apt",
                        "security_update_count": len(security),
                        "packages": security[:100],
                        "evidence_truncated": len(security) > 100,
                        "repository_metadata_refreshed": False,
                    },
                )
            )
        else:
            findings.append(
                self._finding(
                    "server.packages.security_updates",
                    Severity.INFO,
                    "DNF security-advisory classification was not performed",
                    (
                        "This first DNF package phase inventories cached pending updates only. "
                        "Blacklight does not label DNF packages as security updates without "
                        "advisory metadata it has explicitly inspected."
                    ),
                    evidence={
                        "manager": "dnf",
                        "repository_metadata_refreshed": False,
                    },
                )
            )

        findings.append(
            self._finding(
                "server.packages.metadata_snapshot",
                Severity.INFO,
                "Package results are based on existing local repository metadata",
                (
                    "Blacklight intentionally did not refresh package repositories. Cache age is "
                    "reported when it can be derived, and the update inventory should be treated "
                    "as a snapshot rather than proof that no newer upstream updates exist."
                ),
                evidence={
                    "manager": manager,
                    "cache_age_seconds": cache_age,
                    "repository_metadata_refreshed": False,
                },
            )
        )
        return findings

    @staticmethod
    def _parse_updates(manager: str, lines: list[str]) -> list[dict[str, Any]]:
        parsed: list[dict[str, Any]] = []
        for line in lines:
            if manager == "apt":
                match = _APT_PACKAGE_RE.match(line)
                if match is None:
                    continue
                parsed.append(
                    {
                        "package": match.group("package"),
                        "security_origin": "-security" in line.lower(),
                        "raw_candidate": line[:500],
                    }
                )
                continue

            parts = line.split()
            if len(parts) < 3 or "." not in parts[0]:
                continue
            parsed.append(
                {
                    "package": parts[0],
                    "version": parts[1],
                    "repository": parts[2],
                    "security_origin": False,
                }
            )
        return parsed

    def _transport_error(self, name: str, error: SSHExecutionError) -> Finding:
        return self._error(
            f"server.packages.{name}",
            f"Blacklight could not complete the {name.replace('_', ' ')} inspection",
            "The SSH transport failed before this read-only package inspection completed.",
            {"error": str(error)},
        )

    def _error(
        self,
        check_id: str,
        title: str,
        description: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return self._finding(
            check_id,
            Severity.ERROR,
            title,
            description,
            remediation=(
                "Verify SSH connectivity and that the selected package manager has usable local "
                "metadata, then retry. Blacklight will not refresh repositories automatically."
            ),
            evidence=evidence,
        )

    def _finding(
        self,
        check_id: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            provider="server",
            service="packages",
            resource_type="linux_server",
            resource_id=self.target.resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )
