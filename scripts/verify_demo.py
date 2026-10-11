from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo"
ACTIONABLE = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "ERROR"}


def _blacklight_command() -> list[str]:
    executable = shutil.which("blacklight")
    if executable:
        return [executable]
    raise SystemExit(
        "blacklight was not found on PATH. Install the checkout first with "
        'python -m pip install -e ".[dev]".'
    )


def _run(
    command: list[str],
    *,
    expected_exit: int,
    label: str,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if completed.returncode != expected_exit:
        print(f"[FAIL] {label}: expected exit {expected_exit}, got {completed.returncode}")
        if completed.stdout:
            print("--- stdout ---")
            print(completed.stdout.rstrip())
        if completed.stderr:
            print("--- stderr ---")
            print(completed.stderr.rstrip())
        raise SystemExit(1)

    print(f"[PASS] {label}")
    return completed


def _load_report(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("tool") != "project-blacklight":
        raise SystemExit(f"[FAIL] unexpected report tool marker in {path}")
    if not isinstance(payload.get("findings"), list):
        raise SystemExit(f"[FAIL] report has no findings list: {path}")
    return payload


def _assert_no_actionable(payload: dict, label: str) -> None:
    unexpected = [
        finding
        for finding in payload["findings"]
        if finding.get("severity") in ACTIONABLE
    ]
    if unexpected:
        checks = ", ".join(str(item.get("check_id")) for item in unexpected)
        raise SystemExit(f"[FAIL] {label}: unexpected actionable findings: {checks}")
    print(f"[PASS] {label} has no actionable findings")


def _assert_checks(payload: dict, expected: set[str], label: str) -> None:
    observed = {
        str(finding.get("check_id"))
        for finding in payload["findings"]
        if finding.get("severity") in ACTIONABLE
    }
    missing = expected - observed
    if missing:
        raise SystemExit(
            f"[FAIL] {label}: expected checks were missing: {', '.join(sorted(missing))}"
        )
    print(f"[PASS] {label} produced expected deterministic checks")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Project Blacklight's credential-free interview demo."
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="Also run the OSV-backed SBOM demo, which requires internet access.",
    )
    args = parser.parse_args(argv)

    blacklight = _blacklight_command()

    _run(
        [*blacklight, "--version"],
        expected_exit=0,
        label="installed blacklight entry point",
    )

    with tempfile.TemporaryDirectory(prefix="blacklight-demo-") as temp:
        output_dir = Path(temp)

        docker_secure = output_dir / "docker-secure.json"
        _run(
            [
                *blacklight,
                "scan",
                "docker",
                "--path",
                str(DEMO / "docker" / "secure" / "Dockerfile"),
                "--format",
                "json",
                "--output",
                str(docker_secure),
            ],
            expected_exit=0,
            label="secure Dockerfile scan",
        )
        _assert_no_actionable(_load_report(docker_secure), "secure Dockerfile scan")

        docker_insecure = output_dir / "docker-insecure.json"
        _run(
            [
                *blacklight,
                "scan",
                "docker",
                "--path",
                str(DEMO / "docker" / "insecure" / "Dockerfile"),
                "--fail-on",
                "high",
                "--format",
                "json",
                "--output",
                str(docker_insecure),
            ],
            expected_exit=1,
            label="insecure Dockerfile CI gate",
        )
        _assert_checks(
            _load_report(docker_insecure),
            {
                "docker.dockerfile.base_image_latest",
                "docker.dockerfile.root_user",
                "docker.dockerfile.embedded_secret",
                "docker.dockerfile.remote_shell_pipe",
                "docker.dockerfile.world_writable_permissions",
            },
            "insecure Dockerfile scan",
        )

        kubernetes_secure = output_dir / "kubernetes-secure.json"
        _run(
            [
                *blacklight,
                "scan",
                "kubernetes",
                "--path",
                str(DEMO / "kubernetes" / "secure.yaml"),
                "--format",
                "json",
                "--output",
                str(kubernetes_secure),
            ],
            expected_exit=0,
            label="secure Kubernetes manifest scan",
        )
        _assert_no_actionable(
            _load_report(kubernetes_secure),
            "secure Kubernetes manifest scan",
        )

        kubernetes_insecure = output_dir / "kubernetes-insecure.json"
        _run(
            [
                *blacklight,
                "scan",
                "kubernetes",
                "--path",
                str(DEMO / "kubernetes" / "insecure.yaml"),
                "--fail-on",
                "high",
                "--format",
                "json",
                "--output",
                str(kubernetes_insecure),
            ],
            expected_exit=1,
            label="insecure Kubernetes CI gate",
        )
        _assert_checks(
            _load_report(kubernetes_insecure),
            {
                "kubernetes.manifest.privileged_container",
                "kubernetes.manifest.root_user",
                "kubernetes.manifest.privilege_escalation",
                "kubernetes.manifest.host_namespace",
                "kubernetes.manifest.host_path",
                "kubernetes.manifest.capabilities_all",
                "kubernetes.manifest.seccomp_unconfined",
                "kubernetes.manifest.literal_secret_env",
            },
            "insecure Kubernetes manifest scan",
        )

        html_report = output_dir / "docker-insecure.html"
        _run(
            [
                *blacklight,
                "scan",
                "docker",
                "--path",
                str(DEMO / "docker" / "insecure" / "Dockerfile"),
                "--fail-on",
                "high",
                "--format",
                "html",
                "--output",
                str(html_report),
            ],
            expected_exit=1,
            label="HTML report generation on a failing security gate",
        )
        html = html_report.read_text(encoding="utf-8")
        if "Project Blacklight" not in html or "docker.dockerfile.root_user" not in html:
            raise SystemExit("[FAIL] generated HTML report is missing expected content")
        print("[PASS] generated HTML report contains Blacklight findings")

        if args.online:
            sbom_report = output_dir / "sbom.json"
            _run(
                [
                    *blacklight,
                    "scan",
                    "docker",
                    "--service",
                    "sbom",
                    "--path",
                    str(DEMO / "sbom" / "vulnerable.cdx.json"),
                    "--format",
                    "json",
                    "--output",
                    str(sbom_report),
                ],
                expected_exit=0,
                label="online SBOM/OSV scan",
            )
            sbom_payload = _load_report(sbom_report)
            if not any(
                finding.get("check_id") == "docker.sbom.known_vulnerabilities"
                and finding.get("severity") not in {"PASS", "INFO"}
                for finding in sbom_payload["findings"]
            ):
                raise SystemExit(
                    "[FAIL] online SBOM demo did not return a scored known-vulnerability finding"
                )
            print("[PASS] online SBOM demo returned scored vulnerability data")

    print()
    print("Blacklight interview demo verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
