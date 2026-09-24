import json
import sys

import pytest

from blacklight_security.analyst import AnalystError, load_report, run_external_analyst
from blacklight_security.cli import main


def _report():
    return {
        "tool": "project-blacklight",
        "schema_version": "6",
        "risk": {"score": 20, "level": "LOW"},
        "findings": [
            {
                "check_id": "example",
                "provider": "docker",
                "service": "dockerfile",
                "resource_type": "dockerfile",
                "resource_id": "Dockerfile",
                "severity": "HIGH",
                "title": "Example finding",
                "description": "Example",
                "remediation": "Fix it",
                "evidence": {},
            }
        ],
    }


def test_load_report_validates_blacklight_shape(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report()), encoding="utf-8")

    loaded = load_report(path)

    assert loaded["tool"] == "project-blacklight"
    assert loaded["findings"][0]["severity"] == "HIGH"


def test_load_report_rejects_non_blacklight_json(tmp_path):
    path = tmp_path / "report.json"
    path.write_text('{"tool": "other", "findings": []}', encoding="utf-8")

    with pytest.raises(AnalystError):
        load_report(path)


def test_external_analyst_receives_report_on_stdin(tmp_path):
    script = tmp_path / "analyst.py"
    script.write_text(
        "import json, sys\n"
        "report = json.load(sys.stdin)\n"
        "print(report['findings'][0]['title'])\n",
        encoding="utf-8",
    )

    output = run_external_analyst(
        _report(),
        command=sys.executable,
        arguments=[str(script)],
        timeout_seconds=10,
    )

    assert output == "Example finding"


def test_external_analyst_failure_is_reported(tmp_path):
    script = tmp_path / "analyst.py"
    script.write_text(
        "import sys\n"
        "print('analyst failed', file=sys.stderr)\n"
        "raise SystemExit(3)\n",
        encoding="utf-8",
    )

    with pytest.raises(AnalystError, match="analyst failed"):
        run_external_analyst(
            _report(),
            command=sys.executable,
            arguments=[str(script)],
            timeout_seconds=10,
        )


def test_cli_analyze_writes_output(tmp_path):
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(_report()), encoding="utf-8")

    script = tmp_path / "analyst.py"
    script.write_text(
        "import json, sys\n"
        "report = json.load(sys.stdin)\n"
        "print('findings=' + str(len(report['findings'])))\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "analysis.txt"

    exit_code = main(
        [
            "analyze",
            "--input",
            str(report_path),
            "--command",
            sys.executable,
            "--arg",
            str(script),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    assert output_path.read_text(encoding="utf-8").strip() == "findings=1"


def test_analyst_timeout_range_is_enforced():
    with pytest.raises(AnalystError, match="between 1 and 600"):
        run_external_analyst(_report(), command=sys.executable, timeout_seconds=0)
