from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import QApplication, QTableWidgetItem

from blacklight_security.desktop.app import BlacklightDesktop
from blacklight_security.desktop.theme import DESKTOP_STYLESHEET


OUTPUT = Path("desktop-screenshots")


def _save(window: BlacklightDesktop, name: str) -> None:
    QApplication.processEvents()
    pixmap = window.grab()
    path = OUTPUT / f"{name}.png"
    if not pixmap.save(str(path), "PNG"):
        raise RuntimeError(f"Could not save screenshot: {path}")
    print(path)


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)

    app = QApplication([])
    app.setApplicationName("Project Blacklight")
    app.setStyleSheet(DESKTOP_STYLESHEET)
    window = BlacklightDesktop()
    window.resize(1280, 820)
    window.show()
    app.processEvents()

    # Dashboard with representative values so the layout is visible.
    window.dashboard_risk.value.setText("48/100")
    window.dashboard_coverage.value.setText("FULL")
    window.dashboard_findings.value.setText("7")
    window.dashboard_provider.value.setText("AWS")
    window._set_page(0)
    _save(window, "dashboard")

    window._set_page(1)
    _save(window, "targets")

    window.provider_combo.setCurrentIndex(1)
    window.path_input.setText(r"C:\Projects\example-api")
    window.fail_on_combo.setCurrentIndex(3)
    window.coverage_check.setChecked(True)
    window.scan_status.setText("Ready.")
    window._set_page(2)
    _save(window, "scan-docker")

    window.risk_card.value.setText("48/100")
    window.coverage_card.value.setText("FULL")
    window.critical_card.value.setText("1")
    window.high_card.value.setText("3")

    rows = [
        ("CRITICAL", "Deployment/default/api", "Privileged container enabled", "#ff4d6d"),
        ("HIGH", "Deployment/default/api", "Workload explicitly runs as UID 0", "#ff7a59"),
        ("HIGH", "Dockerfile", "Final image runs as root", "#ff7a59"),
        ("HIGH", "Dockerfile", "Secret-like value embedded in ENV", "#ff7a59"),
        ("MEDIUM", "Dockerfile", "Mutable base image tag", "#f6c453"),
        ("MEDIUM", "Pod/default/worker", "Host port is explicitly bound", "#f6c453"),
        ("LOW", "s3://example-bucket", "Bucket versioning is disabled", "#4ecdc4"),
    ]
    window.findings_table.setRowCount(len(rows))
    for row, (severity, resource, title, color) in enumerate(rows):
        severity_item = QTableWidgetItem(severity)
        severity_item.setForeground(QBrush(QColor(color)))
        window.findings_table.setItem(row, 0, severity_item)
        window.findings_table.setItem(row, 1, QTableWidgetItem(resource))
        window.findings_table.setItem(row, 2, QTableWidgetItem(title))

    window.findings_table.selectRow(0)
    window.finding_title.setText("Privileged container enabled")
    window.finding_meta.setText(
        "CRITICAL · kubernetes/manifest · kubernetes.manifest.privileged_container"
    )
    window.finding_detail.setPlainText(
        "RESOURCE\n"
        "Deployment/default/api\n\n"
        "DETAIL\n"
        "The workload explicitly configures a privileged container.\n\n"
        "REMEDIATION\n"
        "Remove privileged mode and grant only the specific capabilities the workload requires.\n\n"
        "EVIDENCE\n"
        "{\n"
        '  "container": "api",\n'
        '  "privileged": true\n'
        "}"
    )
    window._set_page(3)
    _save(window, "findings")

    window.report_status.setText("Latest scan: KUBERNETES · COMPLETE · 842 ms")
    window.export_json_button.setEnabled(True)
    window.export_html_button.setEnabled(True)
    window._set_page(4)
    _save(window, "reports")

    window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
