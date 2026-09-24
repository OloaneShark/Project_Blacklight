from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QApplication, QTableWidgetItem

from blacklight_security.desktop.app import BlacklightDesktop
from blacklight_security.desktop.theme import DESKTOP_STYLESHEET


def save(window: BlacklightDesktop, name: str) -> None:
    QApplication.processEvents()
    pixmap = window.grab()
    path = f"desktop-screenshots/{name}.png"
    if not pixmap.save(path, "PNG"):
        raise RuntimeError(f"Could not save {path}")


def main() -> int:
    from pathlib import Path

    Path("desktop-screenshots").mkdir(parents=True, exist_ok=True)

    app = QApplication([])
    app.setStyle("Fusion")
    app.setStyleSheet(DESKTOP_STYLESHEET)

    window = BlacklightDesktop()
    window.resize(1420, 860)
    window.show()
    app.processEvents()

    window.top_target_combo.setCurrentIndex(0)
    window._update_home_provider(None)
    window._set_page(0)
    save(window, "home")

    window._set_page(1)
    save(window, "targets")

    window.provider_combo.setCurrentIndex(1)
    window.path_input.setText(r"C:\Projects\example-api")
    window.fail_on_combo.setCurrentIndex(3)
    window.coverage_check.setChecked(True)
    window._set_page(2)
    save(window, "new-scan")

    window.risk_card.value.setText("48/100")
    window.coverage_card.value.setText("FULL")
    window.critical_card.value.setText("1")
    window.high_card.value.setText("3")

    rows = [
        ("CRITICAL", "Deployment/default/api", "Privileged container enabled", "#d92d20"),
        ("HIGH", "Deployment/default/api", "Workload explicitly runs as UID 0", "#dc6803"),
        ("HIGH", "Dockerfile", "Final image runs as root", "#dc6803"),
        ("HIGH", "Dockerfile", "Secret-like value embedded in ENV", "#dc6803"),
        ("MEDIUM", "Dockerfile", "Mutable base image tag", "#b54708"),
        ("MEDIUM", "Pod/default/worker", "Host port is explicitly bound", "#b54708"),
    ]
    window.findings_table.setRowCount(len(rows))
    for row, (severity, resource, title, color) in enumerate(rows):
        severity_item = QTableWidgetItem(severity)
        severity_item.setForeground(QBrush(QColor(color)))
        window.findings_table.setItem(row, 0, severity_item)
        window.findings_table.setItem(row, 1, QTableWidgetItem(resource))
        window.findings_table.setItem(row, 2, QTableWidgetItem(title))

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
        "Remove privileged mode and grant only the capabilities the workload requires.\n\n"
        "EVIDENCE\n"
        "{\n"
        '  "container": "api",\n'
        '  "privileged": true\n'
        "}"
    )
    window.findings_table.selectRow(0)
    window._set_page(3)
    save(window, "findings")

    window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
