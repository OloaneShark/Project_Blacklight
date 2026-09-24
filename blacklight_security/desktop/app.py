from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QThread, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from blacklight_security import __version__
from blacklight_security.desktop.controller import (
    DesktopScanOutcome,
    DesktopScanRequest,
    run_scan,
    write_report,
)
from blacklight_security.models import Severity
from blacklight_security.risk import assess_risk
from blacklight_security.desktop.theme import DESKTOP_STYLESHEET


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.ERROR: 4,
    Severity.INFO: 5,
    Severity.PASS: 6,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff4d6d",
    Severity.HIGH: "#ff7a59",
    Severity.MEDIUM: "#f6c453",
    Severity.LOW: "#4ecdc4",
    Severity.ERROR: "#d06cff",
    Severity.INFO: "#8ba4ff",
    Severity.PASS: "#5ac97a",
}


class ScanWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, request: DesktopScanRequest):
        super().__init__()
        self.request = request

    def run(self) -> None:
        try:
            self.finished.emit(run_scan(self.request))
        except Exception as error:
            self.failed.emit(f"{type(error).__name__}: {error}")


class MetricCard(QFrame):
    def __init__(self, label: str, value: str = "--"):
        super().__init__()
        self.setObjectName("MetricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        caption = QLabel(label.upper())
        caption.setObjectName("MetricLabel")
        self.value = QLabel(value)
        self.value.setObjectName("MetricValue")

        layout.addWidget(caption)
        layout.addWidget(self.value)


class TargetCard(QFrame):
    selected = Signal(str)

    def __init__(
        self,
        provider: str,
        title: str,
        description: str,
        status: str = "READY",
        enabled: bool = True,
    ):
        super().__init__()
        self.provider = provider
        self.enabled = enabled
        self.setObjectName("TargetCard")
        self.setCursor(Qt.PointingHandCursor if enabled else Qt.ArrowCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setObjectName("SectionTitle")
        status_label = QLabel(status)
        status_label.setObjectName("Muted")
        header.addWidget(title_label)
        header.addStretch()
        header.addWidget(status_label)

        desc = QLabel(description)
        desc.setObjectName("Muted")
        desc.setWordWrap(True)

        layout.addLayout(header)
        layout.addWidget(desc)
        layout.addStretch()

        button = QPushButton("Configure Scan" if enabled else "Next Phase")
        button.setObjectName("SecondaryButton")
        button.setEnabled(enabled)
        button.clicked.connect(lambda: self.selected.emit(self.provider))
        layout.addWidget(button)

    def mousePressEvent(self, event: Any) -> None:
        if self.enabled and event.button() == Qt.LeftButton:
            self.selected.emit(self.provider)
        super().mousePressEvent(event)


class BlacklightDesktop(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Project Blacklight {__version__}")
        self.resize(1280, 820)
        self.setMinimumSize(1080, 700)

        self.current_outcome: DesktopScanOutcome | None = None
        self.scan_thread: QThread | None = None
        self.scan_worker: ScanWorker | None = None

        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_sidebar())

        self.pages = QStackedWidget()
        self.dashboard_page = self._build_dashboard()
        self.scan_page = self._build_scan_page()
        self.findings_page = self._build_findings_page()
        self.reports_page = self._build_reports_page()
        self.settings_page = self._build_settings_page()

        for page in (
            self.dashboard_page,
            self.scan_page,
            self.findings_page,
            self.reports_page,
            self.settings_page,
        ):
            self.pages.addWidget(page)

        root_layout.addWidget(self.pages, 1)
        self._set_page(0)

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(218)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(18, 24, 18, 20)
        layout.setSpacing(8)

        brand = QLabel("BLACKLIGHT")
        brand.setObjectName("Brand")
        version = QLabel(f"DESKTOP  {__version__}")
        version.setObjectName("Version")

        layout.addWidget(brand)
        layout.addWidget(version)
        layout.addSpacing(24)

        self.nav_buttons: list[QPushButton] = []
        for index, label in enumerate(("Dashboard", "Scan", "Findings", "Reports", "Settings")):
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, i=index: self._set_page(i))
            layout.addWidget(button)
            self.nav_buttons.append(button)

        layout.addStretch()

        engine = QLabel("LOCAL SECURITY ENGINE")
        engine.setObjectName("Muted")
        layout.addWidget(engine)

        return sidebar

    def _page_shell(self, title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 28, 30, 28)
        layout.setSpacing(18)

        title_label = QLabel(title)
        title_label.setObjectName("PageTitle")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("PageSubtitle")
        subtitle_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)
        return page, layout

    def _build_dashboard(self) -> QWidget:
        page, layout = self._page_shell(
            "Security workspace",
            "Run deterministic security scans locally. Choose a target type and Blacklight handles the same risk, coverage, findings, and reporting pipeline underneath.",
        )

        metrics = QHBoxLayout()
        self.dashboard_risk = MetricCard("Last Risk", "--")
        self.dashboard_coverage = MetricCard("Coverage", "--")
        self.dashboard_findings = MetricCard("Actionable", "--")
        self.dashboard_provider = MetricCard("Provider", "--")
        for card in (
            self.dashboard_risk,
            self.dashboard_coverage,
            self.dashboard_findings,
            self.dashboard_provider,
        ):
            metrics.addWidget(card)
        layout.addLayout(metrics)

        section = QLabel("TARGET TYPES")
        section.setObjectName("SectionTitle")
        layout.addWidget(section)

        cards = QHBoxLayout()
        targets = (
            ("aws", "AWS Account", "Audit S3, IAM, CloudTrail, EC2, RDS, Lambda and GuardDuty using the normal AWS credential chain.", "READY", True),
            ("docker", "Docker Project", "Scan local Dockerfiles for root runtime, embedded secrets, mutable images and risky build instructions.", "READY", True),
            ("kubernetes", "Kubernetes", "Inspect workload manifests locally for privileged execution, host access, mutable images and other risky settings.", "READY", True),
            ("server", "Server / SSH", "Connect a read-only server target and inspect services, SSH, firewall and host configuration.", "NEXT PHASE", False),
        )
        for provider, title, description, status, enabled in targets:
            card = TargetCard(provider, title, description, status, enabled)
            card.selected.connect(self._start_target)
            cards.addWidget(card)
        layout.addLayout(cards)

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QHBoxLayout(panel)
        panel_layout.setContentsMargins(18, 16, 18, 16)
        text = QLabel(
            "Blacklight Desktop runs the same deterministic engine as the CLI. "
            "No cloud dashboard account is required for Docker/Kubernetes local scans."
        )
        text.setObjectName("Muted")
        text.setWordWrap(True)
        panel_layout.addWidget(text)
        open_scan = QPushButton("New Scan")
        open_scan.setObjectName("PrimaryButton")
        open_scan.clicked.connect(lambda: self._set_page(1))
        panel_layout.addWidget(open_scan)
        layout.addWidget(panel)
        layout.addStretch()
        return page

    def _build_scan_page(self) -> QWidget:
        page, layout = self._page_shell(
            "New scan",
            "Select a target and configure only the information required for that provider.",
        )

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(22, 20, 22, 20)
        panel_layout.setSpacing(14)

        form = QFormLayout()
        form.setHorizontalSpacing(20)
        form.setVerticalSpacing(12)

        self.provider_combo = QComboBox()
        self.provider_combo.addItem("AWS Account", "aws")
        self.provider_combo.addItem("Docker Project", "docker")
        self.provider_combo.addItem("Kubernetes Manifests", "kubernetes")
        self.provider_combo.currentIndexChanged.connect(self._provider_changed)
        form.addRow("Target type", self.provider_combo)

        self.path_container = QWidget()
        path_layout = QHBoxLayout(self.path_container)
        path_layout.setContentsMargins(0, 0, 0, 0)
        path_layout.setSpacing(8)
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Project directory or file")
        browse = QPushButton("Browse")
        browse.setObjectName("SecondaryButton")
        browse.clicked.connect(self._browse_path)
        path_layout.addWidget(self.path_input, 1)
        path_layout.addWidget(browse)
        form.addRow("Path", self.path_container)

        self.profile_input = QLineEdit()
        self.profile_input.setPlaceholderText("Optional AWS profile")
        form.addRow("AWS profile", self.profile_input)

        self.region_input = QLineEdit()
        self.region_input.setPlaceholderText("Optional region override")
        form.addRow("AWS region", self.region_input)

        self.fail_on_combo = QComboBox()
        self.fail_on_combo.addItem("No severity gate", None)
        for level in ("low", "medium", "high", "critical"):
            self.fail_on_combo.addItem(f"Fail on {level.upper()}+", level)
        form.addRow("Security gate", self.fail_on_combo)

        self.coverage_check = QCheckBox("Require full scan coverage")
        form.addRow("Coverage gate", self.coverage_check)

        panel_layout.addLayout(form)

        controls = QHBoxLayout()
        controls.addStretch()
        self.run_button = QPushButton("Run Blacklight Scan")
        self.run_button.setObjectName("PrimaryButton")
        self.run_button.clicked.connect(self._run_scan)
        controls.addWidget(self.run_button)
        panel_layout.addLayout(controls)

        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 1)
        self.scan_progress.setValue(0)
        self.scan_progress.hide()
        panel_layout.addWidget(self.scan_progress)

        self.scan_status = QLabel("Ready.")
        self.scan_status.setObjectName("Muted")
        panel_layout.addWidget(self.scan_status)

        layout.addWidget(panel)
        layout.addStretch()
        self._provider_changed()
        return page

    def _build_findings_page(self) -> QWidget:
        page, layout = self._page_shell(
            "Findings",
            "Observed security evidence from the most recent scan. Select a row to inspect remediation and evidence.",
        )

        metrics = QHBoxLayout()
        self.risk_card = MetricCard("Risk", "--")
        self.coverage_card = MetricCard("Coverage", "--")
        self.critical_card = MetricCard("Critical", "0")
        self.high_card = MetricCard("High", "0")
        for card in (self.risk_card, self.coverage_card, self.critical_card, self.high_card):
            metrics.addWidget(card)
        layout.addLayout(metrics)

        splitter = QSplitter(Qt.Horizontal)

        self.findings_table = QTableWidget(0, 3)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Resource", "Finding"])
        self.findings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.findings_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.findings_table.itemSelectionChanged.connect(self._finding_selected)
        splitter.addWidget(self.findings_table)

        detail_panel = QFrame()
        detail_panel.setObjectName("Panel")
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(16, 16, 16, 16)
        detail_layout.setSpacing(10)

        self.finding_title = QLabel("Select a finding")
        self.finding_title.setObjectName("SectionTitle")
        self.finding_title.setWordWrap(True)

        self.finding_meta = QLabel("")
        self.finding_meta.setObjectName("Muted")
        self.finding_meta.setWordWrap(True)

        self.finding_detail = QPlainTextEdit()
        self.finding_detail.setReadOnly(True)
        self.finding_detail.setPlaceholderText("Finding details will appear here.")

        detail_layout.addWidget(self.finding_title)
        detail_layout.addWidget(self.finding_meta)
        detail_layout.addWidget(self.finding_detail, 1)
        splitter.addWidget(detail_panel)
        splitter.setSizes([720, 420])

        layout.addWidget(splitter, 1)
        return page

    def _build_reports_page(self) -> QWidget:
        page, layout = self._page_shell(
            "Reports",
            "Export the latest Blacklight result without rerunning the scan.",
        )

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(22, 20, 22, 20)
        panel_layout.setSpacing(14)

        self.report_status = QLabel("No completed scan yet.")
        self.report_status.setObjectName("Muted")
        panel_layout.addWidget(self.report_status)

        buttons = QHBoxLayout()
        self.export_json_button = QPushButton("Export JSON")
        self.export_html_button = QPushButton("Export HTML")
        for button in (self.export_json_button, self.export_html_button):
            button.setObjectName("SecondaryButton")
            button.setEnabled(False)
        self.export_json_button.clicked.connect(lambda: self._export_report("json"))
        self.export_html_button.clicked.connect(lambda: self._export_report("html"))
        buttons.addWidget(self.export_json_button)
        buttons.addWidget(self.export_html_button)
        buttons.addStretch()
        panel_layout.addLayout(buttons)

        layout.addWidget(panel)
        layout.addStretch()
        return page

    def _build_settings_page(self) -> QWidget:
        page, layout = self._page_shell(
            "Settings",
            "Desktop configuration stays local. Blacklight does not require a hosted account for the current scan providers.",
        )

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(22, 20, 22, 20)
        panel_layout.setSpacing(10)

        title = QLabel("ENGINE")
        title.setObjectName("SectionTitle")
        panel_layout.addWidget(title)

        for text in (
            f"Version: {__version__}",
            "Detection: deterministic",
            "Current targets: AWS, Dockerfile, Kubernetes manifests",
            "Server / SSH targets: next product phase",
            "Desktop data: local process only in this first build",
        ):
            label = QLabel(text)
            label.setObjectName("Muted")
            panel_layout.addWidget(label)

        layout.addWidget(panel)
        layout.addStretch()
        return page

    def _set_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        for i, button in enumerate(self.nav_buttons):
            button.setChecked(i == index)

    def _start_target(self, provider: str) -> None:
        provider_index = {"aws": 0, "docker": 1, "kubernetes": 2}.get(provider)
        if provider_index is None:
            return
        self.provider_combo.setCurrentIndex(provider_index)
        self._set_page(1)

    def _provider_changed(self) -> None:
        if not hasattr(self, "provider_combo"):
            return
        provider = self.provider_combo.currentData()
        is_aws = provider == "aws"
        self.profile_input.setVisible(is_aws)
        self.region_input.setVisible(is_aws)
        self.path_container.setVisible(not is_aws)

    def _browse_path(self) -> None:
        provider = self.provider_combo.currentData()
        title = "Select Docker project or file" if provider == "docker" else "Select Kubernetes project or manifest"
        selected = QFileDialog.getExistingDirectory(self, title, self.path_input.text() or str(Path.cwd()))
        if selected:
            self.path_input.setText(selected)

    def _scan_request(self) -> DesktopScanRequest:
        provider = self.provider_combo.currentData()
        path: Path | None = None
        if provider != "aws":
            raw_path = self.path_input.text().strip()
            path = Path(raw_path) if raw_path else Path.cwd()

        return DesktopScanRequest(
            provider=provider,
            path=path,
            profile=self.profile_input.text().strip() or None,
            region=self.region_input.text().strip() or None,
            fail_on=self.fail_on_combo.currentData(),
            require_full_coverage=self.coverage_check.isChecked(),
        )

    def _run_scan(self) -> None:
        if self.scan_thread is not None:
            return

        request = self._scan_request()
        self.run_button.setEnabled(False)
        self.scan_progress.setRange(0, 0)
        self.scan_progress.show()
        self.scan_status.setText(f"Scanning {request.provider.upper()}...")

        thread = QThread(self)
        worker = ScanWorker(request)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._scan_finished)
        worker.failed.connect(self._scan_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(self._scan_thread_finished)

        self.scan_thread = thread
        self.scan_worker = worker
        thread.start()

    def _scan_finished(self, outcome: DesktopScanOutcome) -> None:
        self.current_outcome = outcome
        result = outcome.result
        assessment = assess_risk(result.findings)
        counts = Counter(finding.severity for finding in result.findings)
        actionable = sum(
            count
            for severity, count in counts.items()
            if severity not in {Severity.PASS, Severity.INFO}
        )

        self.dashboard_risk.value.setText(f"{assessment.score}/100")
        self.dashboard_coverage.value.setText(result.coverage.status)
        self.dashboard_findings.value.setText(str(actionable))
        self.dashboard_provider.value.setText(result.provider.upper())

        self.risk_card.value.setText(f"{assessment.score}/100")
        self.coverage_card.value.setText(result.coverage.status)
        self.critical_card.value.setText(str(counts[Severity.CRITICAL]))
        self.high_card.value.setText(str(counts[Severity.HIGH]))

        self._populate_findings(outcome)
        self.report_status.setText(
            f"Latest scan: {result.provider.upper()} · {result.status} · {result.duration_ms} ms"
        )
        self.export_json_button.setEnabled(True)
        self.export_html_button.setEnabled(True)

        self.scan_status.setText(
            f"Complete. Risk {assessment.level} ({assessment.score}/100), "
            f"coverage {result.coverage.status}."
        )
        self._set_page(2)

    def _scan_failed(self, message: str) -> None:
        self.scan_status.setText("Scan failed.")
        QMessageBox.critical(self, "Blacklight scan failed", message)

    def _scan_thread_finished(self) -> None:
        self.scan_progress.hide()
        self.scan_progress.setRange(0, 1)
        self.scan_progress.setValue(0)
        self.run_button.setEnabled(True)

        if self.scan_worker is not None:
            self.scan_worker.deleteLater()
        if self.scan_thread is not None:
            self.scan_thread.deleteLater()
        self.scan_worker = None
        self.scan_thread = None

    def _populate_findings(self, outcome: DesktopScanOutcome) -> None:
        findings = sorted(
            outcome.result.findings,
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.severity, 99),
                finding.resource_id,
                finding.title,
            ),
        )
        self.findings_table.setRowCount(len(findings))

        for row, finding in enumerate(findings):
            severity_item = QTableWidgetItem(finding.severity.value)
            severity_item.setForeground(QColor(SEVERITY_COLORS.get(finding.severity, "#ffffff")))
            resource_item = QTableWidgetItem(finding.resource_id)
            title_item = QTableWidgetItem(finding.title)

            severity_item.setData(Qt.UserRole, finding)
            for column, item in enumerate((severity_item, resource_item, title_item)):
                self.findings_table.setItem(row, column, item)

        if findings:
            self.findings_table.selectRow(0)
        else:
            self.finding_title.setText("No findings returned")
            self.finding_meta.setText("")
            self.finding_detail.setPlainText("The selected scanner returned no resources/findings.")

    def _finding_selected(self) -> None:
        selected = self.findings_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        severity_item = self.findings_table.item(row, 0)
        finding = severity_item.data(Qt.UserRole)
        if finding is None:
            return

        self.finding_title.setText(finding.title)
        self.finding_meta.setText(
            f"{finding.severity.value} · {finding.provider}/{finding.service} · {finding.check_id}"
        )

        detail = [
            f"RESOURCE\n{finding.resource_id}",
            f"\nDETAIL\n{finding.description}",
        ]
        if finding.remediation:
            detail.append(f"\nREMEDIATION\n{finding.remediation}")
        if finding.evidence:
            detail.append(
                "\nEVIDENCE\n" + json.dumps(finding.evidence, indent=2, sort_keys=True, default=str)
            )
        self.finding_detail.setPlainText("\n".join(detail))

    def _export_report(self, output_format: str) -> None:
        if self.current_outcome is None:
            return

        suffix = "json" if output_format == "json" else "html"
        default_name = f"blacklight-{self.current_outcome.result.provider}-report.{suffix}"
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {output_format.upper()} report",
            str(Path.home() / default_name),
            f"{output_format.upper()} files (*.{suffix})",
        )
        if not path:
            return

        try:
            write_report(self.current_outcome, output_format, Path(path))
        except Exception as error:
            QMessageBox.critical(self, "Export failed", f"{type(error).__name__}: {error}")
            return

        QMessageBox.information(self, "Report exported", f"Saved to:\n{path}")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blacklight-desktop", add_help=True)
    parser.add_argument("--version", action="store_true", help="Print the desktop version")
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Initialize the desktop UI offscreen and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)

    if args.version:
        print(f"Project Blacklight Desktop {__version__}")
        return 0

    if args.smoke_test:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    application = QApplication(sys.argv[:1])
    application.setApplicationName("Project Blacklight")
    application.setApplicationVersion(__version__)
    application.setStyleSheet(DESKTOP_STYLESHEET)

    window = BlacklightDesktop()

    if args.smoke_test:
        application.processEvents()
        window.close()
        return 0

    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
