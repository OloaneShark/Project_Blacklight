from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QThread, Qt, Signal, QSize
from PySide6.QtGui import QBrush, QColor
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
    QStyle,
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
from blacklight_security.desktop.theme import DESKTOP_STYLESHEET
from blacklight_security.models import Severity
from blacklight_security.risk import assess_risk


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
    Severity.CRITICAL: "#d92d20",
    Severity.HIGH: "#dc6803",
    Severity.MEDIUM: "#b54708",
    Severity.LOW: "#027a48",
    Severity.ERROR: "#6941c6",
    Severity.INFO: "#175cd3",
    Severity.PASS: "#067647",
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
        layout.setContentsMargins(16, 13, 16, 13)
        layout.setSpacing(3)

        caption = QLabel(label.upper())
        caption.setObjectName("MetricLabel")
        self.value = QLabel(value)
        self.value.setObjectName("MetricValue")

        layout.addWidget(caption)
        layout.addWidget(self.value)


class TargetRow(QFrame):
    selected = Signal(str)

    def __init__(
        self,
        provider: str,
        title: str,
        description: str,
        status: str,
        enabled: bool,
    ):
        super().__init__()
        self.provider = provider
        self.enabled = enabled
        self.setObjectName("TargetRow")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 15, 18, 15)
        layout.setSpacing(14)

        badge = QLabel(title[:1].upper())
        badge.setObjectName("TargetBadge")
        badge.setFixedSize(34, 34)
        badge.setAlignment(Qt.AlignCenter)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(3)
        name = QLabel(title)
        name.setObjectName("SectionTitle")
        detail = QLabel(description)
        detail.setObjectName("Muted")
        detail.setWordWrap(True)
        text_layout.addWidget(name)
        text_layout.addWidget(detail)

        state = QLabel(status)
        state.setObjectName("StatusReady" if enabled else "StatusSoon")

        button = QPushButton("Open" if enabled else "Coming later")
        button.setObjectName("QuietButton")
        button.setEnabled(enabled)
        button.clicked.connect(lambda: self.selected.emit(self.provider))

        layout.addWidget(badge)
        layout.addLayout(text_layout, 1)
        layout.addWidget(state)
        layout.addWidget(button)

    def mousePressEvent(self, event: Any) -> None:
        if self.enabled and event.button() == Qt.LeftButton:
            self.selected.emit(self.provider)
        super().mousePressEvent(event)


class BlacklightDesktop(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Project Blacklight {__version__}")
        self.resize(1420, 860)
        self.setMinimumSize(1120, 720)

        self.current_outcome: DesktopScanOutcome | None = None
        self.scan_thread: QThread | None = None
        self.scan_worker: ScanWorker | None = None
        self.scan_origin = "form"

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_sidebar())

        content = QFrame()
        content.setObjectName("Content")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        content_layout.addWidget(self._build_topbar())

        self.pages = QStackedWidget()
        self.pages.setObjectName("Pages")
        self.dashboard_page = self._build_dashboard()
        self.targets_page = self._build_targets_page()
        self.scan_page = self._build_scan_page()
        self.findings_page = self._build_findings_page()
        self.reports_page = self._build_reports_page()
        self.settings_page = self._build_settings_page()

        for page in (
            self.dashboard_page,
            self.targets_page,
            self.scan_page,
            self.findings_page,
            self.reports_page,
            self.settings_page,
        ):
            self.pages.addWidget(page)

        content_layout.addWidget(self.pages, 1)
        root_layout.addWidget(content, 1)
        self._set_page(0)

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(278)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 26, 16, 16)
        layout.setSpacing(4)

        brand_row = QHBoxLayout()
        brand_row.setSpacing(8)

        mark = QLabel("B")
        mark.setObjectName("BrandMark")
        mark.setAlignment(Qt.AlignCenter)
        mark.setFixedSize(28, 28)

        brand = QLabel("blacklight")
        brand.setObjectName("Brand")

        alpha = QLabel("ALPHA")
        alpha.setObjectName("AlphaBadge")

        brand_row.addWidget(mark)
        brand_row.addWidget(brand)
        brand_row.addWidget(alpha)
        brand_row.addStretch()

        search = QPushButton("")
        search.setObjectName("SidebarIconButton")
        search.setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
        search.setIconSize(QSize(15, 15))
        search.setToolTip("Search is coming later")
        brand_row.addWidget(search)

        layout.addLayout(brand_row)
        layout.addSpacing(18)

        nav_specs = (
            ("Home", 0, QStyle.SP_DirHomeIcon),
            ("New scan", 2, QStyle.SP_FileDialogNewFolder),
            ("Targets", 1, QStyle.SP_ComputerIcon),
            ("Findings", 3, QStyle.SP_MessageBoxWarning),
            ("Reports", 4, QStyle.SP_FileIcon),
        )

        self.nav_buttons: list[tuple[int, QPushButton]] = []
        for label, page_index, icon in nav_specs:
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setIcon(self.style().standardIcon(icon))
            button.setIconSize(QSize(16, 16))
            button.clicked.connect(
                lambda checked=False, i=page_index: self._set_page(i)
            )
            layout.addWidget(button)
            self.nav_buttons.append((page_index, button))

        more = QPushButton("More")
        more.setObjectName("NavButton")
        more.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMenuButton))
        more.setIconSize(QSize(16, 16))
        more.clicked.connect(lambda: self._set_page(5))
        layout.addWidget(more)

        layout.addSpacing(22)
        recents_title = QLabel("Recents")
        recents_title.setObjectName("SidebarSection")
        layout.addWidget(recents_title)

        self.recents_box = QVBoxLayout()
        self.recents_box.setSpacing(2)
        self.recents_placeholder = QLabel("No recent scans yet")
        self.recents_placeholder.setObjectName("SidebarMuted")
        self.recents_box.addWidget(self.recents_placeholder)
        layout.addLayout(self.recents_box)
        layout.addStretch()

        account = QFrame()
        account.setObjectName("EngineRow")
        account_layout = QHBoxLayout(account)
        account_layout.setContentsMargins(0, 8, 0, 0)
        account_layout.setSpacing(9)

        engine_badge = QLabel("B")
        engine_badge.setObjectName("EngineBadge")
        engine_badge.setAlignment(Qt.AlignCenter)
        engine_badge.setFixedSize(32, 32)

        engine_text = QVBoxLayout()
        engine_text.setSpacing(0)
        engine_name = QLabel("Blacklight")
        engine_name.setObjectName("EngineName")
        engine_state = QLabel("Local engine")
        engine_state.setObjectName("SidebarMuted")
        engine_text.addWidget(engine_name)
        engine_text.addWidget(engine_state)

        settings = QPushButton("")
        settings.setObjectName("SidebarIconButton")
        settings.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        settings.setIconSize(QSize(16, 16))
        settings.clicked.connect(lambda: self._set_page(5))
        settings.setToolTip("Settings")

        account_layout.addWidget(engine_badge)
        account_layout.addLayout(engine_text)
        account_layout.addStretch()
        account_layout.addWidget(settings)
        layout.addWidget(account)

        return sidebar

    def _build_topbar(self) -> QWidget:
        topbar = QFrame()
        topbar.setObjectName("TopBar")
        topbar.setFixedHeight(70)

        layout = QHBoxLayout(topbar)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(12)

        self.top_target_combo = QComboBox()
        self.top_target_combo.setObjectName("TopTargetCombo")
        self.top_target_combo.addItem("Select target", None)
        self.top_target_combo.addItem("AWS Account", "aws")
        self.top_target_combo.addItem("Docker Project", "docker")
        self.top_target_combo.addItem("Kubernetes Manifests", "kubernetes")
        self.top_target_combo.currentIndexChanged.connect(self._top_target_changed)
        layout.addWidget(self.top_target_combo)

        layout.addStretch()

        local_dot = QLabel("")
        local_dot.setObjectName("LocalDot")
        local_dot.setFixedSize(8, 8)
        local_status = QLabel("Local")
        local_status.setObjectName("TopMuted")

        layout.addWidget(local_dot)
        layout.addWidget(local_status)

        about = QPushButton("")
        about.setObjectName("TopIconButton")
        about.setIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
        about.setIconSize(QSize(16, 16))
        about.setToolTip("About Project Blacklight")
        about.clicked.connect(lambda: self._set_page(5))
        layout.addWidget(about)

        return topbar

    def _page_shell(self, title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        page.setObjectName("Page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)

        title_label = QLabel(title)
        title_label.setObjectName("PageTitle")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("PageSubtitle")
        subtitle_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)
        return page, layout

    def _build_dashboard(self) -> QWidget:
        page = QWidget()
        page.setObjectName("Page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(36, 0, 36, 0)
        outer.setSpacing(0)
        outer.addStretch(3)

        center = QWidget()
        center.setMaximumWidth(760)
        center_layout = QVBoxLayout(center)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(22)

        headline_row = QHBoxLayout()
        headline_row.setSpacing(12)
        hero_mark = QLabel("B")
        hero_mark.setObjectName("HeroMark")
        hero_mark.setAlignment(Qt.AlignCenter)
        hero_mark.setFixedSize(46, 46)

        headline = QLabel("What should Blacklight scan?")
        headline.setObjectName("HeroTitle")
        headline_row.addStretch()
        headline_row.addWidget(hero_mark)
        headline_row.addWidget(headline)
        headline_row.addStretch()
        center_layout.addLayout(headline_row)

        launcher = QFrame()
        launcher.setObjectName("Launcher")
        launcher_layout = QVBoxLayout(launcher)
        launcher_layout.setContentsMargins(20, 14, 14, 12)
        launcher_layout.setSpacing(10)

        self.home_input = QLineEdit()
        self.home_input.setObjectName("LauncherInput")
        self.home_input.setPlaceholderText("Select a target to start")
        self.home_input.returnPressed.connect(self._run_home_scan)
        launcher_layout.addWidget(self.home_input)

        launcher_controls = QHBoxLayout()
        launcher_controls.setSpacing(8)

        add_button = QPushButton("+")
        add_button.setObjectName("LauncherIconButton")
        add_button.setFixedSize(34, 34)
        add_button.clicked.connect(self._home_browse_or_targets)
        launcher_controls.addWidget(add_button)

        self.home_provider_buttons: dict[str, QPushButton] = {}
        for provider, label in (
            ("aws", "AWS"),
            ("docker", "Docker"),
            ("kubernetes", "Kubernetes"),
        ):
            button = QPushButton(label)
            button.setObjectName("LauncherToolButton")
            button.setCheckable(True)
            button.clicked.connect(
                lambda checked=False, p=provider: self._select_home_provider(p)
            )
            self.home_provider_buttons[provider] = button
            launcher_controls.addWidget(button)

        advanced = QPushButton("Advanced")
        advanced.setObjectName("LauncherToolButton")
        advanced.clicked.connect(lambda: self._set_page(2))
        launcher_controls.addWidget(advanced)

        launcher_controls.addStretch()

        self.home_run_button = QPushButton("↑")
        self.home_run_button.setObjectName("RoundPrimary")
        self.home_run_button.setFixedSize(42, 42)
        self.home_run_button.clicked.connect(self._run_home_scan)
        launcher_controls.addWidget(self.home_run_button)

        launcher_layout.addLayout(launcher_controls)
        center_layout.addWidget(launcher)

        self.home_status = QLabel("Runs locally using the same deterministic Blacklight engine as the CLI.")
        self.home_status.setObjectName("HomeHint")
        self.home_status.setAlignment(Qt.AlignCenter)
        self.home_status.setWordWrap(True)
        center_layout.addWidget(self.home_status)

        outer.addWidget(center, 0, Qt.AlignHCenter)
        outer.addStretch(4)
        return page

    def _build_targets_page(self) -> QWidget:
        page, layout = self._page_shell(
            "Targets",
            "Choose the kind of infrastructure or project Blacklight should inspect.",
        )

        target_specs = (
            (
                "aws",
                "AWS Account",
                "Use an AWS profile or the default credential chain for read-only cloud checks.",
                "Ready",
                True,
            ),
            (
                "docker",
                "Docker Project",
                "Choose a local project directory or Dockerfile. No Docker daemon is required.",
                "Ready",
                True,
            ),
            (
                "kubernetes",
                "Kubernetes Manifests",
                "Choose local YAML manifests. No cluster credentials are required.",
                "Ready",
                True,
            ),
            (
                "server",
                "Server / SSH",
                "Future live-host scans for SSH, firewall, users, services and host configuration.",
                "Next phase",
                False,
            ),
        )

        list_frame = QFrame()
        list_frame.setObjectName("TargetList")
        list_layout = QVBoxLayout(list_frame)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(10)

        for spec in target_specs:
            row = TargetRow(*spec)
            row.selected.connect(self._start_target)
            list_layout.addWidget(row)

        layout.addWidget(list_frame)
        layout.addStretch()
        return page

    def _build_scan_page(self) -> QWidget:
        page, layout = self._page_shell(
            "New scan",
            "Configure the target and optional gate behavior before Blacklight runs.",
        )

        panel = QFrame()
        panel.setObjectName("FormPanel")
        panel.setMaximumWidth(820)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(26, 24, 26, 24)
        panel_layout.setSpacing(16)

        form = QFormLayout()
        form.setHorizontalSpacing(22)
        form.setVerticalSpacing(14)

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
        browse.setObjectName("QuietButton")
        browse.clicked.connect(self._browse_path)
        path_layout.addWidget(self.path_input, 1)
        path_layout.addWidget(browse)
        self.path_label = QLabel("Path")
        form.addRow(self.path_label, self.path_container)

        self.profile_input = QLineEdit()
        self.profile_input.setPlaceholderText("Optional AWS profile")
        self.profile_label = QLabel("AWS profile")
        form.addRow(self.profile_label, self.profile_input)

        self.region_input = QLineEdit()
        self.region_input.setPlaceholderText("Optional region override")
        self.region_label = QLabel("AWS region")
        form.addRow(self.region_label, self.region_input)

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
        self.run_button = QPushButton("Run scan")
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

        layout.addWidget(panel, 0, Qt.AlignHCenter)
        layout.addStretch()
        self._provider_changed()
        return page

    def _build_findings_page(self) -> QWidget:
        page, layout = self._page_shell(
            "Findings",
            "Select a finding to inspect the evidence and remediation behind it.",
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
        detail_panel.setObjectName("DetailPanel")
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(18, 18, 18, 18)
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
        splitter.setSizes([760, 420])

        layout.addWidget(splitter, 1)
        return page

    def _build_reports_page(self) -> QWidget:
        page, layout = self._page_shell(
            "Reports",
            "Export the most recent result without rerunning the scan.",
        )

        panel = QFrame()
        panel.setObjectName("FormPanel")
        panel.setMaximumWidth(820)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(24, 22, 24, 22)
        panel_layout.setSpacing(14)

        self.report_status = QLabel("No completed scan yet.")
        self.report_status.setObjectName("Muted")
        panel_layout.addWidget(self.report_status)

        buttons = QHBoxLayout()
        self.export_json_button = QPushButton("Export JSON")
        self.export_html_button = QPushButton("Export HTML")
        for button in (self.export_json_button, self.export_html_button):
            button.setObjectName("QuietButton")
            button.setEnabled(False)
        self.export_json_button.clicked.connect(lambda: self._export_report("json"))
        self.export_html_button.clicked.connect(lambda: self._export_report("html"))
        buttons.addWidget(self.export_json_button)
        buttons.addWidget(self.export_html_button)
        buttons.addStretch()
        panel_layout.addLayout(buttons)

        layout.addWidget(panel, 0, Qt.AlignHCenter)
        layout.addStretch()
        return page

    def _build_settings_page(self) -> QWidget:
        page, layout = self._page_shell(
            "More",
            "Blacklight Desktop is intentionally local-first in this release.",
        )

        panel = QFrame()
        panel.setObjectName("FormPanel")
        panel.setMaximumWidth(820)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(24, 22, 24, 22)
        panel_layout.setSpacing(9)

        heading = QLabel("About this build")
        heading.setObjectName("SectionTitle")
        panel_layout.addWidget(heading)

        for text in (
            f"Version {__version__}",
            "Light mode only",
            "Detection is deterministic",
            "Current targets: AWS, Docker, Kubernetes manifests",
            "Server / SSH targets: next product phase",
            "No hosted Blacklight account is required",
        ):
            label = QLabel(text)
            label.setObjectName("Muted")
            panel_layout.addWidget(label)

        layout.addWidget(panel, 0, Qt.AlignHCenter)
        layout.addStretch()
        return page

    def _set_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        for page_index, button in self.nav_buttons:
            button.setChecked(page_index == index)

    def _top_target_changed(self) -> None:
        provider = self.top_target_combo.currentData()
        if provider is None:
            self._update_home_provider(None)
            return
        self._update_home_provider(provider)
        provider_index = {"aws": 0, "docker": 1, "kubernetes": 2}[provider]
        if hasattr(self, "provider_combo"):
            self.provider_combo.setCurrentIndex(provider_index)

    def _select_home_provider(self, provider: str) -> None:
        index = {"aws": 1, "docker": 2, "kubernetes": 3}[provider]
        self.top_target_combo.setCurrentIndex(index)

    def _update_home_provider(self, provider: str | None) -> None:
        if not hasattr(self, "home_input"):
            return

        for key, button in self.home_provider_buttons.items():
            button.setChecked(key == provider)

        placeholders = {
            "aws": "AWS profile (optional — leave blank for the default credential chain)",
            "docker": "Project folder or Dockerfile path",
            "kubernetes": "Manifest folder or YAML file path",
            None: "Select a target above or choose AWS, Docker, or Kubernetes below",
        }
        self.home_input.setPlaceholderText(placeholders[provider])

    def _start_target(self, provider: str) -> None:
        provider_index = {"aws": 0, "docker": 1, "kubernetes": 2}.get(provider)
        if provider_index is None:
            return
        self.provider_combo.setCurrentIndex(provider_index)
        self.top_target_combo.setCurrentIndex(provider_index + 1)
        self._set_page(2)

    def _provider_changed(self) -> None:
        if not hasattr(self, "provider_combo"):
            return
        provider = self.provider_combo.currentData()
        is_aws = provider == "aws"
        self.profile_input.setVisible(is_aws)
        self.profile_label.setVisible(is_aws)
        self.region_input.setVisible(is_aws)
        self.region_label.setVisible(is_aws)
        self.path_container.setVisible(not is_aws)
        self.path_label.setVisible(not is_aws)

        top_index = {"aws": 1, "docker": 2, "kubernetes": 3}.get(provider)
        if top_index is not None and self.top_target_combo.currentIndex() != top_index:
            self.top_target_combo.blockSignals(True)
            self.top_target_combo.setCurrentIndex(top_index)
            self.top_target_combo.blockSignals(False)
            self._update_home_provider(provider)

    def _home_browse_or_targets(self) -> None:
        provider = self.top_target_combo.currentData()
        if provider in {"docker", "kubernetes"}:
            selected = QFileDialog.getExistingDirectory(
                self,
                "Select project folder",
                self.home_input.text() or str(Path.cwd()),
            )
            if selected:
                self.home_input.setText(selected)
            return
        self._set_page(1)

    def _browse_path(self) -> None:
        provider = self.provider_combo.currentData()
        title = (
            "Select Docker project folder"
            if provider == "docker"
            else "Select Kubernetes manifest folder"
        )
        selected = QFileDialog.getExistingDirectory(
            self,
            title,
            self.path_input.text() or str(Path.cwd()),
        )
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

    def _home_scan_request(self) -> DesktopScanRequest | None:
        provider = self.top_target_combo.currentData()
        if provider is None:
            QMessageBox.information(
                self,
                "Choose a target",
                "Select AWS, Docker, or Kubernetes before starting a scan.",
            )
            return None

        value = self.home_input.text().strip()
        if provider == "aws":
            return DesktopScanRequest(provider="aws", profile=value or None)

        return DesktopScanRequest(
            provider=provider,
            path=Path(value) if value else Path.cwd(),
        )

    def _run_home_scan(self) -> None:
        request = self._home_scan_request()
        if request is None:
            return
        self.scan_origin = "home"
        self._start_scan_worker(request)

    def _run_scan(self) -> None:
        self.scan_origin = "form"
        self._start_scan_worker(self._scan_request())

    def _start_scan_worker(self, request: DesktopScanRequest) -> None:
        if self.scan_thread is not None:
            return

        self.run_button.setEnabled(False)
        self.home_run_button.setEnabled(False)
        self.scan_progress.setRange(0, 0)
        self.scan_progress.show()
        self.scan_status.setText(f"Scanning {request.provider.upper()}...")
        self.home_status.setText(f"Scanning {request.provider.upper()} with Blacklight...")

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

        summary = (
            f"{result.provider.upper()} · risk {assessment.level} ({assessment.score}/100) · "
            f"{actionable} actionable · coverage {result.coverage.status}"
        )
        self.scan_status.setText(f"Complete. {summary}")
        self.home_status.setText(summary)
        self._add_recent(summary)
        self._set_page(3)

    def _add_recent(self, summary: str) -> None:
        if self.recents_placeholder is not None:
            self.recents_placeholder.hide()

        button = QPushButton(summary)
        button.setObjectName("RecentButton")
        button.setToolTip(summary)
        button.clicked.connect(lambda: self._set_page(3))
        self.recents_box.insertWidget(0, button)

        while self.recents_box.count() > 5:
            item = self.recents_box.takeAt(self.recents_box.count() - 1)
            widget = item.widget()
            if widget is not None and widget is not self.recents_placeholder:
                widget.deleteLater()

    def _scan_failed(self, message: str) -> None:
        self.scan_status.setText("Scan failed.")
        self.home_status.setText("Scan failed. Open New scan to review the target configuration.")
        QMessageBox.critical(self, "Blacklight scan failed", message)

    def _scan_thread_finished(self) -> None:
        self.scan_progress.hide()
        self.scan_progress.setRange(0, 1)
        self.scan_progress.setValue(0)
        self.run_button.setEnabled(True)
        self.home_run_button.setEnabled(True)

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
            severity_item.setForeground(
                QBrush(QColor(SEVERITY_COLORS.get(finding.severity, "#111111")))
            )
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
            self.finding_detail.setPlainText(
                "The selected scanner returned no resources/findings."
            )

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
            f"{finding.severity.value} · {finding.provider}/{finding.service} · "
            f"{finding.check_id}"
        )

        detail = [
            f"RESOURCE\n{finding.resource_id}",
            f"\nDETAIL\n{finding.description}",
        ]
        if finding.remediation:
            detail.append(f"\nREMEDIATION\n{finding.remediation}")
        if finding.evidence:
            detail.append(
                "\nEVIDENCE\n"
                + json.dumps(
                    finding.evidence,
                    indent=2,
                    sort_keys=True,
                    default=str,
                )
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
    application.setStyle("Fusion")
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
