from __future__ import annotations

DESKTOP_STYLESHEET = """
QWidget {
    color: #171717;
    font-family: "Segoe UI";
    font-size: 13px;
}

QMainWindow,
QWidget#Root,
QFrame#Content,
QStackedWidget#Pages,
QWidget#Page {
    background: #ffffff;
}

QFrame#Sidebar {
    background: #fbfbfa;
    border-right: 1px solid #ececea;
}

QLabel#BrandMark,
QLabel#EngineBadge,
QLabel#HeroMark {
    background: #111111;
    color: #ffffff;
    border-radius: 14px;
    font-weight: 700;
}

QLabel#HeroMark {
    border-radius: 23px;
    font-size: 18px;
}

QLabel#Brand {
    color: #111111;
    font-size: 20px;
    font-weight: 700;
}

QLabel#AlphaBadge {
    background: #f5f5f3;
    color: #6f6f6b;
    border: 1px solid #e7e7e3;
    border-radius: 7px;
    padding: 2px 6px;
    font-size: 9px;
    font-weight: 600;
}

QLabel#SidebarSection {
    color: #8a8a85;
    font-size: 12px;
    padding: 0 2px 5px 2px;
}

QLabel#SidebarMuted,
QLabel#TopMuted,
QLabel#Muted,
QLabel#PageSubtitle,
QLabel#HomeHint {
    color: #7a7a75;
}

QLabel#EngineName {
    color: #222222;
    font-size: 12px;
    font-weight: 600;
}

QPushButton#SidebarIconButton,
QPushButton#TopIconButton {
    background: transparent;
    border: 0;
    border-radius: 8px;
    padding: 6px;
}

QPushButton#SidebarIconButton:hover,
QPushButton#TopIconButton:hover {
    background: #f0f0ed;
}

QPushButton#NavButton {
    background: transparent;
    color: #2a2a28;
    text-align: left;
    padding: 9px 9px;
    border: 0;
    border-radius: 8px;
}

QPushButton#NavButton:hover {
    background: #f2f2ef;
}

QPushButton#NavButton:checked {
    background: #eeeeea;
    color: #111111;
    font-weight: 600;
}

QPushButton#RecentButton {
    background: transparent;
    color: #363633;
    text-align: left;
    border: 0;
    border-radius: 6px;
    padding: 5px 2px;
}

QPushButton#RecentButton:hover {
    background: #f2f2ef;
}

QFrame#EngineRow {
    border-top: 1px solid #ececea;
}

QFrame#TopBar {
    background: #ffffff;
    border-bottom: 1px solid #eeeeec;
}

QComboBox#TopTargetCombo {
    background: transparent;
    color: #191919;
    border: 0;
    padding: 7px 24px 7px 0;
    font-size: 14px;
    font-weight: 600;
    min-width: 150px;
}

QComboBox#TopTargetCombo::drop-down {
    border: 0;
    width: 20px;
}

QComboBox#TopTargetCombo QAbstractItemView {
    background: #ffffff;
    color: #222222;
    border: 1px solid #dededb;
    selection-background-color: #f0f7f4;
    selection-color: #111111;
    padding: 5px;
}

QLabel#LocalDot {
    background: #35c995;
    border-radius: 4px;
}

QLabel#PageTitle {
    color: #151515;
    font-size: 27px;
    font-weight: 650;
}

QLabel#PageSubtitle {
    font-size: 13px;
}

QLabel#HeroTitle {
    color: #111111;
    font-size: 29px;
    font-weight: 500;
}

QFrame#Launcher {
    background: #ffffff;
    border: 1px solid #e5e5e2;
    border-radius: 20px;
}

QLineEdit#LauncherInput {
    background: transparent;
    color: #1d1d1b;
    border: 0;
    padding: 5px 0 4px 0;
    font-size: 15px;
    min-height: 28px;
}

QLineEdit#LauncherInput::placeholder {
    color: #8d8d87;
}

QPushButton#LauncherIconButton {
    background: transparent;
    color: #333330;
    border: 0;
    border-radius: 17px;
    font-size: 21px;
}

QPushButton#LauncherIconButton:hover {
    background: #f1f1ee;
}

QPushButton#LauncherToolButton {
    background: transparent;
    color: #777771;
    border: 0;
    border-radius: 7px;
    padding: 7px 8px;
}

QPushButton#LauncherToolButton:hover {
    background: #f5f5f2;
    color: #222222;
}

QPushButton#LauncherToolButton:checked {
    background: #ecf8f4;
    color: #13855f;
    font-weight: 600;
}

QPushButton#RoundPrimary {
    background: #78d9bd;
    color: #ffffff;
    border: 0;
    border-radius: 21px;
    font-size: 21px;
    font-weight: 700;
}

QPushButton#RoundPrimary:hover {
    background: #5ecfac;
}

QPushButton#RoundPrimary:disabled {
    background: #d9d9d5;
    color: #ffffff;
}

QFrame#TargetRow,
QFrame#MetricCard,
QFrame#FormPanel,
QFrame#DetailPanel {
    background: #ffffff;
    border: 1px solid #e7e7e4;
    border-radius: 12px;
}

QFrame#TargetRow:hover {
    background: #fcfcfb;
    border: 1px solid #d8d8d4;
}

QFrame#TargetList {
    background: transparent;
    border: 0;
}

QLabel#TargetBadge {
    background: #f1f5f3;
    color: #167e5b;
    border: 1px solid #e1ebe7;
    border-radius: 9px;
    font-weight: 700;
}

QLabel#StatusReady {
    color: #067647;
    background: #ecfdf3;
    border: 1px solid #abefc6;
    border-radius: 8px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}

QLabel#StatusSoon {
    color: #6b6b66;
    background: #f5f5f3;
    border: 1px solid #e4e4e0;
    border-radius: 8px;
    padding: 4px 8px;
    font-size: 11px;
}

QLabel#MetricLabel {
    color: #8b8b85;
    font-size: 10px;
    font-weight: 650;
}

QLabel#MetricValue {
    color: #171717;
    font-size: 23px;
    font-weight: 650;
}

QLabel#SectionTitle {
    color: #1a1a19;
    font-size: 14px;
    font-weight: 650;
}

QPushButton#PrimaryButton {
    background: #111111;
    color: #ffffff;
    border: 1px solid #111111;
    border-radius: 9px;
    padding: 9px 16px;
    font-weight: 600;
}

QPushButton#PrimaryButton:hover {
    background: #2a2a28;
}

QPushButton#PrimaryButton:disabled {
    background: #d8d8d5;
    border-color: #d8d8d5;
}

QPushButton#QuietButton {
    background: #ffffff;
    color: #242422;
    border: 1px solid #dededb;
    border-radius: 9px;
    padding: 8px 13px;
}

QPushButton#QuietButton:hover {
    background: #f8f8f6;
    border-color: #cfcfca;
}

QPushButton#QuietButton:disabled {
    background: #f7f7f5;
    color: #aaa9a3;
    border-color: #e9e9e6;
}

QLineEdit,
QComboBox,
QSpinBox {
    background: #ffffff;
    color: #1e1e1c;
    border: 1px solid #dededb;
    border-radius: 9px;
    padding: 8px 10px;
    min-height: 20px;
}

QLineEdit:focus,
QComboBox:focus,
QSpinBox:focus {
    border: 1px solid #9ccfbd;
}

QComboBox QAbstractItemView {
    background: #ffffff;
    color: #222222;
    border: 1px solid #dededb;
    selection-background-color: #edf8f4;
    selection-color: #111111;
}

QCheckBox {
    spacing: 8px;
    color: #444440;
}

QCheckBox::indicator {
    width: 15px;
    height: 15px;
    border: 1px solid #bdbdb8;
    background: #ffffff;
    border-radius: 3px;
}

QCheckBox::indicator:checked {
    background: #26b98a;
    border-color: #26b98a;
}

QTableWidget {
    background: #ffffff;
    alternate-background-color: #fbfbfa;
    gridline-color: #eeeeeb;
    border: 1px solid #e5e5e2;
    border-radius: 10px;
    selection-background-color: #edf8f4;
    selection-color: #171717;
}

QHeaderView::section {
    background: #fafaf8;
    color: #777771;
    border: 0;
    border-right: 1px solid #eeeeeb;
    border-bottom: 1px solid #e6e6e3;
    padding: 8px;
    font-size: 11px;
    font-weight: 650;
}

QPlainTextEdit,
QTextEdit {
    background: #fafaf8;
    color: #2b2b28;
    border: 1px solid #e6e6e2;
    border-radius: 8px;
    padding: 8px;
    selection-background-color: #d9f2e9;
}

QProgressBar {
    background: #ededeb;
    border: 0;
    border-radius: 3px;
    min-height: 6px;
    max-height: 6px;
}

QProgressBar::chunk {
    background: #39c49a;
    border-radius: 3px;
}

QScrollBar:vertical {
    background: transparent;
    width: 9px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background: #d5d5d0;
    border-radius: 4px;
    min-height: 30px;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0;
}

QToolTip {
    background: #ffffff;
    color: #222222;
    border: 1px solid #d9d9d5;
    padding: 5px;
}
"""
