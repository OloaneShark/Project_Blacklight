from __future__ import annotations

DESKTOP_STYLESHEET = """
QWidget {
    background: #0b0c10;
    color: #e8e9ee;
    font-family: "Segoe UI";
    font-size: 13px;
}

QMainWindow {
    background: #0b0c10;
}

QFrame#Sidebar {
    background: #111218;
    border-right: 1px solid #292b35;
}

QLabel#Brand {
    color: #f2f2f7;
    font-size: 21px;
    font-weight: 700;
    letter-spacing: 2px;
}

QLabel#Version {
    color: #777a88;
    font-size: 11px;
}

QLabel#PageTitle {
    color: #f5f5f8;
    font-size: 28px;
    font-weight: 700;
}

QLabel#PageSubtitle {
    color: #9295a3;
    font-size: 13px;
}

QPushButton#NavButton {
    background: transparent;
    color: #aeb0ba;
    text-align: left;
    padding: 12px 14px;
    border: 0;
    border-left: 2px solid transparent;
}

QPushButton#NavButton:hover {
    background: #171820;
    color: #ffffff;
}

QPushButton#NavButton:checked {
    background: #171820;
    color: #ffffff;
    border-left: 2px solid #8b5cf6;
}

QFrame#Panel, QFrame#MetricCard, QFrame#TargetCard {
    background: #121319;
    border: 1px solid #292b35;
}

QFrame#TargetCard:hover {
    border: 1px solid #6d4ae5;
}

QLabel#MetricLabel {
    color: #858896;
    font-size: 11px;
    font-weight: 600;
}

QLabel#MetricValue {
    color: #f8f8fb;
    font-size: 26px;
    font-weight: 700;
}

QLabel#SectionTitle {
    color: #f1f1f5;
    font-size: 15px;
    font-weight: 700;
}

QLabel#Muted {
    color: #858896;
}

QPushButton#PrimaryButton {
    background: #7c4dff;
    color: #ffffff;
    border: 1px solid #8b5cf6;
    padding: 10px 18px;
    font-weight: 700;
}

QPushButton#PrimaryButton:hover {
    background: #8b5cf6;
}

QPushButton#PrimaryButton:disabled {
    background: #31323a;
    color: #777a88;
    border-color: #3a3b45;
}

QPushButton#SecondaryButton {
    background: #181920;
    color: #e8e9ee;
    border: 1px solid #353744;
    padding: 9px 14px;
}

QPushButton#SecondaryButton:hover {
    border-color: #6d4ae5;
}

QLineEdit, QComboBox, QSpinBox {
    background: #0f1015;
    color: #f0f0f3;
    border: 1px solid #343642;
    padding: 8px;
    min-height: 18px;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #7c4dff;
}

QComboBox QAbstractItemView {
    background: #14151b;
    selection-background-color: #29203d;
    selection-color: #ffffff;
    border: 1px solid #343642;
}

QCheckBox {
    spacing: 8px;
    color: #c4c6cf;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #505260;
    background: #101116;
}

QCheckBox::indicator:checked {
    background: #7c4dff;
    border-color: #8b5cf6;
}

QTableWidget {
    background: #101116;
    alternate-background-color: #13141a;
    gridline-color: #242630;
    border: 1px solid #292b35;
    selection-background-color: #282038;
    selection-color: #ffffff;
}

QHeaderView::section {
    background: #171820;
    color: #9ea0ad;
    border: 0;
    border-right: 1px solid #292b35;
    border-bottom: 1px solid #292b35;
    padding: 8px;
    font-weight: 600;
}

QTextEdit, QPlainTextEdit {
    background: #0f1015;
    color: #d9dae1;
    border: 1px solid #292b35;
    padding: 8px;
    selection-background-color: #4f3788;
}

QProgressBar {
    background: #111218;
    border: 1px solid #292b35;
    min-height: 7px;
    max-height: 7px;
    text-align: center;
}

QProgressBar::chunk {
    background: #7c4dff;
}

QScrollBar:vertical {
    background: #0f1015;
    width: 10px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background: #333540;
    min-height: 30px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QToolTip {
    background: #171820;
    color: #ffffff;
    border: 1px solid #4d4f5c;
}
"""
