"""Module cmd_log_widget - description."""
from PyQt5.QtWidgets import QTextEdit
from datetime import datetime


def create_cmd_log(min_height: int = 60, max_height: int = 60) -> QTextEdit:
    """
    Returns a styled command log QTextEdit, matching dashboard style.
    """
    log = QTextEdit()
    log.setReadOnly(True)
    log.setPlaceholderText('Log działań...')
    log.setStyleSheet(
        'background: #222; color: #fff; font-family: Consolas, monospace; '
        'font-size: 12px; border-radius: 6px; padding: 4px;'
    )
    log.setMinimumHeight(min_height)
    log.setMaximumHeight(max_height)
    return log
