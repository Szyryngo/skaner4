from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qtui.scanner_layout import ScannerLayout
from datetime import datetime

class ScannerTab(QWidget):
    """Zakładka Scanner: ręczne skanowanie sieci"""
    def __init__(self, parent=None):
        super().__init__(parent)
        widget, ctrls = ScannerLayout().build()
        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)
        # Zapamiętaj kontrolki i dodaj wiring
        self.ctrls = ctrls
        self.ctrls['scan_btn'].clicked.connect(
            lambda: self.ctrls['cmd_log'].append(
                f"[{datetime.now().strftime('%H:%M:%S')}] Rozpoczęto skanowanie sieci"
            )
        )
        # After scan complete event from core, log results
        if 'cmd_log' in self.ctrls:
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] ScannerTab initialized")
