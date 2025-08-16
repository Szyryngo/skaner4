from PyQt5.QtWidgets import QWidget, QVBoxLayout
from PyQt5.QtCore import QTimer
from qtui.scanner_layout import ScannerLayout
from modules.scanner import ScannerModule
from core.events import Event
from datetime import datetime

class ScannerTab(QWidget):
    """Zakładka Scanner: ręczne skanowanie sieci"""
    def __init__(self, parent=None):
        super().__init__(parent)
        # Build UI
        widget, ctrls = ScannerLayout().build()
        layout = QVBoxLayout()
        layout.addWidget(widget)
        class ScannerTab(QWidget):
            """Zakładka Scanner: ręczne skanowanie sieci"""
            def __init__(self, parent=None):
                super().__init__(parent)
                # Build UI
                widget, ctrls = ScannerLayout().build()
                layout = QVBoxLayout()
                layout.addWidget(widget)
                self.setLayout(layout)

                # Controls and scanner module
                self.ctrls = ctrls
                self._scanner_module = ScannerModule()
                self._scanner_module.initialize({})

                # Connect start button
                self.ctrls['start_btn'].clicked.connect(self._on_start_scan)

                # Timer for polling results
                self._scan_timer = QTimer(self)
                self._scan_timer.timeout.connect(self._process_scan_result)
                self._scan_timer.start(1000)

                # Initial log
                self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] ScannerTab initialized")

            def _on_start_scan(self):
                scan_type = self.ctrls['scan_type_combo'].currentText()
                target = self.ctrls['target_input'].text()
                subtype = self.ctrls['port_mode_combo'].currentText()

                # Trigger scan
                self._scanner_module.handle_event(
                    Event('SCAN_REQUEST', {'type': scan_type, 'target': target, 'subtype': subtype})
                )

                # Clear results table
                table = self.ctrls['results_table']
                table.setRowCount(0)

                # Log start
                self.ctrls['cmd_log'].append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Rozpoczęto {scan_type} na {target} ({subtype})"
                )

            def _process_scan_result(self):
                ev = self._scanner_module.generate_event()
                if ev and ev.type == 'SCAN_COMPLETED':
                    hosts = getattr(self._scanner_module, '_scan_result', [])
                    table = self.ctrls['results_table']
                    table.setRowCount(0)
                    from PyQt5.QtWidgets import QTableWidgetItem
                    for row, ip in enumerate(hosts):
                        table.insertRow(row)
                        table.setItem(row, 0, QTableWidgetItem(str(ip)))

                    # Log completion
                    self.ctrls['cmd_log'].append(
                        f"[{datetime.now().strftime('%H:%M:%S')}] Skanowanie zakończone: aktywne hosty {hosts}"
                    )
