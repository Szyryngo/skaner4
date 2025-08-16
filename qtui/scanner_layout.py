from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QGroupBox, QVBoxLayout, QPushButton, QListWidget


class ScannerLayout:
    """
Attributes
----------

Methods
-------

"""

    def build(self):
        widget = QWidget()
        layout = QVBoxLayout()
        title = QLabel('Network Scanner')
        title.setStyleSheet(
            'font-size: 16px; font-weight: bold; margin-bottom: 10px;')
        layout.addWidget(title)
        group = QGroupBox('Skanowanie sieci')
        group_layout = QVBoxLayout()
        scan_btn = QPushButton('Uruchom skanowanie')
        group_layout.addWidget(scan_btn)
        results = QListWidget()
        group_layout.addWidget(results)
        group.setLayout(group_layout)
        layout.addWidget(group)
        layout.addStretch()
        # log poleceń w zakładce Scanner
        from qtui.cmd_log_widget import create_cmd_log
        cmd_log = create_cmd_log()
        layout.addWidget(cmd_log)
        widget.setLayout(layout)
        return widget, {
            'scan_btn': scan_btn,
            'results': results,
            'cmd_log': cmd_log
        }
