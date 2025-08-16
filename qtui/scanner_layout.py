from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QComboBox, QLineEdit, QPushButton, QListWidget, QHBoxLayout


class ScannerLayout:
    """
Attributes
----------

Methods
-------

"""

    def build(self):
        widget = QWidget()
        from PyQt5.QtWidgets import (QHBoxLayout, QVBoxLayout, QGroupBox,
            QFormLayout, QLabel, QLineEdit, QComboBox, QPushButton,
            QTableWidget, QHeaderView, QProgressBar)
        # Main splitter layout
        main_layout = QHBoxLayout(widget)
        # Left: Scan Settings
        settings_group = QGroupBox('Scan Settings')
        settings_layout = QFormLayout()
        target_input = QLineEdit()
        target_input.setPlaceholderText('IP or range')
        settings_layout.addRow('Target:', target_input)
        scan_type_combo = QComboBox()
        scan_type_combo.addItems(['Discovery', 'Port Scan', 'Service Detection', 'OS Fingerprint', 'Custom'])
        settings_layout.addRow('Scan Type:', scan_type_combo)
        port_mode_combo = QComboBox()
        port_mode_combo.addItems(['Soft (stealth)', 'Hard (full)'])
        settings_layout.addRow('Port Mode:', port_mode_combo)
        start_btn = QPushButton('Start Scan')
        settings_layout.addRow(start_btn)
        settings_group.setLayout(settings_layout)
        main_layout.addWidget(settings_group)
        # Right: Results and Log
        right_layout = QVBoxLayout()
        # Results table
        results_table = QTableWidget(0, 6)
        headers = ['Host', 'Status', 'Hostname', 'Open Ports', 'Services', 'OS']
        results_table.setHorizontalHeaderLabels(headers)
        results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        right_layout.addWidget(results_table)
        # Progress bar
        progress_bar = QProgressBar()
        right_layout.addWidget(progress_bar)
        # Command log
        from qtui.cmd_log_widget import create_cmd_log
        cmd_log = create_cmd_log()
        right_layout.addWidget(cmd_log)
        main_layout.addLayout(right_layout)
        # Return widget and control references
        return widget, {
            'target_input': target_input,
            'scan_type_combo': scan_type_combo,
            'port_mode_combo': port_mode_combo,
            'start_btn': start_btn,
            'results_table': results_table,
            'progress_bar': progress_bar,
            'cmd_log': cmd_log
        }
