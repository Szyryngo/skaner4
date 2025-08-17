from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QGroupBox, QTableWidget, QAbstractItemView
from qtui.cmd_log_widget import create_cmd_log


class DevicesLayout:
    """
Attributes
----------

Methods
-------

"""

    def build(self):
        widget = QWidget()
        layout = QVBoxLayout()
        # Title label
        title = QLabel('Live Devices')
        title.setStyleSheet('font-size: 16px; font-weight: bold; margin-bottom: 10px;')
        layout.addWidget(title)
        # Refresh button for ARP scan
        from PyQt5.QtWidgets import QPushButton
        refresh_btn = QPushButton('Odśwież')
        layout.addWidget(refresh_btn)
        # Group box for active devices table
        group = QGroupBox('Aktywne urządzenia w sieci')
        group_layout = QVBoxLayout()
        devices = QTableWidget(0, 6)
        devices.setHorizontalHeaderLabels([
            'IP', 'MAC', 'Ostatnio widziany', 'Pakiety', 'Status', 'Typ'
        ])
        devices.setSelectionBehavior(QAbstractItemView.SelectRows)
        devices.setEditTriggers(QAbstractItemView.NoEditTriggers)
        devices.verticalHeader().setVisible(False)
        devices.setAlternatingRowColors(True)
        devices.setStyleSheet('QTableWidget {selection-background-color: #2196F3;}')
        group_layout.addWidget(devices)
        group.setLayout(group_layout)
        layout.addWidget(group)
        # Spacer before command log
        layout.addStretch()
        # Command log styled like other tabs
        cmd_log = create_cmd_log()
        layout.addWidget(cmd_log)
        widget.setLayout(layout)
        return widget, {'devices': devices, 'cmd_log': cmd_log, 'refresh_btn': refresh_btn}
