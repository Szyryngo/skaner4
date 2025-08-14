from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QGroupBox, QTableWidget, QAbstractItemView

class DevicesLayout:
    def build(self):
        widget = QWidget()
        layout = QVBoxLayout()
        title = QLabel("Live Devices")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        group = QGroupBox("Aktywne urządzenia w sieci")
        group_layout = QVBoxLayout()
        devices = QTableWidget(0, 5)
        devices.setHorizontalHeaderLabels([
            "IP", "MAC", "Ostatnio widziany", "Pakiety", "Status"
        ])
        devices.setSelectionBehavior(QAbstractItemView.SelectRows)
        devices.setEditTriggers(QAbstractItemView.NoEditTriggers)
        devices.verticalHeader().setVisible(False)
        devices.setAlternatingRowColors(True)
        devices.setStyleSheet("QTableWidget {selection-background-color: #2196F3;}")
        group_layout.addWidget(devices)
        group.setLayout(group_layout)
        layout.addWidget(group)
        layout.addStretch()
        widget.setLayout(layout)
        return widget, {'devices': devices}
