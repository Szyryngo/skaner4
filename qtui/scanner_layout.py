from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QFormLayout,
    QLabel, QLineEdit, QComboBox, QPushButton, QTableWidget,
    QHeaderView, QProgressBar
)
from PyQt5.QtCore import Qt
from qtui.cmd_log_widget import create_cmd_log

class ScannerLayout:
    """UI builder for the Scanner tab."""

    def build(self):
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        split_layout = QHBoxLayout()

        # Settings panel
        settings_group = QGroupBox('Ustawienia skanu')
        settings_layout = QFormLayout()

        target_input = QLineEdit()
        target_input.setPlaceholderText('Zakres IP (np. 192.168.0.0/24)')
        settings_layout.addRow('Zakres IP:', target_input)

        scan_type_combo = QComboBox()
        scan_type_combo.addItems(['Discovery', 'Port Scan', 'Service Detection'])
        settings_layout.addRow('Tryb skanu:', scan_type_combo)

        port_mode_combo = QComboBox()
        port_mode_combo.addItems(['SYN', 'UDP', 'ICMP'])
        settings_layout.addRow('Port Mode:', port_mode_combo)

        port_selection_combo = QComboBox()
        port_selection_combo.addItems([
            '21 (FTP)',
            '22 (SSH)',
            '25 (SMTP)',
            '53 (DNS)',
            '80 (HTTP)',
            '110 (POP3)',
            '143 (IMAP)',
            '443 (HTTPS)',
            'Wszystkie porty',
            'Własne'
        ])
        settings_layout.addRow('Porty:', port_selection_combo)

        custom_ports_input = QLineEdit()
        custom_ports_input.setPlaceholderText('np. 80,443,8080')
        custom_ports_input.setEnabled(False)
        settings_layout.addRow('Własne porty:', custom_ports_input)

        port_selection_combo.currentIndexChanged.connect(
            lambda idx: custom_ports_input.setEnabled(
                port_selection_combo.currentText() == 'Własne'
            )
        )

        btn_layout = QHBoxLayout()
        start_btn = QPushButton('Skanuj teraz')
        save_btn = QPushButton('Zapisz')
        export_btn = QPushButton('Eksport do SIEM')
        btn_layout.addWidget(start_btn)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(export_btn)
        settings_layout.addRow(btn_layout)

        instr_label = QLabel(
            'Zakres IP: podsieć np. 192.168.0.0/24; '
            'Discovery – wykrywa hosty; '
            'Port Scan – skanuje porty TCP; '
            'Service Detection – identyfikuje usługi; '
            'Port Mode – SYN/UDP/ICMP.'
        )
        instr_label.setWordWrap(True)
        settings_layout.addRow(instr_label)

        settings_group.setLayout(settings_layout)
        split_layout.addWidget(settings_group)

        # Results panel
        right_layout = QVBoxLayout()
        results_table = QTableWidget(0, 4)
        results_table.setHorizontalHeaderLabels(['IP', 'Porty', 'MAC', 'Producent'])
        results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        right_layout.addWidget(QLabel('Wyniki skanowania'))
        right_layout.addWidget(results_table)
        split_layout.addLayout(right_layout)

        main_layout.addLayout(split_layout)

        progress_bar = QProgressBar()
        progress_bar.setRange(0, 100)
        progress_bar.setValue(0)
        progress_bar.setFormat('%p %')
        progress_bar.setAlignment(Qt.AlignCenter)
        progress_bar.setStyleSheet('QProgressBar::chunk { background-color: #4caf50; }')
        main_layout.addWidget(progress_bar)

        cmd_log = create_cmd_log()
        main_layout.addWidget(cmd_log)

        return widget, {
            'target_input': target_input,
            'scan_type_combo': scan_type_combo,
            'port_mode_combo': port_mode_combo,
            'port_selection_combo': port_selection_combo,
            'custom_ports_input': custom_ports_input,
            'start_btn': start_btn,
            'save_btn': save_btn,
            'export_btn': export_btn,
            'results_table': results_table,
            'progress_bar': progress_bar,
            'cmd_log': cmd_log
        }
