from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QPushButton, QTextEdit, QTableWidget, QLabel, QSplitter, QGroupBox


class DashboardLayout:
    """
Attributes
----------

Methods
-------

"""

    def build(self):
        widget = QWidget()
        main_layout = QVBoxLayout()
        top_row = QHBoxLayout()
        interface_combo = QComboBox()
        interface_combo.setMinimumWidth(220)
        interface_combo.setEditable(False)
        top_row.addWidget(QLabel('Interfejs:'))
        top_row.addWidget(interface_combo)
        filter_combo = QComboBox()
        filter_combo.setEditable(True)
        filter_combo.setMinimumWidth(220)
        top_row.addWidget(QLabel('Filtr BPF:'))
        top_row.addWidget(filter_combo)
        start_btn = QPushButton('Start')
        pause_btn = QPushButton('Pauza')
        stop_btn = QPushButton('Stop')
        test_btn = QPushButton('Testuj interfejs')
        top_row.addWidget(start_btn)
        top_row.addWidget(pause_btn)
        top_row.addWidget(stop_btn)
        top_row.addWidget(test_btn)
        main_layout.addLayout(top_row)
        splitter = QSplitter()
        pkt_group = QGroupBox('Przechwycone pakiety')
        pkt_group_layout = QVBoxLayout()
        packets_table = QTableWidget()
        pkt_group_layout.addWidget(packets_table)
        pkt_group.setLayout(pkt_group_layout)
        splitter.addWidget(pkt_group)
        details_widget = QWidget()
        details_layout = QVBoxLayout()
        details_layout.addWidget(QLabel('Szczegóły pakietu:'))
        detail_info = QTextEdit()
        detail_info.setReadOnly(True)
        details_layout.addWidget(detail_info)
        details_layout.addWidget(QLabel('HEX:'))
        hex_view = QTextEdit()
        hex_view.setReadOnly(True)
        hex_view.setMaximumHeight(100)
        details_layout.addWidget(hex_view)
        details_layout.addWidget(QLabel('ASCII:'))
        ascii_view = QTextEdit()
        ascii_view.setReadOnly(True)
        ascii_view.setMaximumHeight(100)
        details_layout.addWidget(ascii_view)
        details_widget.setLayout(details_layout)
        splitter.addWidget(details_widget)
        splitter.setSizes([700, 300])
        main_layout.addWidget(splitter, stretch=1)
        status_log = QTextEdit()
        status_log.setReadOnly(True)
        status_log.setMaximumHeight(60)
        main_layout.addWidget(status_log)
        widget.setLayout(main_layout)
        return widget, {'interface_combo': interface_combo, 'filter_combo':
            filter_combo, 'start_btn': start_btn, 'pause_btn': pause_btn,
            'stop_btn': stop_btn, 'test_btn': test_btn, 'packets_table':
            packets_table, 'detail_info': detail_info, 'hex_view': hex_view,
            'ascii_view': ascii_view, 'status_log': status_log}
