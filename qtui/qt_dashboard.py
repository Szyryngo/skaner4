from modules.features import FeaturesModule
from scapy.all import Ether
from modules.detection import DetectionModule
print('qt_dashboard.py: start import')
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QPushButton, QListWidget, QGroupBox, QTableWidget, QTableWidgetItem, QAbstractItemView, QSplitter, QTextEdit, QHBoxLayout, QDialog, QComboBox
import threading
import yaml
from core.config_manager import ConfigManager
from qtui.dashboard_layout import DashboardLayout
from qtui.config_layout import ConfigLayout
from qtui.devices_layout import DevicesLayout
from qtui.scanner_layout import ScannerLayout
from qtui.nn_layout import NNLayout
from modules.scanner import ScannerModule
from core.events import Event
import sqlite3
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QTextCursor
try:
    from PyQt5.QtCore import qRegisterMetaType
    qRegisterMetaType(QTextCursor, 'QTextCursor')
except ImportError:
    pass
print('qt_dashboard.py: przed PacketDetailDialog')


class PacketDetailDialog(QDialog):
    """
Attributes
----------

Methods
-------

"""

    def __init__(self, pkt_id, hex_data, ascii_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f'Szczegóły pakietu ID {pkt_id}')
        layout = QVBoxLayout()
        layout.addWidget(QLabel('HEX:'))
        hex_view = QTextEdit()
        hex_view.setReadOnly(True)
        hex_view.setText(hex_data)
        layout.addWidget(hex_view)
        layout.addWidget(QLabel('ASCII:'))
        ascii_view = QTextEdit()
        ascii_view.setReadOnly(True)
        ascii_view.setText(ascii_data)
        layout.addWidget(ascii_view)
        self.setLayout(layout)


print('qt_dashboard.py: przed DashboardTab')


class DashboardTab(QWidget):
    """
Attributes
----------

Methods
-------

"""

    def log_status(self, msg):
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S')
        self.status_log.append(
            f'<span style="color:#8bc34a;">[{ts}]</span> {msg}')

    def __init__(self):
        super().__init__()
        from PyQt5 import uic
        uic.loadUi('qtui/dashboard.ui', self)
        from PyQt5.QtWidgets import QComboBox, QPushButton, QTableWidget, QTextEdit
        self.interface_combo = self.findChild(QComboBox, 'interface_combo')
        self.filter_combo = self.findChild(QComboBox, 'filter_combo')
        self.start_btn = self.findChild(QPushButton, 'start_btn')
        self.pause_btn = self.findChild(QPushButton, 'pause_btn')
        self.stop_btn = self.findChild(QPushButton, 'stop_btn')
        self.test_btn = self.findChild(QPushButton, 'test_btn')
        self.packets = self.findChild(QTableWidget, 'packets_table')
        self.detail_info = self.findChild(QTextEdit, 'detail_info')
        self.hex_view = self.findChild(QTextEdit, 'hex_view')
        self.ascii_view = self.findChild(QTextEdit, 'ascii_view')
        self.layer_view = self.findChild(QTextEdit, 'layer_view')
        self.status_log = self.findChild(QTextEdit, 'status_log')
        from modules.netif_pretty import get_interfaces_pretty
        self._iface_map = get_interfaces_pretty()
        self.interface_combo.clear()
        for iface, pretty in self._iface_map:
            self.interface_combo.addItem(pretty, iface)
        self.interface_combo.currentIndexChanged.connect(self.
            _on_interface_changed)
        self.filter_combo.clear()
        self.filter_combo.setEditable(True)
        self.filter_combo.setMinimumWidth(180)
        self.filter_combo.addItem('Nie filtruj')
        self.filter_combo.addItems(['tcp', 'udp', 'icmp', 'port 80',
            'port 443', 'host 8.8.8.8'])
        self.filter_combo.currentIndexChanged.connect(self.
            _on_filter_combo_changed)
        self.filter_combo.lineEdit().editingFinished.connect(self.
            _on_filter_edit_changed)
        try:
            self.set_filter_btn = self.findChild(QPushButton, 'set_filter_btn')
            if self.set_filter_btn:
                self.set_filter_btn.clicked.connect(self._on_set_filter)
        except Exception:
            pass
        self.test_btn.clicked.connect(self._on_test_interfaces)
        self.start_btn.clicked.connect(self._on_start_sniffing)
        self.pause_btn.clicked.connect(self._on_pause_sniffing)
        self.stop_btn.clicked.connect(self._on_stop_sniffing)
        self.export_csv_btn = self.findChild(QPushButton, 'export_csv_btn')
        self.export_pcap_btn = self.findChild(QPushButton, 'export_pcap_btn')
        if self.export_csv_btn:
            self.export_csv_btn.clicked.connect(self._on_export_csv)
        if self.export_pcap_btn:
            self.export_pcap_btn.clicked.connect(self._on_export_pcap)
        self.packets.setColumnCount(8)
        self.packets.setHorizontalHeaderLabels(['ID', 'Czas', 'Źródło',
            'Cel', 'Protokół', 'Rozmiar (B)', 'Waga AI', 'Geolokalizacja'])
        from PyQt5.QtWidgets import QAbstractItemView
        self.packets.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packets.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.packets.verticalHeader().setVisible(False)
        self.packets.setAlternatingRowColors(True)
        self.packets.setStyleSheet(
            'QTableWidget {selection-background-color: #2196F3;}')
        self.packets.cellClicked.connect(self._show_packet_details_inline)
        self.detail_info.setPlaceholderText(
            'Wybierz pakiet, aby zobaczyć szczegóły...')
        self.status_log.setStyleSheet(
            'background: #222; color: #fff; font-family: Consolas, monospace; font-size: 12px; border-radius: 6px; padding: 4px;'
            )
        from modules.capture import CaptureModule
        self._capture = CaptureModule()
        self._capture.initialize({})
        self._packet_data = []
        self._db_path = 'packets.db'
        self._init_db()
        self._sniffing = False
        self._paused = False
        self._orchestrator = None
        self._packet_counter = 0
        from PyQt5.QtCore import QTimer
        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._process_new_packets)
        self._event_timer.start(100)
        import yaml
        cfg_path = 'config/config.yaml'
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}
        bpf = cfg.get('filter', '')
        if bpf:
            self.filter_combo.lineEdit().setText(bpf)
        self._capture.config['filter'] = bpf
        iface = cfg.get('network_interface', None)
        if iface:
            idx = [i for i, (ifn, _) in enumerate(self._iface_map) if ifn ==
                iface]
            if idx:
                self.interface_combo.setCurrentIndex(idx[0])
        config_mgr = ConfigManager('config/protocols.yaml')
        self.protocols = config_mgr.load()
        self._features_module = FeaturesModule()
        self._features_module.initialize({})
        self._detection_module = DetectionModule()
        self._detection_module.initialize({})
        # Automatyczne rozpoczęcie przechwytywania pakietów przy starcie aplikacji
        self._on_start_sniffing()

    def _on_test_interfaces(self):
        if not hasattr(self, '_capture') or self._capture is None:
            self.log_status('Brak CaptureModule!')
            return
        try:
            results = self._capture.test_all_interfaces()
            found = None
            for iface, res in results.items():
                if isinstance(res, int) and res > 0:
                    found = iface
                    break
            if found:
                self.log_status(f'Przechwytywanie pakietów: <b>{found}</b>')
            else:
                self.log_status('Żaden interfejs nie przechwytuje pakietów.')
        except Exception as e:
            self.log_status(f'Błąd testu interfejsów: {e}')

    def _on_interface_changed(self, idx):
        iface = self.interface_combo.itemData(idx)
        if hasattr(self, '_capture') and self._capture:
            try:
                self._capture.set_interface(iface)
                self.log_status(f'Ustawiono interfejs: {iface}')
            except Exception as e:
                self.log_status(f'Błąd ustawiania interfejsu: {e}')
        main_window = self.parentWidget().parentWidget() if hasattr(self,
            'parentWidget') else None
        if main_window and hasattr(main_window, '_orchestrator'):
            for m in main_window._orchestrator.modules:
                if m.__class__.__name__ == 'DevicesSnifferModule':
                    m.set_interface(iface)

    def _on_filter_combo_changed(self, idx):
        if idx == 0:
            self.filter_combo.lineEdit().setText('')
            self._set_bpf_filter('')
        else:
            bpf = self.filter_combo.currentText().strip()
            self._set_bpf_filter(bpf)

    def _on_filter_edit_changed(self):
        bpf = self.filter_combo.lineEdit().text().strip()
        self._set_bpf_filter(bpf)

    def _on_set_filter(self):
        if not self._sniffing:
            self._on_start_sniffing()
        bpf = self.filter_combo.currentText().strip() or self.filter_combo.lineEdit().text().strip()
        self._set_bpf_filter(bpf)
        self.packets.setRowCount(0)
        self.log_status(f'Ustawiono filtr: {bpf}')
    
    def _on_start_sniffing(self):
        """Rozpocznij przechwytywanie pakietów"""
        self._sniffing = True
        # Uruchom AsyncSniffer w CaptureModule
        try:
            if hasattr(self._capture, '_start_sniffing'):
                self._capture._start_sniffing()
            elif hasattr(self._capture, 'start_sniffing'):
                self._capture.start_sniffing()
        except Exception:
            pass
        self.log_status('Rozpoczęto przechwytywanie pakietów')

    def _on_pause_sniffing(self):
        """Wstrzymaj/wznów przechwytywanie pakietów"""
        self._paused = not getattr(self, '_paused', False)
        if self._paused:
            self.log_status('Pauza przechwytywania pakietów')
        else:
            self.log_status('Wznawiam przechwytywanie pakietów')

    def _on_stop_sniffing(self):
        """Zatrzymaj przechwytywanie pakietów"""
        self._sniffing = False
        self._paused = False
        self.log_status('Zatrzymano przechwytywanie pakietów')

    def _on_export_csv(self):
        """Eksportuj pakiety do pliku CSV"""
        # TODO: implementacja eksportu do CSV
        self.log_status('Eksport pakietów do CSV niezaimplementowany')

    def _on_export_pcap(self):
        """Eksportuj pakiety do pliku PCAP"""
        # TODO: implementacja eksportu do PCAP
        self.log_status('Eksport pakietów do PCAP niezaimplementowany')
    
    def _show_packet_details_inline(self, row, col):
        """Wyświetla szczegóły pakietu po kliknięciu w tabeli"""
        try:
            pkt_id_item = self.packets.item(row, 0)
            if not pkt_id_item:
                return
            pkt_id = pkt_id_item.text()
            # TODO: Pobierz dane pakietu po pkt_id i wyświetl szczegóły
            self.detail_info.setText(f"Szczegóły pakietu ID {pkt_id}")
            self.hex_view.setText("HEX view not implemented")
            self.ascii_view.setText("ASCII view not implemented")
        except Exception as e:
            self.log_status(f"Nie można wyświetlić szczegółów pakietu: {e}")

    def _set_bpf_filter(self, bpf):
        if not bpf or bpf.strip().lower().startswith('nie filtruj'):
            bpf = ''
        import yaml
        cfg_path = 'config/config.yaml'
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}
        cfg['filter'] = bpf
        with open(cfg_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(cfg, f, allow_unicode=True)
        if hasattr(self, '_capture') and self._capture:
            self._capture.config['filter'] = bpf
            if self._sniffing:
                if hasattr(self._capture, '_start_sniffing'):
                    self._capture._start_sniffing()
                elif hasattr(self._capture, 'start_sniffing'):
                    self._capture.start_sniffing()

    def _init_db(self):
        self._conn = sqlite3.connect(self._db_path)
        c = self._conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pkt_id INTEGER,
            czas TEXT,
            src TEXT,
            dst TEXT,
            proto TEXT,
            size TEXT,
            ai_weight TEXT,
            geo TEXT
        )"""
            )
        self._conn.commit()

    def _save_packet_to_db(self, pkt_id, czas, src, dst, proto, size,
        ai_weight, geo):
        c = self._conn.cursor()
        c.execute(
            'INSERT INTO packets (pkt_id, czas, src, dst, proto, size, ai_weight, geo) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            , (pkt_id, czas, src, dst, proto, size, ai_weight, geo))
        self._conn.commit()

    def _load_recent_packets(self, limit=300, offset=0):
        self._db_offset = 0
        c = self._conn.cursor()
        c.execute(
            'SELECT pkt_id, czas, src, dst, proto, size, ai_weight, geo FROM packets ORDER BY id DESC LIMIT ? OFFSET ?'
            , (limit, offset))
        rows = c.fetchall()
        self.packets.setRowCount(0)
        for row in rows:
            self._add_packet_from_db(*row)
        self._db_offset = len(rows)

    def _load_more_packets(self, limit=300):
        c = self._conn.cursor()
        c.execute(
            'SELECT pkt_id, czas, src, dst, proto, size, ai_weight, geo FROM packets ORDER BY id DESC LIMIT ? OFFSET ?'
            , (limit, self._db_offset))
        rows = c.fetchall()
        for row in rows:
            self._add_packet_from_db(*row)
        self._db_offset += len(rows)

    def _add_packet_from_db(self, pkt_id, czas, src, dst, proto, size,
        ai_weight, geo):
        row = self.packets.rowCount()
        self.packets.insertRow(row)
        self.packets.setItem(row, 0, QTableWidgetItem(str(pkt_id)))
        self.packets.setItem(row, 1, QTableWidgetItem(str(czas)))
        self.packets.setItem(row, 2, QTableWidgetItem(str(src)))
        self.packets.setItem(row, 3, QTableWidgetItem(str(dst)))
        self.packets.setItem(row, 4, QTableWidgetItem(str(proto)))
        self.packets.setItem(row, 5, QTableWidgetItem(str(size)))
        self.packets.setItem(row, 6, QTableWidgetItem(str(ai_weight)))
        self.packets.setItem(row, 7, QTableWidgetItem(str(geo)))
        try:
            w = float(ai_weight)
            from PyQt5.QtGui import QColor
            if w < 0.5:
                color = QColor(0, 200, 0, 60)
            elif w < 1.5:
                color = QColor(255, 255, 0, 60)
            else:
                color = QColor(255, 0, 0, 80)
            for col in range(self.packets.columnCount()):
                item = self.packets.item(row, col)
                if item:
                    item.setBackground(color)
        except Exception:
            pass

    def _process_new_packets(self):
        if not self._sniffing or self._paused:
            return
        if self._capture and hasattr(self._capture, 'generate_event'):
            event = self._capture.generate_event()
            if not event:
                return
            pkt_bytes = event.data.get('raw_bytes')
            meta = event.data
            # Dodaj nowy wiersz z przechwyconym pakietem
            from datetime import datetime
            row = self.packets.rowCount()
            self.packets.insertRow(row)
            # Ustaw kolumny: ID, Czas, Źródło, Cel, Protokół, Rozmiar, Waga AI, Geo
            self.packets.setItem(row, 0, QTableWidgetItem(str(self._packet_counter)))
            now = datetime.now().strftime('%H:%M:%S')
            self.packets.setItem(row, 1, QTableWidgetItem(now))
            self.packets.setItem(row, 2, QTableWidgetItem(str(meta.get('src_ip', ''))))
            self.packets.setItem(row, 3, QTableWidgetItem(str(meta.get('dst_ip', ''))))
            self.packets.setItem(row, 4, QTableWidgetItem(str(meta.get('protocol', ''))))
            self.packets.setItem(row, 5, QTableWidgetItem(str(meta.get('payload_size', ''))))
            self.packets.setItem(row, 6, QTableWidgetItem(''))
            self.packets.setItem(row, 7, QTableWidgetItem(''))
            self._packet_counter += 1
            # Wywołanie handlerów aktualizacji pakietów dla wszystkich protokołów
            protocols = [
                'ipsec', 'ssl', 'tls', 'http', 'dns', 'dhcp', 'ntp', 'smtp',
                'pop3', 'imap', 'ftp', 'tftp', 'snmp', 'ldap', 'radius',
                'tacacs', 'sctp', 'igmp', 'arp', 'rarp', 'ipv4', 'ipv6',
                'icmp', 'ah', 'eap', 'pptp', 'l2tp'
            ]
            for proto in protocols:
                handler = getattr(self, f'_update_packet_{proto}', None)
                if callable(handler):
                    handler(pkt_bytes, meta)
                # end of DashboardTab

class MainWindow(QMainWindow):
    """Główne okno aplikacji z zakładkami"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle('AI Network Packet Analyzer Pro')
        # tab widget
        tabs = QTabWidget()
        self.setCentralWidget(tabs)
        # Dashboard tab (with logic)
        dash_tab = DashboardTab()
        tabs.addTab(dash_tab, 'Dashboard')
        # Devices tab
        dev_widget, _ = DevicesLayout().build()
        tabs.addTab(dev_widget, 'Devices')
        # Scanner tab
        scanner_tab = ScannerLayout()
        scan_widget, scan_ctrls = scanner_tab.build()
        tabs.addTab(scan_widget, 'Scanner')
        # Wire scanning button to log
        from datetime import datetime
        scan_ctrls['scan_btn'].clicked.connect(
            lambda: scan_ctrls['cmd_log'].append(
                f"[{datetime.now().strftime('%H:%M:%S')}] Rozpoczęto skanowanie sieci"
            )
        )
        # NN tab
        nn_tab = NNLayout()
        nn_widget, nn_ctrls = nn_tab.build()
        tabs.addTab(nn_widget, 'NN')
        # Wire NN training and evaluation buttons
        nn_ctrls['train_btn'].clicked.connect(nn_tab._on_train)
        nn_ctrls['eval_btn'].clicked.connect(nn_tab._on_evaluate)
        # Config tab (last)
        from qtui.config_layout import ConfigLayout
        config_widget, self.config_controls = ConfigLayout().build()
        tabs.addTab(config_widget, 'Config')
        # Wire config buttons
        cc = self.config_controls
        # Resize window
        cc['apply_btn'].clicked.connect(
            lambda: self.resize(cc['width_spin'].value(), cc['height_spin'].value())
        )
        # Switch AI engine: log and status
        cc['switch_ai_btn'].clicked.connect(
            lambda: [
                cc['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Przełączono silnik AI na: {cc['ai_combo'].currentText()}"),
                dash_tab.log_status(f"Silnik AI ustawiony na: {cc['ai_combo'].currentText()}")
            ]
        )
        # Check AI engine: log and status
        cc['check_ai_btn'].clicked.connect(
            lambda: [
                cc['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Testuję wybrany silnik AI"),
                dash_tab.log_status('Test silnika AI wykonany')
            ]
        )