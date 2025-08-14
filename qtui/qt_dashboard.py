from modules.features import FeaturesModule
from modules.detection import DetectionModule
print('qt_dashboard.py: start import')
import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QPushButton, QListWidget, QGroupBox,
    QTableWidget, QTableWidgetItem, QAbstractItemView, QSplitter, QTextEdit, QHBoxLayout, QDialog, QComboBox
)
import threading
import yaml
import sqlite3
from PyQt5.QtCore import Qt

print('qt_dashboard.py: przed PacketDetailDialog')
class PacketDetailDialog(QDialog):
    def __init__(self, pkt_id, hex_data, ascii_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Szczegóły pakietu ID {pkt_id}")
        layout = QVBoxLayout()
        layout.addWidget(QLabel("HEX:"))
        hex_view = QTextEdit()
        hex_view.setReadOnly(True)
        hex_view.setText(hex_data)
        layout.addWidget(hex_view)
        layout.addWidget(QLabel("ASCII:"))
        ascii_view = QTextEdit()
        ascii_view.setReadOnly(True)
        ascii_view.setText(ascii_data)
        layout.addWidget(ascii_view)
        self.setLayout(layout)

print('qt_dashboard.py: przed DashboardTab')
class DashboardTab(QWidget):
    def log_status(self, msg):
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S')
        self.status_log.append(f'<span style="color:#8bc34a;">[{ts}]</span> {msg}')
    # usunięto pustą, powieloną definicję __init__
    def __init__(self):
        super().__init__()
        from PyQt5 import uic
        uic.loadUi("qtui/dashboard.ui", self)
        # Przypisz referencje do widżetów z .ui
        from PyQt5.QtWidgets import QComboBox, QPushButton, QTableWidget, QTextEdit
        self.interface_combo = self.findChild(QComboBox, "interface_combo")
        self.filter_combo = self.findChild(QComboBox, "filter_combo")
        self.start_btn = self.findChild(QPushButton, "start_btn")
        self.pause_btn = self.findChild(QPushButton, "pause_btn")
        self.stop_btn = self.findChild(QPushButton, "stop_btn")
        self.test_btn = self.findChild(QPushButton, "test_btn")
        self.packets = self.findChild(QTableWidget, "packets_table")
        self.detail_info = self.findChild(QTextEdit, "detail_info")
        self.hex_view = self.findChild(QTextEdit, "hex_view")
        self.ascii_view = self.findChild(QTextEdit, "ascii_view")
        self.status_log = self.findChild(QTextEdit, "status_log")

        # Inicjalizacja pozostałych pól i logiki
        from modules.netif_pretty import get_interfaces_pretty
        self._iface_map = get_interfaces_pretty()
        self.interface_combo.clear()
        for iface, pretty in self._iface_map:
            self.interface_combo.addItem(pretty, iface)
        self.interface_combo.currentIndexChanged.connect(self._on_interface_changed)
        self.filter_combo.clear()
        self.filter_combo.setEditable(True)
        self.filter_combo.setMinimumWidth(180)
        self.filter_combo.addItem("Nie filtruj")
        self.filter_combo.addItems([
            "tcp", "udp", "icmp", "port 80", "port 443", "host 8.8.8.8"
        ])
        self.filter_combo.currentIndexChanged.connect(self._on_filter_combo_changed)
        self.filter_combo.lineEdit().editingFinished.connect(self._on_filter_edit_changed)
        self.test_btn.clicked.connect(self._on_test_interfaces)
        self.start_btn.clicked.connect(self._on_start_sniffing)
        self.pause_btn.clicked.connect(self._on_pause_sniffing)
        self.stop_btn.clicked.connect(self._on_stop_sniffing)
        self.packets.setColumnCount(8)
        self.packets.setHorizontalHeaderLabels([
            "ID", "Czas", "Źródło", "Cel", "Protokół", "Rozmiar (B)", "Waga AI", "Geolokalizacja"
        ])
        from PyQt5.QtWidgets import QAbstractItemView
        self.packets.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packets.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.packets.verticalHeader().setVisible(False)
        self.packets.setAlternatingRowColors(True)
        self.packets.setStyleSheet("QTableWidget {selection-background-color: #2196F3;}")
        self.packets.cellClicked.connect(self._show_packet_details_inline)
        self.detail_info.setPlaceholderText("Wybierz pakiet, aby zobaczyć szczegóły...")
        self.status_log.setStyleSheet("background: #222; color: #fff; font-family: Consolas, monospace; font-size: 12px; border-radius: 6px; padding: 4px;")

        self._capture = None
        self._packet_data = []
        self._db_path = "packets.db"
        self._init_db()
        self._sniffing = False
        self._orchestrator = None
        self._packet_counter = 0
        from PyQt5.QtCore import QTimer
        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._process_new_packets)
        self._event_timer.start(100)
        import yaml
        cfg_path = "config/config.yaml"
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
        except Exception:
            cfg = {}
        bpf = cfg.get('filter', '')
        if bpf:
            self.filter_combo.lineEdit().setText(bpf)
        # Wybierz interfejs z config.yaml jeśli istnieje
        iface = cfg.get('network_interface', None)
        if iface:
            idx = [i for i, (ifn, _) in enumerate(self._iface_map) if ifn == iface]
            if idx:
                self.interface_combo.setCurrentIndex(idx[0])
        self._sniffing = False
        self._orchestrator = None
        self._packet_counter = 0

        # Timer do cyklicznego pobierania pakietów
        from PyQt5.QtCore import QTimer
        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._process_new_packets)
        self._event_timer.start(100)

        # Wczytaj filtr z config.yaml jeśli istnieje
        import yaml
        cfg_path = "config/config.yaml"
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
        except Exception:
            cfg = {}
        bpf = cfg.get('filter', '')
        if bpf:
            self.filter_combo.lineEdit().setText(bpf)
        # Wybierz interfejs z config.yaml jeśli istnieje
        iface = cfg.get('network_interface', None)
        if iface:
            idx = [i for i, (ifn, _) in enumerate(self._iface_map) if ifn == iface]
            if idx:
                self.interface_combo.setCurrentIndex(idx[0])

    def _on_test_interfaces(self):
        if not hasattr(self, '_capture') or self._capture is None:
            self.log_status("Brak CaptureModule!")
            return
        try:
            results = self._capture.test_all_interfaces()
            found = None
            for iface, res in results.items():
                if isinstance(res, int) and res > 0:
                    found = iface
                    break
            if found:
                self.log_status(f"Przechwytywanie pakietów: <b>{found}</b>")
            else:
                self.log_status("Żaden interfejs nie przechwytuje pakietów.")
        except Exception as e:
            self.log_status(f"Błąd testu interfejsów: {e}")

    def _on_interface_changed(self, idx):
        iface = self.interface_combo.itemData(idx)
        if hasattr(self, '_capture') and self._capture:
            try:
                self._capture.set_interface(iface)
                self.log_status(f"Ustawiono interfejs: {iface}")
            except Exception as e:
                self.log_status(f"Błąd ustawiania interfejsu: {e}")
        self.pause_btn = QPushButton("Pauza")
        self.stop_btn = QPushButton("Stop")
        for btn, color, pressed in [
            (self.start_btn, '#4CAF50', '#087f23'),
            (self.pause_btn, '#FFC107', '#b28704'),
            (self.stop_btn, '#F44336', '#b71c1c')]:
            btn.setFixedWidth(100)
            btn.setStyleSheet(f"""
                QPushButton {{
                    font-weight: bold; background: {color}; color: white; border-radius: 8px; padding: 8px 0px; font-size: 14px;
                }}
                QPushButton:pressed {{
                    background: {pressed};
                    border: 2px inset {pressed};
                }}
            """)
        self.start_btn.clicked.connect(self._on_start_sniffing)
        self.pause_btn.clicked.connect(self._on_pause_sniffing)
        self.stop_btn.clicked.connect(self._on_stop_sniffing)

        # Inicjalizacja backendu/orchestratora
        self._sniffing = False
        self._orchestrator = None
        self._packet_counter = 0

        # Timer do cyklicznego pobierania pakietów
        from PyQt5.QtCore import QTimer
        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._process_new_packets)
        self._event_timer.start(100)


    def _init_db(self):
        self._conn = sqlite3.connect(self._db_path)
        c = self._conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pkt_id INTEGER,
            czas TEXT,
            src TEXT,
            dst TEXT,
            proto TEXT,
            size TEXT,
            ai_weight TEXT,
            geo TEXT
        )''')
        self._conn.commit()

    def _save_packet_to_db(self, pkt_id, czas, src, dst, proto, size, ai_weight, geo):
        c = self._conn.cursor()
        c.execute("INSERT INTO packets (pkt_id, czas, src, dst, proto, size, ai_weight, geo) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (pkt_id, czas, src, dst, proto, size, ai_weight, geo))
        self._conn.commit()

    def _load_recent_packets(self, limit=300, offset=0):
        self._db_offset = 0
        c = self._conn.cursor()
        c.execute("SELECT pkt_id, czas, src, dst, proto, size, ai_weight, geo FROM packets ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        rows = c.fetchall()
        self.packets.setRowCount(0)
        for row in rows:
            self._add_packet_from_db(*row)
        self._db_offset = len(rows)

    def _load_more_packets(self, limit=300):
        c = self._conn.cursor()
        c.execute("SELECT pkt_id, czas, src, dst, proto, size, ai_weight, geo FROM packets ORDER BY id DESC LIMIT ? OFFSET ?", (limit, self._db_offset))
        rows = c.fetchall()
        for row in rows:
            self._add_packet_from_db(*row)
        self._db_offset += len(rows)

    def _add_packet_from_db(self, pkt_id, czas, src, dst, proto, size, ai_weight, geo):
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
        # Kolorowanie jak dotychczas
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
        # Pobiera nowe pakiety z CaptureModule, analizuje AI i wyświetla w tabeli.
        if not self._sniffing:
            return
        if self._capture and hasattr(self._capture, 'generate_event'):
            event = self._capture.generate_event()
            if event and getattr(event, 'type', None) == "NEW_PACKET":
                pkt_bytes = event.data.get("raw_bytes")
                meta = dict(event.data)
                # AI analiza: przepuść przez FeaturesModule i DetectionModule
                features = FeaturesModule()
                features.initialize({})
                features.handle_event(event)
                features_event = features.generate_event()
                ai_weight = ''
                if features_event:
                    detection = DetectionModule()
                    detection.initialize({})
                    detection.handle_event(features_event)
                    threat_event = detection.generate_event()
                    if threat_event and 'ai_weight' in threat_event.data:
                        ai_weight = threat_event.data['ai_weight']
                meta['ai_weight'] = ai_weight
                self._packet_counter += 1
                self._add_packet(self._packet_counter, pkt_bytes, meta)

    def _add_packet(self, pkt_id, pkt_bytes, meta):
        from datetime import datetime
        from PyQt5.QtGui import QColor
        self._packet_data.append((pkt_id, pkt_bytes, meta))
        row = 0
        self.packets.insertRow(row)
        czas = datetime.now().strftime('%H:%M:%S')
        src = meta.get('src_ip', '')
        dst = meta.get('dst_ip', '')
        proto_num = meta.get('protocol', '')
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        try:
            proto = proto_map.get(int(proto_num), str(proto_num))
        except Exception:
            proto = str(proto_num)
        size = meta.get('payload_size', '')
        ai_weight = meta.get('ai_weight', '') if 'ai_weight' in meta else ''
        geo = "-"
        self.packets.setItem(row, 0, QTableWidgetItem(str(pkt_id)))
        self.packets.setItem(row, 1, QTableWidgetItem(str(czas)))
        self.packets.setItem(row, 2, QTableWidgetItem(str(src)))
        self.packets.setItem(row, 3, QTableWidgetItem(str(dst)))
        self.packets.setItem(row, 4, QTableWidgetItem(str(proto)))
        self.packets.setItem(row, 5, QTableWidgetItem(str(size)))
        self.packets.setItem(row, 6, QTableWidgetItem(str(ai_weight)))
        self.packets.setItem(row, 7, QTableWidgetItem(str(geo)))
        # Zapis do bazy
        self._save_packet_to_db(pkt_id, czas, src, dst, proto, size, ai_weight, geo)
        # Ogranicz liczbę wyświetlanych pakietów do 300 (reszta w bazie)
        if self.packets.rowCount() > 300:
            self.packets.removeRow(self.packets.rowCount() - 1)
            if len(self._packet_data) > 300:
                self._packet_data.pop()
        # Kolorowanie jak dotychczas
        try:
            w = float(ai_weight)
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
    def _on_filter_combo_changed(self, idx):
        # Jeśli wybrano "Nie filtruj", ustaw pusty filtr
        if idx == 0:
            self.filter_combo.lineEdit().setText("")
            self._set_bpf_filter("")
        else:
            bpf = self.filter_combo.currentText().strip()
            self._set_bpf_filter(bpf)

    def _on_filter_edit_changed(self):
        bpf = self.filter_combo.lineEdit().text().strip()
        self._set_bpf_filter(bpf)

    def _set_bpf_filter(self, bpf):
        # Jeśli pole jest puste lub "Nie filtruj", przekazuj pusty filtr
        if not bpf or bpf.strip().lower().startswith("nie filtruj"):
            bpf = ""
        # Zapisz do config.yaml i restart sniffingu
        import yaml
        cfg_path = "config/config.yaml"
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
        except Exception:
            cfg = {}
        cfg['filter'] = bpf
        with open(cfg_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(cfg, f, allow_unicode=True)
        # Restart sniffingu jeśli jest uruchomiony
        if hasattr(self, '_capture') and self._capture:
            self._capture.config['filter'] = bpf
            if self._sniffing:
                self._capture._start_sniffing()
    # Po kliknięciu wiersza w tabeli pokaż szczegóły pakietu
    def _show_packet_details_inline(self, row, col):
        idx = row
        if 0 <= idx < len(self._packet_data):
            pkt_id, pkt_bytes, meta = self._packet_data[idx]
            # Szczegóły tekstowe
            details = []
            for k, v in meta.items():
                details.append(f"{k}: {v}")
            self.detail_info.setText("\n".join(details))
            # HEX i ASCII
            self.hex_view.setText(self._format_hex(pkt_bytes))
            self.ascii_view.setText(self._format_ascii(pkt_bytes))

    def _format_hex(self, pkt_bytes):
        # HEX dump (16 bajtów na linię)
        lines = []
        for i in range(0, len(pkt_bytes), 16):
            chunk = pkt_bytes[i:i+16]
            hexstr = ' '.join(f"{b:02X}" for b in chunk)
            lines.append(hexstr)
        return '\n'.join(lines)

    def _format_ascii(self, pkt_bytes):
        # ASCII dump (nieczytelne znaki jako .)
        lines = []
        for i in range(0, len(pkt_bytes), 16):
            chunk = pkt_bytes[i:i+16]
            asciistr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(asciistr)
        return '\n'.join(lines)

    def _on_start_sniffing(self):
        self._sniffing = True
        self.log_status("Sniffing uruchomiony.")

    def _on_pause_sniffing(self):
        if self._sniffing:
            self._sniffing = False
            self.log_status("Sniffing wstrzymany.")

    def _on_stop_sniffing(self):
        if self._sniffing:
            self._sniffing = False
            self.log_status("Sniffing zatrzymany.")

    # ...existing code...

    # _packet_desc niepotrzebny

    # _short_packet niepotrzebny


    # ...existing code...

    # ...existing code...

print('qt_dashboard.py: przed DevicesTab')
class DevicesTab(QWidget):
    def __init__(self):
        super().__init__()
        from PyQt5 import uic
        from PyQt5.QtWidgets import QTableWidget
        uic.loadUi("qtui/devices.ui", self)
        self.devices = self.findChild(QTableWidget, "devices")
        self._device_data = []

    def update_device(self, device_info):
        # device_info: dict z polami ip, mac, last_seen, packets, status
        # Szukaj po IP, aktualizuj lub dodaj na początek
        ip = device_info.get('ip', '-')
        idx = next((i for i, d in enumerate(self._device_data) if d.get('ip') == ip), None)
        if idx is not None:
            self._device_data.pop(idx)
            self.devices.removeRow(idx)
        self._device_data.insert(0, device_info)
        self.devices.insertRow(0)
        row = [
            device_info.get('ip', '-'),
            device_info.get('mac', '-'),
            device_info.get('last_seen', '-'),
            str(device_info.get('packets', '-')),
            device_info.get('status', '-')
        ]
        for col, val in enumerate(row):
            item = QTableWidgetItem(val)
            self.devices.setItem(0, col, item)
        # Kolorowanie statusu
        color = None
        status = device_info.get('status', 'online')
        if status == 'threat':
            color = '#FFCDD2'
        elif status == 'suspicious':
            color = '#FFF9C4'
        elif status == 'online':
            color = '#C8E6C9'
        if color:
            for col in range(self.devices.columnCount()):
                self.devices.item(0, col).setBackgroundColor(color)
        # Ogranicz do 500 urządzeń
        if self.devices.rowCount() > 500:
            self.devices.removeRow(self.devices.rowCount()-1)
            self._device_data = self._device_data[:500]

print('qt_dashboard.py: przed ScannerTab')
class ScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        from PyQt5 import uic
        from PyQt5.QtWidgets import QPushButton, QListWidget
        uic.loadUi("qtui/scanner.ui", self)
        self.scan_btn = self.findChild(QPushButton, "scan_btn")
        self.results = self.findChild(QListWidget, "results")


from PyQt5.QtWidgets import QHBoxLayout, QLineEdit, QMessageBox, QComboBox, QFormLayout


print('qt_dashboard.py: przed ConfigTab')
class ConfigTab(QWidget):
    def __init__(self, main_window=None):
        super().__init__()
        from PyQt5 import uic
        from PyQt5.QtWidgets import QComboBox, QLineEdit, QPushButton
        uic.loadUi("qtui/config.ui", self)
        self.main_window = main_window
        self.preset_combo = self.findChild(QComboBox, "preset_combo")
        self.width_input = self.findChild(QLineEdit, "width_input")
        self.height_input = self.findChild(QLineEdit, "height_input")
        self.apply_btn = self.findChild(QPushButton, "apply_btn")
        self._load_window_size()
        self.apply_btn.clicked.connect(self._apply_window_size)
        self.preset_combo.currentIndexChanged.connect(self._preset_selected)

    def _preset_selected(self, idx):
        w, h = self.preset_combo.currentData()
        self.width_input.setText(str(w))
        self.height_input.setText(str(h))

    def _load_window_size(self):
        try:
            with open('config/config.yaml', 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
            width = cfg.get('window_width', '')
            height = cfg.get('window_height', '')
            self.width_input.setText(str(width))
            self.height_input.setText(str(height))
        except Exception:
            self.width_input.setText('')
            self.height_input.setText('')

    def _apply_window_size(self):
        try:
            width = int(self.width_input.text())
            height = int(self.height_input.text())
            if width < 400 or height < 300:
                raise ValueError("Minimalny rozmiar to 400x300")
            with open('config/config.yaml', 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
            cfg['window_width'] = width
            cfg['window_height'] = height
            with open('config/config.yaml', 'w', encoding='utf-8') as f:
                yaml.safe_dump(cfg, f, allow_unicode=True)
            if self.main_window:
                self.main_window.resize(width, height)
            QMessageBox.information(self, "Sukces", f"Nowy rozmiar okna: {width}x{height}")
        except Exception as e:
            QMessageBox.warning(self, "Błąd", f"Nieprawidłowe dane: {e}")



import threading
import queue
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QScreen



print('qt_dashboard.py: przed MainWindow')
class MainWindow(QMainWindow):
    def _set_initial_window_size(self):
        # Ustaw rozmiar okna na podstawie config.yaml lub domyślnie na 1200x800
        import os
        import yaml
        cfg_path = os.path.join("config", "config.yaml")
        width, height = 1200, 800
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
            w = cfg.get('window_width')
            h = cfg.get('window_height')
            if isinstance(w, int) and isinstance(h, int):
                width, height = w, h
        except Exception:
            pass
        self.resize(width, height)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Network Packet Analyzer Pro")
        self.tabs = QTabWidget()
        from core.orchestrator import Orchestrator
        orchestrator = Orchestrator()
        orchestrator.initialize()
        capture = None
        for m in orchestrator.modules:
            if m.__class__.__name__ == "CaptureModule":
                capture = m
                break
        self.dashboard = DashboardTab()
        self.dashboard._capture = capture
        self.devices = DevicesTab()
        self.scanner = ScannerTab()
        self.config = ConfigTab(main_window=self)
        self.tabs.addTab(self.dashboard, "Dashboard")
        self.tabs.addTab(self.devices, "Live Devices")
        self.tabs.addTab(self.scanner, "Network Scanner")
        self.tabs.addTab(self.config, "Configuration")
        self.setCentralWidget(self.tabs)

        # Skalowanie okna do rozdzielczości ekranu lub config.yaml
        self._set_initial_window_size()
        self.setMinimumSize(800, 600)  # Minimalny rozmiar
        self.setWindowFlag(Qt.Window)
        self.setWindowState(Qt.WindowActive)

    def initialize_orchestrator(self):
        self._selected_iface = self.dashboard.iface_combo.currentText()
        self._event_queue = queue.Queue()
        self._orchestrator_thread = threading.Thread(target=self._run_orchestrator, daemon=True)
        self._orchestrator_thread.start()
        # Timer do odbioru eventów z kolejki co 100ms
        self._event_timer = QTimer()
        self._event_timer.timeout.connect(self._process_events)
        self._event_timer.start(100)
        # Stan sniffingu
        self._sniffing = False
        self._paused = False
        self._packet_counter = 0

    def _run_orchestrator(self):
        # Import lokalny, by nie blokować GUI
        from core.orchestrator import Orchestrator
        orchestrator = Orchestrator()
        orchestrator.initialize()
        # Znajdź CaptureModule
        self._capture = None
        for m in orchestrator.modules:
            if m.__class__.__name__ == "CaptureModule":
                self._capture = m
                break
        # Ustaw interfejs na start
        if self._capture:
            self._capture.set_interface(self._selected_iface)
        # Przechwytuj pakiety tylko gdy _sniffing==True
        while True:
            if self._sniffing and not self._paused and self._capture:
                event = self._capture.generate_event()
                if event and event.type == "NEW_PACKET":
                    self._event_queue.put(event)
            import time
        self.initialize_orchestrator()
        self._ai_weights = getattr(self, '_ai_weights', {})
        while not self._event_queue.empty():
            event = self._event_queue.get()
            if event.type == "NEW_PACKET":
                pkt_bytes = event.data.get("raw_bytes")
                if pkt_bytes:
                    src_ip = event.data.get('src_ip', '-')
                    # Zawsze wyświetl ostatnią znaną wagę AI dla src_ip (nie usuwaj z dict)
                    ai_weight = self._ai_weights.get(src_ip, '-')
                    meta = dict(event.data)
                    meta['ai_weight'] = ai_weight
                    self._packet_counter += 1
                    self.dashboard.add_packet(self._packet_counter, pkt_bytes, meta)
            elif event.type == "NEW_THREAT":
                # Zapisz wagę AI dla danego src_ip
                src_ip = event.data.get('ip', '-')
                ai_weight = event.data.get('ai_weight', '-')
                self._ai_weights[src_ip] = ai_weight
            elif event.type == "DEVICE_DETECTED":
                # Przekaż dane do DevicesTab
                ip = event.data.get('ip', '-')
                # Uzupełnij o inne dane jeśli są dostępne
                device_info = {
                    'ip': ip,
                    'mac': event.data.get('mac', '-'),
                    'last_seen': event.data.get('last_seen', '-'),
                    'packets': event.data.get('packets', 1),
                    'status': event.data.get('status', 'online'),
                }
                self.devices.update_device(device_info)

    def _start_sniffing(self):
        self._sniffing = True
        self._paused = False
        # Ustaw interfejs na aktualnie wybrany
        if hasattr(self, '_capture') and self._capture:
            self._capture.set_interface(self._selected_iface)

    def _pause_sniffing(self):
        if self._sniffing:
            self._paused = not self._paused


