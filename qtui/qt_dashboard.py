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
# Import layout classes for dynamic tabs
from qtui.dashboard_layout import DashboardLayout
from qtui.config_layout import ConfigLayout
from qtui.devices_layout import DevicesLayout
from qtui.scanner_layout import ScannerLayout
from modules.scanner import ScannerModule
from core.events import Event
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
        # Add 'Ustaw filtr' button
        try:
            self.set_filter_btn = self.findChild(QPushButton, "set_filter_btn")
            if self.set_filter_btn:
                self.set_filter_btn.clicked.connect(self._on_set_filter)
        except Exception:
            pass
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

        # Inicjalizacja CaptureModule
        from modules.capture import CaptureModule
        self._capture = CaptureModule()
        self._capture.initialize({})

        # Initialize local storage and DB
        self._packet_data = []
        self._db_path = "packets.db"
        self._init_db()
        self._sniffing = False
        self._orchestrator = None
        self._packet_counter = 0
        # Timer for new packet processing
        from PyQt5.QtCore import QTimer
        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._process_new_packets)
        self._event_timer.start(100)
        # Load settings from config
        import yaml
        cfg_path = "config/config.yaml"
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}
        bpf = cfg.get('filter', '')
        if bpf:
            self.filter_combo.lineEdit().setText(bpf)
        # Apply filter in CaptureModule
        self._capture.set_filter(bpf)
        # Select saved interface
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
        # Przekaż zmianę interfejsu do DevicesSnifferModule przez orchestrator
        main_window = self.parentWidget().parentWidget() if hasattr(self, 'parentWidget') else None
        if main_window and hasattr(main_window, '_orchestrator'):
            for m in main_window._orchestrator.modules:
                if m.__class__.__name__ == 'DevicesSnifferModule':
                    m.set_interface(iface)


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
        # DODATKOWA BLOKADA: nie przetwarzaj jeśli _sniffing==False
        if not self._sniffing or self._paused:
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
    
    def _on_set_filter(self):
        # Ensure sniffing is active before applying filter
        if not self._sniffing:
            self._on_start_sniffing()
        # Apply new filter
        bpf = self.filter_combo.currentText().strip() or self.filter_combo.lineEdit().text().strip()
        self._set_bpf_filter(bpf)
        # Clear table so only new packets matching filter appear
        self.packets.setRowCount(0)
        # Log status
        self.log_status(f"Ustawiono filtr: {bpf}")

    def _set_bpf_filter(self, bpf):
        # Jeśli pole jest puste lub "Nie filtruj", przekazuj pusty filtr
        if not bpf or bpf.strip().lower().startswith("nie filtruj"):
            bpf = ""
        # Zapisz do config.yaml i restart sniffingu
        import yaml
        cfg_path = "config/config.yaml"
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
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
        self._paused = False
        # Przekaż do CaptureModule
        if self._capture:
            # Preferowane: jawne metody start/stop/pause
            if hasattr(self._capture, "start_sniffing"):
                self._capture.start_sniffing()
            elif hasattr(self._capture, "_start_sniffing"):
                self._capture._start_sniffing()
            # Jeśli CaptureModule ma własny wątek, ustaw flagę/wznów
            if hasattr(self._capture, "paused"):
                self._capture.paused = False
            if hasattr(self._capture, "stopped"):
                self._capture.stopped = False
        self.log_status("Sniffing uruchomiony.")

    def _on_pause_sniffing(self):
        if self._sniffing:
            self._sniffing = False
            self._paused = True
            if self._capture:
                if hasattr(self._capture, "pause_sniffing"):
                    self._capture.pause_sniffing()
                elif hasattr(self._capture, "_pause_sniffing"):
                    self._capture._pause_sniffing()
                elif hasattr(self._capture, "stop_sniffing"):
                    self._capture.stop_sniffing()
                elif hasattr(self._capture, "_stop_sniffing"):
                    self._capture._stop_sniffing()
                if hasattr(self._capture, "paused"):
                    self._capture.paused = True
            self.log_status("Sniffing wstrzymany.")

    def _on_stop_sniffing(self):
        if self._sniffing or self._paused:
            self._sniffing = False
            self._paused = False
            if self._capture:
                if hasattr(self._capture, "stop_sniffing"):
                    self._capture.stop_sniffing()
                elif hasattr(self._capture, "_stop_sniffing"):
                    self._capture._stop_sniffing()
                if hasattr(self._capture, "stopped"):
                    self._capture.stopped = True
                if hasattr(self._capture, "paused"):
                    self._capture.paused = False
            self.log_status("Sniffing zatrzymany.")


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Dashboard")

        tab_widget = QTabWidget(self)
        self.setCentralWidget(tab_widget)

        # Dynamiczne ładowanie zakładek z config/ui_tabs.yaml
        try:
            with open('config/ui_tabs.yaml', 'r', encoding='utf-8') as f:
                tabs_cfg = yaml.safe_load(f).get('tabs', [])
        except Exception:
            tabs_cfg = []
        for tab in tabs_cfg:
            TabClass = globals().get(tab.get('class'))
            if TabClass is None:
                print(f"Brak klasy zakładki: {tab.get('class')}")
                continue
            # Jeśli klasa ma metodę build(), użyj jej do utworzenia widgetu i pobierz kontrolki
            if hasattr(TabClass, 'build'):
                widget, controls = TabClass().build()
            else:
                widget = TabClass()
                controls = {}
            index = tab_widget.addTab(widget, tab.get('label', tab.get('class')))
            # Konfiguracja funkcjonalności
            if tab.get('class') == 'ConfigLayout' and controls:
                apply_btn = controls.get('apply_btn')
                wi = controls.get('width_input')
                hi = controls.get('height_input')
                if apply_btn and wi and hi:
                    apply_btn.clicked.connect(lambda _, wi=wi, hi=hi: self._apply_window_size(wi, hi))
            elif tab.get('class') == 'ScannerLayout' and controls:
                scan_btn = controls.get('scan_btn')
                results = controls.get('results')
                if scan_btn and results:
                    scan_btn.clicked.connect(lambda _, r=results: self._run_scan(r))
            elif tab.get('class') == 'DevicesLayout' and controls:
                devices_table = controls.get('devices')
                if devices_table:
                    self._devices_table = devices_table
                    self._devices_map = {}
                    # tracking last seen timestamps for inactivity
                    self._devices_last_seen = {}
                    self._device_timeout = 300  # seconds until considered inactive

                    # Import sniffer and supporting modules
                    from modules.devices_sniffer import DevicesSniffer
                    from datetime import datetime
                    from PyQt5.QtWidgets import QTableWidgetItem
                    import time

                    # Callback for detected devices
                    def on_device(event):
                        data = event.data
                        ip = data.get('ip')
                        mac = data.get('mac', '')
                        proto = data.get('proto', '')
                        ts = datetime.now().strftime('%H:%M:%S')
                        # Filter private LAN IPs only
                        try:
                            import ipaddress
                            if not ipaddress.ip_address(ip).is_private:
                                return
                        except Exception:
                            pass
                        now_ts = time.time()
                        # update last seen timestamp
                        self._devices_last_seen[ip] = now_ts
                        if ip not in self._devices_map:
                            row = self._devices_table.rowCount()
                            self._devices_table.insertRow(row)
                            self._devices_map[ip] = row
                            self._devices_table.setItem(row, 0, QTableWidgetItem(ip))
                            self._devices_table.setItem(row, 1, QTableWidgetItem(mac))
                            self._devices_table.setItem(row, 2, QTableWidgetItem(ts))
                            self._devices_table.setItem(row, 3, QTableWidgetItem('1'))
                            # set status to online
                            self._devices_table.setItem(row, 4, QTableWidgetItem('online'))
                        else:
                            row = self._devices_map[ip]
                            self._devices_table.item(row, 2).setText(ts)
                            cnt_item = self._devices_table.item(row, 3)
                            try:
                                cnt = int(cnt_item.text()) + 1
                            except:
                                cnt = 1
                            cnt_item.setText(str(cnt))

                    # Initialize and connect sniffer
                    self._device_sniffer = DevicesSniffer(iface=None, event_callback=on_device)
        # Po dodaniu wszystkich zakładek: uruchamiaj sniffing tylko na Devices tab
        try:
            # znajdź indeks zakładki Devices
            devices_idx = next(i for i in range(tab_widget.count()) if tab_widget.tabText(i) == 'Devices')
        except StopIteration:
            devices_idx = None
        if devices_idx is not None and hasattr(self, '_device_sniffer'):
            # po zmianie zakładki start/stop sniffer
            tab_widget.currentChanged.connect(
                lambda idx: self._device_sniffer.start() if idx == devices_idx else self._device_sniffer.stop()
            )
            self._device_sniffer.start()
            # timer to clean up inactive devices
            from PyQt5.QtCore import QTimer
            self._device_cleanup_timer = QTimer(self)
            self._device_cleanup_timer.timeout.connect(self._cleanup_devices)
            self._device_cleanup_timer.start(5000)
    def _apply_window_size(self, width_input, height_input):
        """Zastosuj nowe wymiary okna z zakładki konfiguracji"""
        try:
            w = int(width_input.text())
            h = int(height_input.text())
            self.resize(w, h)
            # Zapisz do config.yaml
            cfg_path = 'config/config.yaml'
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
            cfg['window_width'] = w
            cfg['window_height'] = h
            with open(cfg_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(cfg, f, allow_unicode=True)
            self.log_status(f"Zmieniono rozmiar okna na {w}x{h}")
        except Exception as e:
            print(f"Błąd przy zmianie rozmiaru okna: {e}")
    def _run_scan(self, results_widget):
        """Uruchom skanowanie sieci i wyświetl wyniki"""
        try:
            module = ScannerModule()
            module.initialize({})
            module.handle_event(Event('SCAN_REQUEST', {}))
            ev = module.generate_event()
            if ev and hasattr(ev, 'data'):
                found = ev.data.get('result', [])
                results_widget.clear()
                for item in found if isinstance(found, list) else []:
                    results_widget.addItem(str(item))
                self.log_status('Skanowanie ukończone.')
            else:
                self.log_status('Brak wyników skanowania.')
        except Exception as e:
            print(f"Błąd podczas skanowania: {e}")
    def _cleanup_devices(self):
        """
        Oznacza hosty przekraczające timeout jako offline w tabeli Devices.
        """
        import time
        from PyQt5.QtWidgets import QTableWidgetItem
        now_ts = time.time()
        # Iteruj po kopii, bo modyfikujemy oryginał
        for ip, last in list(self._devices_last_seen.items()):
            if now_ts - last > self._device_timeout:
                row = self._devices_map.get(ip)
                if row is not None:
                    # ustaw status na offline
                    self._devices_table.setItem(row, 4, QTableWidgetItem('offline'))

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
        self._paused = False
        # Przekaż do CaptureModule
        if self._capture:
            # Preferowane: jawne metody start/stop/pause
            if hasattr(self._capture, "start_sniffing"):
                self._capture.start_sniffing()
            elif hasattr(self._capture, "_start_sniffing"):
                self._capture._start_sniffing()
            # Jeśli CaptureModule ma własny wątek, ustaw flagę/wznów
            if hasattr(self._capture, "paused"):
                self._capture.paused = False
            if hasattr(self._capture, "stopped"):
                self._capture.stopped = False
        self.log_status("Sniffing uruchomiony.")

    def _on_pause_sniffing(self):
        if self._sniffing:
            self._sniffing = False
            self._paused = True
            if self._capture:
                if hasattr(self._capture, "pause_sniffing"):
                    self._capture.pause_sniffing()
                elif hasattr(self._capture, "_pause_sniffing"):
                    self._capture._pause_sniffing()
                elif hasattr(self._capture, "stop_sniffing"):
                    self._capture.stop_sniffing()
                elif hasattr(self._capture, "_stop_sniffing"):
                    self._capture._stop_sniffing()
                if hasattr(self._capture, "paused"):
                    self._capture.paused = True
            self.log_status("Sniffing wstrzymany.")

    def _on_stop_sniffing(self):
        if self._sniffing or self._paused:
            self._sniffing = False
            self._paused = False
            if self._capture:
                if hasattr(self._capture, "stop_sniffing"):
                    self._capture.stop_sniffing()
                elif hasattr(self._capture, "_stop_sniffing"):
                    self._capture._stop_sniffing()
                if hasattr(self._capture, "stopped"):
                    self._capture.stopped = True
                if hasattr(self._capture, "paused"):
                    self._capture.paused = False
            self.log_status("Sniffing zatrzymany.")
