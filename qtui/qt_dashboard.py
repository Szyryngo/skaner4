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
        # Dodaje pakiet do tabeli i do self._packet_data, koloruje według ai_weight
        from datetime import datetime
        from PyQt5.QtGui import QColor
        self._packet_data.append((pkt_id, pkt_bytes, meta))
        row = 0
        self.packets.insertRow(row)
        # Kolumny: ID, Czas, Źródło, Cel, Protokół, Rozmiar (B), Waga AI
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
        self.packets.setItem(row, 0, QTableWidgetItem(str(pkt_id)))
        self.packets.setItem(row, 1, QTableWidgetItem(str(czas)))
        self.packets.setItem(row, 2, QTableWidgetItem(str(src)))
        self.packets.setItem(row, 3, QTableWidgetItem(str(dst)))
        self.packets.setItem(row, 4, QTableWidgetItem(str(proto)))
        self.packets.setItem(row, 5, QTableWidgetItem(str(size)))
        self.packets.setItem(row, 6, QTableWidgetItem(str(ai_weight)))
        # Kolorowanie wiersza według ai_weight
        try:
            w = float(ai_weight)
            if w < 0.5:
                color = QColor(0, 200, 0, 60)  # zielony
            elif w < 1.5:
                color = QColor(255, 255, 0, 60)  # żółty
            else:
                color = QColor(255, 0, 0, 80)  # czerwony
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
            # HEX

    def __init__(self):
        super().__init__()
        self._capture = None

        main_layout = QVBoxLayout()
        title = QLabel("AI Network Packet Analyzer Pro - Dashboard")
        title.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 10px;")
        main_layout.addWidget(title)
        main_layout.addSpacing(10)

        # Wiersz: wybór interfejsu
        from modules.netif_pretty import get_interfaces_pretty
        iface_row = QHBoxLayout()
        iface_label = QLabel("Interfejs:")
        self.iface_combo = QComboBox()
        self._iface_map = {}
        for name, pretty in get_interfaces_pretty():
            self.iface_combo.addItem(pretty)
            self._iface_map[pretty] = name
        iface_row.addWidget(iface_label)
        iface_row.addWidget(self.iface_combo)
        iface_row.addStretch()
        main_layout.addLayout(iface_row)

        # Wiersz: testowanie, wybór interfejsu i filtrów
        test_row = QHBoxLayout()
        self.test_ifaces_btn = QPushButton("Testuj interfejsy")
        self.test_ifaces_btn.setStyleSheet("""
            QPushButton {
                background: #1976D2; color: white; font-weight: bold; border-radius: 6px; padding: 6px 8px;
            }
            QPushButton:pressed {
                background: #0D47A1;
                border: 2px inset #0D47A1;
            }
        """)
        self.test_ifaces_btn.clicked.connect(self._test_interfaces)
        test_row.addWidget(self.test_ifaces_btn)

        self.use_iface_btn = QPushButton("Użyj wybrany interfejs")
        self.use_iface_btn.setStyleSheet("""
            QPushButton {
                background: #388E3C; color: white; font-weight: bold; border-radius: 6px; padding: 6px 8px;
            }
            QPushButton:pressed {
                background: #1B5E20;
                border: 2px inset #1B5E20;
            }
        """)
        self.use_iface_btn.clicked.connect(self._use_selected_interface)
        test_row.addWidget(self.use_iface_btn)

        # --- FILTR BPF ---
        self.filter_combo = QComboBox()
        self.filter_combo.setEditable(True)
        self.filter_combo.setInsertPolicy(QComboBox.NoInsert)
        self.filter_combo.setPlaceholderText("np. tcp, udp, port 80, host 192.168.1.1")
        # Przykładowe filtry
        self.filter_combo.addItem("Nie filtruj (wszystkie pakiety)") # pusty filtr
        self.filter_combo.addItem("tcp")
        self.filter_combo.addItem("udp")
        self.filter_combo.addItem("port 80")
        self.filter_combo.addItem("host 192.168.1.1")
        self.filter_combo.addItem("icmp")
        self.filter_combo.addItem("tcp port 443")
        self.filter_combo.addItem("udp port 53")
        self.filter_combo.setCurrentIndex(0)
        test_row.addWidget(QLabel("Filtr (BPF):"))
        test_row.addWidget(self.filter_combo)
        self.filter_combo.lineEdit().editingFinished.connect(self._on_filter_edit_changed)
        self.filter_combo.currentIndexChanged.connect(self._on_filter_combo_changed)
        test_row.addStretch()
        main_layout.addLayout(test_row)

        # Wiersz: przyciski sniffingu
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("Start")
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
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.pause_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addStretch()
        main_layout.addLayout(btn_row)

        # Przechwycone pakiety + panel szczegółów (QSplitter)
        from PyQt5.QtCore import Qt
        splitter = QSplitter(Qt.Horizontal)

        # Lewa: tabela pakietów
        pkt_group = QGroupBox("Przechwycone pakiety")
        pkt_group_layout = QVBoxLayout()
        self.packets = QTableWidget(0, 7)
        self.packets.setHorizontalHeaderLabels([
            "ID", "Czas", "Źródło", "Cel", "Protokół", "Rozmiar (B)", "Waga AI"
        ])
        self.packets.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packets.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.packets.verticalHeader().setVisible(False)
        self.packets.setAlternatingRowColors(True)
        self.packets.setStyleSheet("QTableWidget {{selection-background-color: #2196F3;}}")
        self.packets.cellClicked.connect(self._show_packet_details_inline)
        pkt_group_layout.addWidget(self.packets)
        pkt_group.setLayout(pkt_group_layout)
        splitter.addWidget(pkt_group)

        # Prawa: panel szczegółów pakietu
        details_widget = QWidget()
        details_layout = QVBoxLayout()
        details_layout.addWidget(QLabel("Szczegóły pakietu:"))
        self.detail_info = QTextEdit()
        self.detail_info.setReadOnly(True)
        self.detail_info.setPlaceholderText("Wybierz pakiet, aby zobaczyć szczegóły...")
        details_layout.addWidget(self.detail_info)
        details_layout.addWidget(QLabel("HEX:"))
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setMaximumHeight(100)
        details_layout.addWidget(self.hex_view)
        details_layout.addWidget(QLabel("ASCII:"))
        self.ascii_view = QTextEdit()
        self.ascii_view.setReadOnly(True)
        self.ascii_view.setMaximumHeight(100)
        details_layout.addWidget(self.ascii_view)
        details_widget.setLayout(details_layout)
        splitter.addWidget(details_widget)
        splitter.setSizes([700, 300])
        main_layout.addWidget(splitter, stretch=1)

        # Dolna belka/log panel
        self.status_log = QTextEdit()
        self.status_log.setReadOnly(True)
        self.status_log.setMaximumHeight(60)
        self.status_log.setStyleSheet("background: #222; color: #fff; font-family: Consolas, monospace; font-size: 12px; border-radius: 6px; padding: 4px;")
        main_layout.addWidget(self.status_log)

        self._packet_data = []
        self.setLayout(main_layout)

        # Połącz przyciski z metodami
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
        cfg_path = "config/config.yaml"
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
        except Exception:
            cfg = {}
    # (usunięto powielony fragment z bpf)

        # Wiersz: przyciski sniffingu
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("Start")
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
    # ...wszystko to jest już w __init__...
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


    def _use_selected_interface(self):
        pretty = self.iface_combo.currentText()
        iface = self._iface_map.get(pretty)
        if iface:
            try:
                from core.orchestrator import Orchestrator
                if not self._orchestrator:
                    orchestrator = Orchestrator()
                    orchestrator.initialize()
                    self._orchestrator = orchestrator
                else:
                    orchestrator = self._orchestrator
                # Znajdź CaptureModule i ustaw interfejs
                for m in orchestrator.modules:
                    if m.__class__.__name__ == "CaptureModule":
                        m.set_interface(iface)
                        self._capture = m
                        break
                self.log_status(f"Ustawiono interfejs: {pretty}")
            except Exception as e:
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.warning(self, "Błąd", f"Nie udało się ustawić interfejsu: {e}")
                self.log_status(f"Błąd: nie udało się ustawić interfejsu: {e}")
        else:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Błąd", "Nie wybrano poprawnego interfejsu!")
            self.log_status("Błąd: nie wybrano poprawnego interfejsu!")


    def _test_interfaces(self):
        from modules.capture import CaptureModule
        results = CaptureModule().test_all_interfaces()
        msg = "Wyniki testu interfejsów:\n"
        for iface, res in results.items():
            msg += f"{iface}: {res}\n"
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(self, "Test interfejsów", msg)
        self.log_status("Wykonano test interfejsów.")

    def _on_start_sniffing(self):
        pretty = self.iface_combo.currentText()
        iface = self._iface_map.get(pretty)
        if iface:
            try:
                from core.orchestrator import Orchestrator
                if not self._orchestrator:
                    orchestrator = Orchestrator()
                    orchestrator.initialize()
                    self._orchestrator = orchestrator
                else:
                    orchestrator = self._orchestrator
                # Znajdź CaptureModule i ustaw interfejs
                for m in orchestrator.modules:
                    if m.__class__.__name__ == "CaptureModule":
                        m.set_interface(iface)
                        self._capture = m
                        break
                self._sniffing = True
                self.log_status(f"Sniffing uruchomiony na interfejsie: {pretty}")
            except Exception as e:
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.warning(self, "Błąd", f"Nie udało się ustawić interfejsu: {e}")
                self.log_status(f"Błąd: nie udało się ustawić interfejsu: {e}")
        else:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Błąd", "Nie wybrano poprawnego interfejsu!")
            self.log_status("Błąd: nie wybrano poprawnego interfejsu!")

    def _on_pause_sniffing(self):
        if self._sniffing:
            self._sniffing = False
            self.log_status("Sniffing wstrzymany.")

    def _on_stop_sniffing(self):
        if self._sniffing:
            self._sniffing = False
            self.log_status("Sniffing zatrzymany.")

    def log_status(self, msg):
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S')
        self.status_log.append(f"[{ts}] {msg}")

    # ...existing code...

    def _show_packet_details_inline(self, row, col):
        idx = row
        if 0 <= idx < len(self._packet_data):
            pkt_id, pkt_bytes, meta = self._packet_data[idx]
            # Szczegóły pakietu w stylu Wireshark
            details = []
            # Warstwa łącza (Ethernet)
            eth_src = meta.get('eth_src')
            eth_dst = meta.get('eth_dst')
            eth_type = meta.get('eth_type')
            if eth_src or eth_dst or eth_type:
                details.append('[Ethernet]')
                if eth_src: details.append(f'  MAC źródłowy: {eth_src}')
                if eth_dst: details.append(f'  MAC docelowy: {eth_dst}')
                if eth_type: details.append(f'  Typ ramki: {eth_type}')

            # Warstwa sieciowa (IP)
            ip_src = meta.get('src_ip')
            ip_dst = meta.get('dst_ip')
            ip_ver = meta.get('ip_version')
            ttl = meta.get('ttl')
            ip_id = meta.get('ip_id')
            ip_flags = meta.get('ip_flags')
            if ip_src or ip_dst or ip_ver or ttl or ip_id or ip_flags:
                details.append('[IP]')
                if ip_ver: details.append(f'  Wersja: {ip_ver}')
                if ip_src: details.append(f'  IP źródłowy: {ip_src}')
                if ip_dst: details.append(f'  IP docelowy: {ip_dst}')
                if ttl: details.append(f'  TTL: {ttl}')
                if ip_id: details.append(f'  ID: {ip_id}')
                if ip_flags: details.append(f'  Flagi: {ip_flags}')

            # Warstwa transportowa (TCP/UDP/ICMP)
            proto = meta.get('protocol')
            src_port = meta.get('src_port')
            dst_port = meta.get('dst_port')
            tcp_flags = meta.get('tcp_flags')
            seq = meta.get('tcp_seq')
            ack = meta.get('tcp_ack')
            win = meta.get('tcp_win')
            icmp_type = meta.get('icmp_type')
            icmp_code = meta.get('icmp_code')
            if proto:
                details.append(f'[Transport: {proto}]')
                if src_port: details.append(f'  Port źródłowy: {src_port}')
                if dst_port: details.append(f'  Port docelowy: {dst_port}')
                if tcp_flags: details.append(f'  Flagi TCP: {tcp_flags}')
                if seq: details.append(f'  SEQ: {seq}')
                if ack: details.append(f'  ACK: {ack}')
                if win: details.append(f'  Okno: {win}')
                if icmp_type: details.append(f'  ICMP typ: {icmp_type}')
                if icmp_code: details.append(f'  ICMP kod: {icmp_code}')

            # Warstwa aplikacyjna (np. HTTP, DNS)
            app_proto = meta.get('app_proto')
            http_method = meta.get('http_method')
            http_host = meta.get('http_host')
            http_url = meta.get('http_url')
            http_code = meta.get('http_code')
            dns_query = meta.get('dns_query')
            dns_resp = meta.get('dns_resp')
            if app_proto:
                details.append(f'[Aplikacja: {app_proto}]')
                if http_method: details.append(f'  HTTP metoda: {http_method}')
                if http_host: details.append(f'  HTTP host: {http_host}')
                if http_url: details.append(f'  HTTP URL: {http_url}')
                if http_code: details.append(f'  HTTP kod: {http_code}')
                if dns_query: details.append(f'  DNS zapytanie: {dns_query}')
                if dns_resp: details.append(f'  DNS odpowiedź: {dns_resp}')

            # AI/Status
            ai_status = meta.get('ai_status')
            ai_weight = meta.get('ai_weight')
            if ai_status or ai_weight:
                details.append('[AI/Security]')
                if ai_status: details.append(f'  Status AI: {ai_status}')
                if ai_weight: details.append(f'  Waga AI: {ai_weight}')

            # Ogólne
            details.append('[Ogólne]')
            details.append(f'  ID pakietu: {pkt_id}')
            details.append(f'  Rozmiar: {len(pkt_bytes)} B')
            ts = meta.get('timestamp')
            if ts: details.append(f'  Czas: {ts}')
            iface = meta.get('iface')
            if iface: details.append(f'  Interfejs: {iface}')

            self.detail_info.setText("\n".join(details))
            # HEX
            hex_data = self._format_hex(pkt_bytes)
            self.hex_view.setText(hex_data)
            # ASCII
            ascii_data = self._format_ascii(pkt_bytes)
            self.ascii_view.setText(ascii_data)

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

    # ...existing code...

    # _packet_desc niepotrzebny

    # _short_packet niepotrzebny


    # ...existing code...

    # ...existing code...

print('qt_dashboard.py: przed DevicesTab')
class DevicesTab(QWidget):
    def __init__(self):
        from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView
        super().__init__()
        layout = QVBoxLayout()
        title = QLabel("Live Devices")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        group = QGroupBox("Aktywne urządzenia w sieci")
        group_layout = QVBoxLayout()
        self.devices = QTableWidget(0, 5)
        self.devices.setHorizontalHeaderLabels([
            "IP", "MAC", "Ostatnio widziany", "Pakiety", "Status"
        ])
        self.devices.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.devices.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.devices.verticalHeader().setVisible(False)
        self.devices.setAlternatingRowColors(True)
        self.devices.setStyleSheet("QTableWidget {selection-background-color: #2196F3;}")
        group_layout.addWidget(self.devices)
        group.setLayout(group_layout)
        layout.addWidget(group)
        layout.addStretch()
        self.setLayout(layout)

        # Bufor: lista słowników z danymi urządzeń
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
        layout = QVBoxLayout()
        title = QLabel("Network Scanner")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        group = QGroupBox("Skanowanie sieci")
        group_layout = QVBoxLayout()
        self.scan_btn = QPushButton("Uruchom skanowanie")
        group_layout.addWidget(self.scan_btn)
        self.results = QListWidget()
        group_layout.addWidget(self.results)
        group.setLayout(group_layout)
        layout.addWidget(group)
        layout.addStretch()
        self.setLayout(layout)


from PyQt5.QtWidgets import QHBoxLayout, QLineEdit, QMessageBox, QComboBox, QFormLayout


print('qt_dashboard.py: przed ConfigTab')
class ConfigTab(QWidget):
    PRESETS = [
        ("800 x 600", 800, 600),
        ("1024 x 768", 1024, 768),
        ("1280 x 800", 1280, 800),
        ("1366 x 768", 1366, 768),
        ("1600 x 900", 1600, 900),
        ("1920 x 1080", 1920, 1080),
        ("2560 x 1440", 2560, 1440),
        ("3840 x 2160", 3840, 2160),
    ]
    def __init__(self, main_window=None):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout()
        title = QLabel("Konfiguracja okna GUI")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)

        group = QGroupBox("Rozmiar okna")
        form = QFormLayout()

        self.preset_combo = QComboBox()
        for label, w, h in self.PRESETS:
            self.preset_combo.addItem(label, (w, h))
        self.preset_combo.currentIndexChanged.connect(self._preset_selected)
        form.addRow("Wybierz rozmiar:", self.preset_combo)

        self.width_input = QLineEdit()
        self.height_input = QLineEdit()
        self.width_input.setMaximumWidth(80)
        self.height_input.setMaximumWidth(80)
        wh_box = QHBoxLayout()
        wh_box.addWidget(QLabel("Szerokość:"))
        wh_box.addWidget(self.width_input)
        wh_box.addWidget(QLabel("Wysokość:"))
        wh_box.addWidget(self.height_input)
        wh_box.addStretch()
        form.addRow("Ręcznie:", wh_box)

        self.apply_btn = QPushButton("Zastosuj rozmiar okna")
        form.addRow(self.apply_btn)
        group.setLayout(form)
        layout.addWidget(group)
        layout.addStretch()
        self.setLayout(layout)

        self._load_window_size()
        self.apply_btn.clicked.connect(self._apply_window_size)

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
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Network Packet Analyzer Pro")
        self.tabs = QTabWidget()
        self.dashboard = DashboardTab()
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

    def _stop_sniffing(self):
        self._sniffing = False
        self._paused = False

    def _set_initial_window_size(self):
        # Domyślne wartości
        width, height = None, None
        try:
            with open('config/config.yaml', 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
            width = cfg.get('window_width')
            height = cfg.get('window_height')
        except Exception:
            pass
        if not width or not height:
            # Pobierz rozdzielczość głównego ekranu
            screen = QApplication.primaryScreen()
            size = screen.size()
            width = int(size.width() * 0.8)
            height = int(size.height() * 0.8)
        self.resize(width, height)

    def run_scan(self):
        self.scanner.results.addItem("[DEMO] Wynik skanowania...")

