import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QPushButton, QListWidget, QGroupBox,
    QTableWidget, QTableWidgetItem, QAbstractItemView, QSplitter, QTextEdit, QHBoxLayout, QDialog
)
import threading

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

class DashboardTab(QWidget):

    def __init__(self):
        super().__init__()
        main_layout = QVBoxLayout()
        title = QLabel("AI Network Packet Analyzer Pro - Dashboard")
        title.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 10px;")
        main_layout.addWidget(title)
        main_layout.addSpacing(10)

        # Wybór interfejsu sieciowego
        from PyQt5.QtWidgets import QComboBox
        from modules.netif_pretty import get_interfaces_pretty
        iface_layout = QHBoxLayout()
        iface_label = QLabel("Interfejs:")
        self.iface_combo = QComboBox()
        self._iface_map = {}  # czytelny opis -> nazwa techniczna
        for name, pretty in get_interfaces_pretty():
            self.iface_combo.addItem(pretty)
            self._iface_map[pretty] = name
        iface_layout.addWidget(iface_label)
        iface_layout.addWidget(self.iface_combo)
        # Dodaj przycisk testowania interfejsów
        self.test_ifaces_btn = QPushButton("Testuj interfejsy")
        self.test_ifaces_btn.setStyleSheet("background: #1976D2; color: white; font-weight: bold; border-radius: 6px; padding: 6px 8px;")
        self.test_ifaces_btn.clicked.connect(self._test_interfaces)
        iface_layout.addWidget(self.test_ifaces_btn)
        iface_layout.addStretch()
        main_layout.addLayout(iface_layout)

        # Przyciski sterujące sniffingiem
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.pause_btn = QPushButton("Pauza")
        self.stop_btn = QPushButton("Stop")
        for btn, color in [
            (self.start_btn, '#4CAF50'),
            (self.pause_btn, '#FFC107'),
            (self.stop_btn, '#F44336')]:
            btn.setFixedWidth(100)
            btn.setStyleSheet(f"font-weight: bold; background: {color}; color: white; border-radius: 8px; padding: 8px 0px; font-size: 14px;")
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.pause_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addStretch()
        main_layout.addLayout(btn_layout)
        # Inicjalizacja orchestratora w tle i referencji do CaptureModule
        self._orchestrator = None
        self._capture = None
        self._event_queue = []
        self._sniffing = False
        self._packet_counter = 0
        self._init_orchestrator_thread()
        # Timer do pobierania eventów co 100ms
        from PyQt5.QtCore import QTimer
        self._event_timer = QTimer()
        self._event_timer.timeout.connect(self._process_events)
        self._event_timer.start(100)
        self.start_btn.clicked.connect(self._on_start_sniffing)

    def _init_orchestrator_thread(self):
        import threading
        def run_orchestrator():
            from core.orchestrator import Orchestrator
            orchestrator = Orchestrator()
            orchestrator.initialize()
            self._orchestrator = orchestrator
            # Znajdź CaptureModule
            for m in orchestrator.modules:
                if m.__class__.__name__ == "CaptureModule":
                    self._capture = m
                    break
        t = threading.Thread(target=run_orchestrator, daemon=True)
        t.start()

    def _on_start_sniffing(self):
        pretty = self.iface_combo.currentText()
        iface = self._iface_map.get(pretty)
        if iface and self._capture:
            self._capture.set_interface(iface)
            self._sniffing = True
            print(f"[GUI] Start sniffingu na interfejsie: {iface}")
        else:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Błąd", "Nie wybrano poprawnego interfejsu lub backend niegotowy!")

    def _process_events(self):
        if not self._sniffing or not self._capture:
            return
        event = self._capture.generate_event()
        if event and event.type == "NEW_PACKET":
            pkt_bytes = event.data.get("raw_bytes")
            if pkt_bytes:
                meta = dict(event.data)
                self._packet_counter += 1
                self.add_packet(self._packet_counter, pkt_bytes, meta)

    def _on_start_sniffing(self):
        # Pobierz wybrany interfejs (czytelny opis -> nazwa techniczna)
        pretty = self.iface_combo.currentText()
        iface = self._iface_map.get(pretty)
        if iface:
            from modules.capture import CaptureModule
            print(f"[GUI] Start sniffingu na interfejsie: {iface}")
            # Możesz tu dodać logikę do przekazania iface do orchestratora/capture
            # (np. przez event lub bezpośrednio, zależnie od architektury)
            # Przykład bezpośredni (jeśli masz referencję do capture):
            # self._capture.set_interface(iface)
            # (lub wywołanie eventu do orchestratora)
        else:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Błąd", "Nie wybrano poprawnego interfejsu!")

        # Layout główny: poziomy (tabela + panel podglądu)
        from PyQt5.QtCore import Qt
        main_splitter = QSplitter()
        main_splitter.setOrientation(Qt.Horizontal)

        # Lewa strona: tabela pakietów
        pkt_widget = QWidget()
        pkt_layout = QVBoxLayout()
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
        self.packets.setStyleSheet("QTableWidget {selection-background-color: #2196F3;}")
        pkt_group_layout.addWidget(self.packets)
        pkt_group.setLayout(pkt_group_layout)
        pkt_layout.addWidget(pkt_group)
        pkt_widget.setLayout(pkt_layout)
        main_splitter.addWidget(pkt_widget)

        # Dodaj main_splitter do layoutu głównego
        main_layout.addWidget(main_splitter)

        self._packet_data = []
        self.setLayout(main_layout)

    def _test_interfaces(self):
        from modules.capture import CaptureModule
        results = CaptureModule().test_all_interfaces()
        msg = "Wyniki testu interfejsów:\n"
        for iface, res in results.items():
            msg += f"{iface}: {res}\n"
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(self, "Test interfejsów", msg)

    def _on_start_sniffing(self):
        # Pobierz wybrany interfejs (czytelny opis -> nazwa techniczna)
        pretty = self.iface_combo.currentText()
        iface = self._iface_map.get(pretty)
        if iface:
            # Przekaż wybrany interfejs do orchestratora/capture
            try:
                from core.orchestrator import Orchestrator
                if hasattr(self, '_orchestrator'):
                    orchestrator = self._orchestrator
                else:
                    orchestrator = Orchestrator()
                    orchestrator.initialize()
                    self._orchestrator = orchestrator
                # Znajdź CaptureModule i ustaw interfejs
                for m in orchestrator.modules:
                    if m.__class__.__name__ == "CaptureModule":
                        m.set_interface(iface)
                        print(f"[GUI] Start sniffingu na interfejsie: {iface}")
                        break
            except Exception as e:
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.warning(self, "Błąd", f"Nie udało się ustawić interfejsu: {e}")
        else:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Błąd", "Nie wybrano poprawnego interfejsu!")
    def add_packet(self, pkt_id, pkt_bytes, meta=None):
        # Dodaj pakiet na początek tabeli i bufora
        if meta is None:
            meta = {}
        print(f"[DashboardTab] add_packet: pkt_id={pkt_id}, meta={meta}")
        self._packet_data.insert(0, (pkt_id, pkt_bytes, meta))
        self.packets.insertRow(0)
        # Kolumny: ID, czas, src, dst, protokół, rozmiar
        src = meta.get('src_ip', '-')
        dst = meta.get('dst_ip', '-')
        proto = meta.get('protocol', '-')
        # Zamiana numeru protokołu na nazwę
        proto_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            '1': 'ICMP',
            '6': 'TCP',
            '17': 'UDP',
            'ICMP': 'ICMP',
            'TCP': 'TCP',
            'UDP': 'UDP',
        }
        if isinstance(proto, int) or (isinstance(proto, str) and proto.isdigit()):
            proto_str = proto_map.get(int(proto), str(proto))
        else:
            proto_str = proto_map.get(proto, str(proto))
        size = meta.get('payload_size', len(pkt_bytes))
        ts = meta.get('timestamp', '-')
        ai_status = meta.get('ai_status', 'safe')
        # Pobierz wagę AI jeśli jest dostępna
        ai_weight = meta.get('ai_weight', '-')
        row = [
            str(pkt_id), str(ts), str(src), str(dst), proto_str, str(size), str(ai_weight)
        ]
        for col, val in enumerate(row):
            item = QTableWidgetItem(val)
            self.packets.setItem(0, col, item)
        # Kolorowanie wiersza na podstawie ai_status
        color = None
        if ai_status == 'threat':
            color = '#FFCDD2'  # czerwony
        elif ai_status == 'suspicious':
            color = '#FFF9C4'  # żółty
        elif ai_status == 'safe':
            color = '#C8E6C9'  # zielony
        if color:
            from PyQt5.QtGui import QColor
            qcolor = QColor(color)
            for col in range(self.packets.columnCount()):
                item = self.packets.item(0, col)
                if item:
                    item.setBackground(qcolor)
        # Ogranicz liczbę pakietów na liście (np. 1000)
        if self.packets.rowCount() > 1000:
            self.packets.removeRow(self.packets.rowCount()-1)
            self._packet_data = self._packet_data[:1000]

    # _packet_desc niepotrzebny

    # _short_packet niepotrzebny


    def _show_packet_details_inline(self, row, col):
        idx = row
        if 0 <= idx < len(self._packet_data):
            pkt_id, pkt_bytes, meta = self._packet_data[idx]
            hex_data = self._format_hex(pkt_bytes)
            ascii_data = self._format_ascii(pkt_bytes)
            self.hex_view.setText(hex_data)
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



import yaml
import threading
import queue
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QScreen



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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
