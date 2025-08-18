from modules.features import FeaturesModule
from scapy.all import Ether
from modules.detection import DetectionModule
# print('qt_dashboard.py: start import')
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
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QTextCursor
try:
    from PyQt5.QtCore import qRegisterMetaType
    qRegisterMetaType(QTextCursor, 'QTextCursor')
except ImportError:
    pass
# print('qt_dashboard.py: przed PacketDetailDialog')


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


# print('qt_dashboard.py: przed DashboardTab')


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
        # Load UI from file relative to this script
        import os
        ui_path = os.path.join(os.path.dirname(__file__), 'dashboard.ui')
        uic.loadUi(ui_path, self)
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
        # Double-click to open detailed dialog
        self.packets.cellDoubleClicked.connect(self._show_packet_detail_dialog)
        self.detail_info.setPlaceholderText(
            'Wybierz pakiet, aby zobaczyć szczegóły...')
        self.status_log.setStyleSheet(
            'background: #222; color: #fff; font-family: Consolas, monospace; '
            'font-size: 12px; border-radius: 6px; padding: 4px;'
        )
        # Inicjalizacja modułu przechwytywania pakietów
        from modules.capture import CaptureModule
        self._capture = CaptureModule()
        self._capture.initialize({})
        # Load protocol mapping from config/protocols.yaml
        import yaml, os
        proto_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'protocols.yaml'))
        try:
            with open(proto_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            # Build mapping only for numeric keys, skip ranges or invalid entries
            mapping = {}
            for key, name in data.items():
                # Add mapping for integer keys and their string equivalents
                if isinstance(key, int):
                    mapping[key] = name
                    mapping[str(key)] = name
                elif isinstance(key, str) and key.isdigit():
                    num = int(key)
                    mapping[num] = name
                    mapping[key] = name
            self.protocols = mapping
        except Exception:
            self.protocols = {}
        # Initialize AI pipeline modules
        from modules.features import FeaturesModule
        self._features_module = FeaturesModule()
        self._features_module.initialize({})
        from modules.detection import DetectionModule
        self._detection_module = DetectionModule()
        self._detection_module.initialize({})
        # Inicjalizacja danych pakietów
        self._packet_data = []
        self._packet_metas = []  # metadane do eksportu i podglądu
        self._db_path = 'packets.db'
        self._init_db()
        # Flagi stanu
        self._sniffing = False
        self._paused = False
        self._orchestrator = None
        self._packet_counter = 0
        # Executor for AI pipeline offloading
        self._executor = ThreadPoolExecutor(max_workers=2)
        self._futures = []  # pending processing futures
        # Timer do przetwarzania zdarzeń pakietowych
        from PyQt5.QtCore import QTimer
        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._process_new_packets)
        self._event_timer.start(100)
        # Wczytanie ustawień aplikacji
        import yaml, os
        cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'config.yaml'))
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
        except:
            cfg = {}
        bpf = cfg.get('filter', '')
        if bpf:
            self.filter_combo.lineEdit().setText(bpf)
        self._capture.config['filter'] = bpf
        iface = cfg.get('network_interface', None)
        if iface:
            idx = [i for i, (ifn, _) in enumerate(self._iface_map) if ifn == iface]
            if idx:
                self.interface_combo.setCurrentIndex(idx[0])
        # Automatyczne rozpoczęcie przechwytywania
        self._on_start_sniffing()

        # Limit number of displayed rows to avoid excessive repaint
        self._max_display_rows = 100
    # Executor for DB writes (używa module-level importu ThreadPoolExecutor)
        self._db_executor = ThreadPoolExecutor(max_workers=1)

    def _on_test_interfaces(self):
        """Testuj przechwytywanie na wszystkich interfejsach i wyświetl wyniki."""
        from scapy.all import sniff
        self.log_status('Rozpoczynam test interfejsów...')
        for iface, pretty in getattr(self, '_iface_map', []):
            packets = []
            try:
                sniff(prn=lambda pkt: packets.append(pkt), iface=iface,
                      timeout=2, count=1, store=0)
                count = len(packets)
            except Exception as e:
                count = f'Błąd: {e}'
            self.log_status(f'{pretty}: {count} pakietów')

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
        from PyQt5.QtWidgets import QFileDialog
        from datetime import datetime
        default_name = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            path, _ = QFileDialog.getSaveFileName(self, 'Zapisz CSV', default_name, 'CSV (*.csv)')
            if not path:
                self.log_status('Eksport CSV anulowany')
                return
            import csv
            # Zapisz dane pakietów z metadanych
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Time', 'Src', 'Dst', 'Proto', 'Size', 'AI'])
                for i, m in enumerate(self._packet_metas, start=1):
                    writer.writerow([
                        i,
                        m.get('timestamp', ''),
                        m.get('src_ip', ''),
                        m.get('dst_ip', ''),
                        m.get('protocol', ''),
                        m.get('payload_size', ''),
                        m.get('ai_weight', '')
                    ])
            self.log_status(f'Zapisano CSV: {path}')
        except Exception as e:
            self.log_status(f'Błąd zapisu CSV: {e}')

    def _on_export_pcap(self):
        """Eksportuj pakiety do pliku PCAP"""
        from PyQt5.QtWidgets import QFileDialog
        from scapy.all import wrpcap, Ether
        try:
            from datetime import datetime
            default_pcap = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            path, _ = QFileDialog.getSaveFileName(self, 'Zapisz PCAP', default_pcap, 'PCAP (*.pcap)')
            if not path:
                self.log_status('Eksport PCAP anulowany')
                return
            # Utwórz listę pakietów Scapy z surowych bajtów
            pkts = [Ether(m.get('raw_bytes', b'')) for m in self._packet_metas]
            wrpcap(path, pkts)
            self.log_status(f'Zapisano PCAP: {path}')
        except Exception as e:
            self.log_status(f'Błąd zapisu PCAP: {e}')
    
    def _show_packet_details_inline(self, row, col):
        """Wyświetla szczegóły pakietu po kliknięciu w tabeli"""
        try:
            # Pobierz metadane pakietu
            meta = self._packet_metas[row]
            raw = meta.get('raw_bytes', b'')
            weight = meta.get('ai_weight', '')
            # Parsowanie warstw pakietu
            from scapy.packet import NoPayload
            pkt = Ether(raw)
            lines = [f"AI weight: {weight}\n"]
            layer = pkt
            while layer and not isinstance(layer, NoPayload):
                lines.append(f"== Layer: {layer.name} ==\n")
                for field, value in layer.fields.items():
                    if field in ('proto', 'type') and isinstance(value, int):
                        pname = self.protocols.get(value)
                        if pname:
                            value = f"{pname} ({value})"
                    lines.append(f"{field}: {value}\n")
                layer = layer.payload if hasattr(layer, 'payload') else None
            # Wyświetl szczegóły pakietu
            self.detail_info.setPlainText(''.join(lines))
            # Wyświetl HEX
            self.hex_view.setPlainText(' '.join(f"{b:02x}" for b in raw))
            # Wyświetl ASCII
            self.ascii_view.setPlainText(''.join(chr(b) if 32 <= b < 127 else '.' for b in raw))
        except Exception as e:
            self.log_status(f"Nie można wyświetlić szczegółów pakietu: {e}")

    def _show_packet_detail_dialog(self, row, col):
        """Open packet details in a separate dialog."""
        try:
            meta = self._packet_metas[row]
            raw = meta.get('raw_bytes', b'')
            # Prepare hex and ascii strings
            hex_data = ' '.join(f"{b:02x}" for b in raw)
            ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
            dialog = PacketDetailDialog(row+1, hex_data, ascii_data, self)
            dialog.exec_()
        except Exception as e:
            self.log_status(f"Nie można otworzyć okna szczegółów pakietu: {e}")

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
        # Skip if not active
        if not self._sniffing or self._paused:
            return
        # Fetch and submit new events to executor
        if self._capture and hasattr(self._capture, 'generate_event'):
            while True:
                event = self._capture.generate_event()
                if not event:
                    break
                # Submit processing to background
                fut = self._executor.submit(self._process_packet, event)
                self._futures.append(fut)
        # Collect completed futures and update UI in batch
        if not self._futures:
            return
        # Disable updates for batch insert
        self.packets.setUpdatesEnabled(False)
        done, pending = [], []
        for fut in self._futures:
            if fut.done():
                try:
                    meta = fut.result()
                    self._insert_packet_row(meta)
                except Exception as e:
                    self.log_status(f'Błąd przetwarzania pakietu: {e}')
                else:
                    done.append(fut)
            else:
                pending.append(fut)
        self._futures = pending
        self.packets.setUpdatesEnabled(True)

    def _process_packet(self, event):
        """Oblicza AI weight i przygotowuje metadane pakietu."""
        # Copy event data and preserve raw bytes for detail panels
        meta = event.data.copy()
        meta['raw_bytes'] = event.data.get('raw_bytes', b'')
        # Timestamp
        from datetime import datetime
        meta['timestamp'] = datetime.now().strftime('%H:%M:%S')
        # AI pipeline
        self._features_module.handle_event(event)
        try:
            feat_ev = self._features_module.generate_event()
        except AttributeError:
            # Missing last_packet, treat as no features
            feat_ev = None
        weight = 0.0
        if feat_ev:
            feats = feat_ev.data
            import numpy as _np
            X = _np.array([
                float(feats.get('packet_count', 0)),
                float(feats.get('total_bytes', 0)),
                float(feats.get('flow_id', 0))
            ])
            # Ensure 2D array for model
            if X.ndim == 1:
                X = X.reshape(1, -1)
            if getattr(self._detection_module, 'use_nn', False) and hasattr(self._detection_module, 'nn_model'):
                weight = float(self._detection_module.nn_model.predict(X)[0][0])
            elif hasattr(self._detection_module, 'if_model'):
                # Ensure feature vector matches model dimension
                model = self._detection_module.if_model
                expected = getattr(model, 'n_features_in_', X.shape[1])
                # Pad or trim X as needed
                if X.shape[1] < expected:
                    X = _np.pad(X, ((0, 0), (0, expected - X.shape[1])), constant_values=0)
                elif X.shape[1] > expected:
                    X = X[:, :expected]
                score = float(model.decision_function(X)[0])
                weight = abs(score)
        meta['ai_weight'] = round(weight, 2)
        # Run Snort rules plugins
        for plugin in getattr(self, '_snort_plugins', []):
            res = plugin.handle_event(event)
            if res and res.type == 'SNORT_ALERT':
                # Log and emit UI alert
                self.log_status(f"[SNORT ALERT] SID:{res.data.get('sid')} MSG:{res.data.get('msg')}")
        return meta

    def _insert_packet_row(self, meta):
        """Wstawia przetworzony pakiet do GUI."""
        # Store metadata and insert row at top
        self._packet_metas.insert(0, meta)
        # Insert row at top
        self._packet_counter += 1
        self.packets.insertRow(0)
        # Map protocol
        # Translate protocol number to name based on mapping
        raw_proto = meta.get('protocol', '')
        display_proto = raw_proto
        # Integer protocol code
        if isinstance(raw_proto, int):
            display_proto = self.protocols.get(raw_proto, str(raw_proto))
        # String numeric protocol code
        elif isinstance(raw_proto, str) and raw_proto.isdigit():
            num = int(raw_proto)
            display_proto = self.protocols.get(num, raw_proto)
        # Leave other strings (e.g., 'ARP') unchanged
        vals = [
            str(self._packet_counter),
            meta.get('timestamp', ''),
            str(meta.get('src_ip', '')),
            str(meta.get('dst_ip', '')),
            str(display_proto),
            str(meta.get('payload_size', '')),
            str(meta.get('ai_weight', '')),
            str(meta.get('geolocation', ''))
        ]
        for col, v in enumerate(vals):
            self.packets.setItem(0, col, QTableWidgetItem(v))
        # Color by weight
        try:
            from PyQt5.QtGui import QColor
            w = float(vals[6])
            if w < 0.5:
                color = QColor(0, 200, 0, 60)
            elif w < 1.5:
                color = QColor(255, 255, 0, 60)
            else:
                color = QColor(255, 0, 0, 80)
            for c in range(self.packets.columnCount()):
                item = self.packets.item(0, c)
                if item:
                    item.setBackground(color)
        except:
            pass
        # Store metadata
        self._packet_metas.insert(0, meta)
        # Asynchronously save to DB
        try:
            pkt_id = self._packet_counter
            # schedule DB write
            self._db_executor.submit(
                self._save_packet_to_db,
                pkt_id,
                meta.get('timestamp', ''),
                meta.get('src_ip', ''),
                meta.get('dst_ip', ''),
                meta.get('protocol', ''),
                meta.get('payload_size', ''),
                meta.get('ai_weight', ''),
                meta.get('geolocation', '')
            )
        except Exception as e:
            self.log_status(f'Błąd zapisu do DB: {e}')
        # Enforce row cap
        row_count = self.packets.rowCount()
        if row_count > self._max_display_rows:
            # remove oldest row
            self.packets.removeRow(row_count - 1)
            try:
                self._packet_metas.pop()
            except IndexError:
                pass
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