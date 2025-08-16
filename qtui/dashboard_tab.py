from PyQt5.QtWidgets import QWidget, QTableWidgetItem, QTextEdit, QComboBox, QPushButton, QTableWidget, QFileDialog, QApplication
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QColor
import csv
from scapy.all import wrpcap, Ether
from modules.capture import CaptureModule
from modules.features import FeaturesModule
from modules.detection import DetectionModule
from modules.netif import list_interfaces
import numpy as np
import os, yaml

class DashboardTab(QWidget):
    """Zakładka Dashboard: podgląd pakietów, filtr, logi i detale"""
    def __init__(self, parent=None):
        super().__init__(parent)
        # Load UI
        import os
        from PyQt5 import uic
        ui_path = os.path.join(os.path.dirname(__file__), 'dashboard.ui')
        uic.loadUi(ui_path, self)

        # UI controls
        self.interface_combo = self.findChild(QComboBox, 'interface_combo')
        self.filter_combo = self.findChild(QComboBox, 'filter_combo')
        self.set_filter_btn = self.findChild(QPushButton, 'set_filter_btn')
        self.start_btn = self.findChild(QPushButton, 'start_btn')
        self.pause_btn = self.findChild(QPushButton, 'pause_btn')
        self.stop_btn = self.findChild(QPushButton, 'stop_btn')
        self.export_csv_btn = self.findChild(QPushButton, 'export_csv_btn')
        self.export_pcap_btn = self.findChild(QPushButton, 'export_pcap_btn')
        self.test_btn = self.findChild(QPushButton, 'test_btn')
        self.packets = self.findChild(QTableWidget, 'packets_table')
        self.detail_info = self.findChild(QTextEdit, 'detail_info')
        self.hex_view = self.findChild(QTextEdit, 'hex_view')
        self.ascii_view = self.findChild(QTextEdit, 'ascii_view')
        self.status_log = self.findChild(QTextEdit, 'status_log')
        # Style status log like cmd_log_widget
        self.status_log.setStyleSheet(
            'background: #222; color: #fff; font-family: Consolas, monospace; '
            'font-size: 12px; border-radius: 6px; padding: 4px;'
        )
        self.status_log.setMinimumHeight(60)
        self.status_log.setMaximumHeight(60)

        # Load protocol names map for detail decoding
        proto_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'protocols.yaml'))
        try:
            with open(proto_file, 'r', encoding='utf-8') as pf:
                self.protocols_map = yaml.safe_load(pf)
        except Exception:
            self.protocols_map = {}
        # Initialize modules
        self._capture = CaptureModule(); self._capture.initialize({'network_interface': None, 'filter': ''})
        self._features_module = FeaturesModule(); self._features_module.initialize({})
        self._detection_module = DetectionModule(); self._detection_module.initialize({})

        # Populate dropdowns
        self.interface_combo.addItems(list_interfaces())
        self.filter_combo.setEditable(True)
        self.filter_combo.addItems(['', 'tcp', 'udp', 'icmp', 'port 80', 'port 443'])
        # Set default interface for capture
        if self.interface_combo.count() > 0:
            default_if = self.interface_combo.currentText()
            self._capture.set_interface(default_if)
            self.log_status(f'Wybrano interfejs sieciowy: {default_if}')

        # Connect events
        self.set_filter_btn.clicked.connect(self._on_set_filter)
        self.export_csv_btn.clicked.connect(self._on_export_csv)
        self.export_pcap_btn.clicked.connect(self._on_export_pcap)
        self.interface_combo.currentIndexChanged.connect(
            lambda idx: self._capture.set_interface(self.interface_combo.itemText(idx))
        )
        self.test_btn.clicked.connect(self._on_test_interfaces)
        self.start_btn.clicked.connect(self._on_start_sniffing)
        self.pause_btn.clicked.connect(self._on_pause_sniffing)
        self.stop_btn.clicked.connect(self._on_stop_sniffing)
        self.packets.cellClicked.connect(self._show_packet_details_inline)
        # State and timer
        self._sniffing = False
        self._paused = False
        self._packet_metas = []
        self._packet_counter = 0
        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._process_new_packets)
        self._event_timer.start(100)
        # Auto-start
        self._on_start_sniffing()
        # Initial logs
        self.log_status('DashboardTab załadowany')
        # Report initial resolution
        screen = QApplication.primaryScreen()
        geom = screen.availableGeometry()
        self.log_status(f'Uruchomiono w rozdzielczości: {geom.width()}x{geom.height()}')
        # Report active AI engine
        engine = 'Neural Net' if self._detection_module.use_nn else 'Isolation Forest'
        self.log_status(f'Aktualny silnik AI: {engine}')

    def log_status(self, msg):
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S')
        self.status_log.append(f'<span style="color:#8bc34a;">[{ts}]</span> {msg}')

    def _on_set_filter(self):
        bpf = self.filter_combo.currentText()
        self._capture.set_filter(bpf)
        self.log_status(f'Ustawiono filtr BPF: {bpf}')

    def _on_test_interfaces(self):
        try:
            results = self._capture.test_all_interfaces()
            found = next((iface for iface, cnt in results.items() if isinstance(cnt, int) and cnt > 0), None)
            self.log_status(f'Aktywny interfejs: {found}' if found else 'Brak ruchu na interfejsach')
        except Exception as e:
            self.log_status(f'Błąd testu interfejsów: {e}')

    def _on_start_sniffing(self):
        self._sniffing = True
        self._capture._start_sniffing()
        self.log_status('Rozpoczęto przechwytywanie pakietów')

    def _on_pause_sniffing(self):
        self._paused = not self._paused
        self.log_status('Pauza' if self._paused else 'Wznawiam przechwytywanie pakietów')

    def _on_stop_sniffing(self):
        self._sniffing = False
        self._paused = False
        self.log_status('Zatrzymano przechwytywanie pakietów')

    def _process_new_packets(self):
        if not self._sniffing or self._paused:
            return
        ev = self._capture.generate_event()
        if not ev:
            return
        # Capture raw packet data
        data = ev.data
        # AI pipeline: features then detection
        self._features_module.handle_event(ev)
        feat_ev = self._features_module.generate_event()
        weight = 0.0
        if feat_ev:
            feats = feat_ev.data
            X = np.array([[
                float(feats.get('packet_count', 0)),
                float(feats.get('total_bytes', 0)),
                float(feats.get('flow_id', 0))
            ]])
            # Neural Net
            if getattr(self._detection_module, 'use_nn', False) and hasattr(self._detection_module, 'nn_model'):
                weight = float(self._detection_module.nn_model.predict(X)[0][0])
            # Isolation Forest
            elif hasattr(self._detection_module, 'if_model'):
                score = float(self._detection_module.if_model.decision_function(X)[0])
                weight = abs(score)
        # Attach and round AI weight
        data['ai_weight'] = round(weight, 2)
        # Timestamp
        from datetime import datetime
        data['timestamp'] = datetime.now().strftime('%H:%M:%S')
        # Store metadata
        self._packet_metas.insert(0, data)
        # Add row and populate values
        self.packets.insertRow(0)

        # Insert into table
        # Map protocol number to name if possible
        proto = data.get('protocol', '')
        try:
            pn = int(proto)
            pname = self.protocols_map.get(pn)
            if pname:
                proto = f'{pname} ({pn})'
        except Exception:
            pass
        vals = [
            str(self._packet_counter),
            data.get('timestamp', ''),
            data.get('src_ip', ''),
            data.get('dst_ip', ''),
            proto,
            str(data.get('payload_size', '')),
            str(data.get('ai_weight', '')),
            ''
        ]
        for i, v in enumerate(vals):
            self.packets.setItem(0, i, QTableWidgetItem(v))

        # Color row
        try:
            w = float(data.get('ai_weight', 0))
            color = QColor(0, 200, 0, 60) if w < 0.5 else QColor(255, 255, 0, 60) if w < 1.5 else QColor(255, 0, 0, 80)
            for c in range(self.packets.columnCount()):
                self.packets.item(0, c).setBackground(color)
        except:
            pass
        # Scroll to newest packet
        self.packets.scrollToItem(self.packets.item(0, 0))
        # Increment packet counter
        self._packet_counter += 1

    def _on_export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Zapisz CSV', '', 'CSV (*.csv)')
        if not path:
            self.log_status('Eksport CSV anulowany')
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Time', 'Src', 'Dst', 'Proto', 'Size', 'AI'])
                for i, m in enumerate(self._packet_metas):
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
        path, _ = QFileDialog.getSaveFileName(self, 'Zapisz PCAP', '', 'PCAP (*.pcap)')
        if not path:
            self.log_status('Eksport PCAP anulowany')
            return
        try:
            pkts = [Ether(m.get('raw_bytes', b'')) for m in self._packet_metas]
            wrpcap(path, pkts)
            self.log_status(f'Zapisano PCAP: {path}')
        except Exception as e:
            self.log_status(f'Błąd zapisu PCAP: {e}')

    def _show_packet_details_inline(self, row, _):
        # Retrieve raw bytes and AI weight
        from scapy.all import Ether
        m = self._packet_metas[row]
        raw = m.get('raw_bytes', b'')
        weight = m.get('ai_weight', 0)
        # Parse layers and fields with safety check
        from scapy.packet import NoPayload
        pkt = Ether(raw)
        lines = [f"AI weight: {weight}\n"]
        layer = pkt
        while layer and not isinstance(layer, NoPayload):
            lines.append(f"== Layer: {layer.name} ==\n")
            # Iterate over fields in this layer
            for field, value in layer.fields.items():
                # Translate protocol numbers if configured
                if field in ('proto', 'type') and isinstance(value, int):
                    pname = self.protocols_map.get(value)
                    if pname:
                        value = f"{pname} ({value})"
                lines.append(f"{field}: {value}\n")
            # Move to next payload
            layer = layer.payload if hasattr(layer, 'payload') else None
        # Set detail view
        self.detail_info.setPlainText(''.join(lines))
        # Hex and ASCII views remain unchanged
        self.hex_view.setPlainText(' '.join(f'{b:02x}' for b in raw))
        self.ascii_view.setPlainText(''.join(chr(b) if 32 <= b < 127 else '.' for b in raw))
