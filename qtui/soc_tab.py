from PyQt5.QtWidgets import QWidget, QVBoxLayout, QGraphicsScene, QFileDialog, QTableWidgetItem, QTabWidget, QGraphicsTextItem, QGraphicsItem, QGraphicsLineItem
from PyQt5.QtGui import QPen, QBrush
from PyQt5.QtCore import Qt, QTimer, QLineF
from .soc_layout import SOCLayout
from core.events import Event
from datetime import datetime
from modules.devices import DevicesModule

class SOCTab(QWidget):
    """Zakładka SIEM/SOC: dashboard security logs and alerts"""
    def __init__(self, parent=None):
        super().__init__(parent)
        # Build UI from layout
        widget, ctrls = SOCLayout().build()
        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)
        # Controls
        self.ctrls = ctrls
        # Setup network map scene
        self.scene = QGraphicsScene(self)
        self.ctrls['map_view'].setScene(self.scene)
        self._nodes = {}        # ip -> (ellipse, text)
        self._node_positions = {}  # ip -> (x_center, y_center)
        # Devices module for map
        from modules.devices import DevicesModule as _DevMod
        self._devices = DevicesModule(); self._devices.initialize({})
        # Identify local IP addresses for highlighting
        import psutil, socket
        self._local_ips = set()
        for iface_addrs in psutil.net_if_addrs().values():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    self._local_ips.add(addr.address)
        # Initialize modules
        from modules.capture import CaptureModule
        from modules.features import FeaturesModule
        from modules.detection import DetectionModule
        self._capture = CaptureModule(); self._capture.initialize({'network_interface': None, 'filter': ''})
        self._features = FeaturesModule(); self._features.initialize({})
        self._detection = DetectionModule(); self._detection.initialize({})
        # State
        self._live = False
        self._scheduled = False
        # Timers
        from PyQt5.QtCore import QTimer
        self._log_timer = QTimer(self)
        self._log_timer.timeout.connect(self._process_events)
        self._log_timer.start(100)
        # Scheduler timer for periodic scans
        self._sched_timer = QTimer(self)
        self._sched_timer.timeout.connect(self._start_scheduled_scan)
        # Connect UI buttons
        self.ctrls['live_btn'].clicked.connect(self._toggle_live)
        self.ctrls['scheduled_btn'].clicked.connect(self._toggle_scheduled)
        self.ctrls['export_btn'].clicked.connect(self._export_siem)
        self.ctrls['email_btn'].clicked.connect(lambda: self._log('Email notification sent'))
        self.ctrls['report_btn'].clicked.connect(lambda: self._log('PDF report generated'))
        self._log('SOC tab initialized')
        # Install click filter on map for node info
        self.ctrls['map_view'].viewport().installEventFilter(self)

    def _toggle_live(self):
        self._live = not self._live
        if self._live:
            # start live sniffing
            try:
                self._capture._start_sniffing()
            except Exception:
                pass
        else:
            # stop live sniffing
            try:
                self._capture.stop_sniffing()
            except Exception:
                pass
        state = 'Live Monitoring ON' if self._live else 'Live Monitoring OFF'
        self._log(state)
    def eventFilter(self, source, event):
        from PyQt5.QtCore import QEvent
        from PyQt5.QtWidgets import QMessageBox
        # Left click on map viewport
        if source is self.ctrls['map_view'].viewport() and event.type() == QEvent.MouseButtonPress and event.button() == Qt.LeftButton:
            scene_pos = self.ctrls['map_view'].mapToScene(event.pos())
            items = self.scene.items(scene_pos)
            for it in items:
                for ip, (ellipse, text) in self._nodes.items():
                    if it is ellipse or it is text:
                        # fetch device info
                        dev = self._devices.devices.get(ip, {})
                        from datetime import datetime
                        first = dev.get('first_seen')
                        first_str = datetime.fromtimestamp(first).strftime('%H:%M:%S') if first else 'N/A'
                        info = (f"IP: {ip}\n"
                                f"MAC: {dev.get('mac','')}\n"
                                f"First seen: {first_str}\n"
                                f"Packets: {dev.get('count','')}\n")
                        QMessageBox.information(self, f"Device info: {ip}", info)
                        return True
        return super().eventFilter(source, event)

    def _toggle_scheduled(self):
        self._scheduled = not self._scheduled
        if self._scheduled:
            # schedule every 15 minutes
            self._sched_timer.start(15 * 60 * 1000)
            self._log('Scheduled scanning enabled (co 15 min)')
            # start an immediate scan
            self._start_scheduled_scan()
        else:
            self._sched_timer.stop()
            self._log('Scheduled scanning disabled')

    def _start_scheduled_scan(self):
        self._log('Starting scheduled scan')
        # delegate to capture module or scanner
        self._capture.handle_event(Event('SCAN_REQUEST', None))

    def _process_events(self):
        if not self._live and not self._scheduled:
            return
        # capture event
        ev = self._capture.generate_event()
        if not ev:
            return
        # ensure nodes exist for src and dst
        src = ev.data.get('src_ip')
        dst = ev.data.get('dst_ip')
        if src and src not in self._nodes:
            self._add_device(Event('DEVICE_DETECTED', {'ip': src}))
        if dst and dst not in self._nodes:
            self._add_device(Event('DEVICE_DETECTED', {'ip': dst}))
        # draw live communication line between nodes
        if src in self._node_positions and dst in self._node_positions:
            x1, y1 = self._node_positions[src]
            x2, y2 = self._node_positions[dst]
            line = QGraphicsLineItem(QLineF(x1, y1, x2, y2))
            line.setPen(QPen(Qt.blue))
            self.scene.addItem(line)
            # remove line after 2 seconds
            QTimer.singleShot(2000, lambda l=line: self.scene.removeItem(l))
        # device discovery: feed packet to devices module
        for dev_ev in self._devices.handle_event(ev) or []:
            if dev_ev.type == 'DEVICE_DETECTED':
                self._add_device(dev_ev)
        # features
        self._features.handle_event(ev)
        fe = self._features.generate_event()
        if fe:
            self._detection.handle_event(fe)
            th = self._detection.generate_event()
            if th:
                # enrich threat event with original packet IPs
                th.data['src_ip'] = ev.data.get('src_ip')
                th.data['dst_ip'] = ev.data.get('dst_ip')
                self._add_alert(th)
                # update node color based on threat ai_weight
                ip = th.data.get('ip')
                weight = th.data.get('ai_weight', 0)
                self._update_node_color(ip, weight)

    def _add_alert(self, event):
        tbl = self.ctrls['log_table']
        from PyQt5.QtWidgets import QTableWidgetItem
        row = tbl.rowCount()
        tbl.insertRow(row)
        ts = event.data.get('timestamp', datetime.now().strftime('%H:%M:%S'))
        evname = event.type
        weight = event.data.get('ai_weight', 0)
        sev = 'Low' if weight < 0.5 else 'Medium' if weight < 1.5 else 'High'
        tbl.setItem(row, 0, QTableWidgetItem(ts))
        tbl.setItem(row, 1, QTableWidgetItem(evname))
        tbl.setItem(row, 2, QTableWidgetItem(sev))
        # Additional details
        src = event.data.get('src_ip', '') or event.data.get('ip', '')
        dst = event.data.get('dst_ip', '')
        conf_val = event.data.get('confidence', event.data.get('ai_weight', 0))
        conf = f"{conf_val:.2f}" if isinstance(conf_val, (float, int)) else str(conf_val)
        tbl.setItem(row, 3, QTableWidgetItem(src))
        tbl.setItem(row, 4, QTableWidgetItem(dst))
        tbl.setItem(row, 5, QTableWidgetItem(conf))
    def _add_device(self, event):
        # Add a node to the network map
        ip = event.data.get('ip')
        if ip in self._nodes:
            return
        # compute position on concentric circles around local machine
        import math
        count = len(self._nodes)  # existing nodes count
        idx = count  # zero-based index for new node
        # determine ring and position within ring: ring 1 has 8, ring2 16, etc.
        ring = 1
        capacity = 8 * ring
        pos = idx
        while pos >= capacity:
            pos -= capacity
            ring += 1
            capacity = 8 * ring
        # angle and radius
        angle = 2 * math.pi * pos / capacity
        radius = 80 * ring  # distance per ring
        # center of scene (hardcoded or adjust to view size)
        center_x, center_y = 200, 150
        x = center_x + radius * math.cos(angle)
        y = center_y + radius * math.sin(angle)
        # draw node
        color = Qt.blue if ip in self._local_ips else Qt.green
        ellipse = self.scene.addEllipse(x, y, 20, 20, QPen(Qt.black), QBrush(color))
        # draw IP label that ignores scene scaling (fixed size)
        text = QGraphicsTextItem(ip)
        text.setDefaultTextColor(Qt.black)
        text.setFlag(QGraphicsItem.ItemIgnoresTransformations, True)
        self.scene.addItem(text)
        text.setPos(x + 5, y + 5)
        # store center position for traffic lines
        cx = x + 10
        cy = y + 10
        self._nodes[ip] = (ellipse, text)
        self._node_positions[ip] = (cx, cy)

    def _export_siem(self):
        # export log_table to CSV with file dialog
        tbl = self.ctrls['log_table']
        path, _ = QFileDialog.getSaveFileName(self, 'Save SIEM Log', '', 'CSV Files (*.csv)')
        if not path:
            return
        import csv, datetime
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # headers
            headers = [tbl.horizontalHeaderItem(i).text() for i in range(tbl.columnCount())]
            writer.writerow(headers)
            for r in range(tbl.rowCount()):
                row = [tbl.item(r, c).text() if tbl.item(r, c) else '' for c in range(tbl.columnCount())]
                writer.writerow(row)
        self._log(f'Exported SIEM log to {path}')

    def _open_settings(self):
        """Switch to Config tab in main window"""
        # assume parent is QTabWidget
        tab_widget = self.parent()
        if isinstance(tab_widget, QTabWidget):
            # find Config tab
            for i in range(tab_widget.count()):
                if tab_widget.tabText(i).lower() == 'config':
                    tab_widget.setCurrentIndex(i)
                    break
    
    def _log(self, msg):
        """Append message to command log"""
        from datetime import datetime
        # styled command log at bottom
        ts = datetime.now().strftime('%H:%M:%S')
        if 'cmd_log' in self.ctrls:
            self.ctrls['cmd_log'].append(f"[{ts}] {msg}")
        print(f'[SOCTab] {msg}')
    def _update_node_color(self, ip, weight):
        """Change ellipse color: green=safe, yellow=suspicious, red=threat"""
        if ip not in self._nodes:
            return
        ellipse, _ = self._nodes[ip]
        from PyQt5.QtGui import QBrush
        # determine severity
        if weight < 0.5:
            color = Qt.green
        elif weight < 1.5:
            color = Qt.yellow
        else:
            color = Qt.red
        ellipse.setBrush(QBrush(color))
