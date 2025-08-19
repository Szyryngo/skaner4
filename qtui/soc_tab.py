"""SOC Tab module - coordinate background processing of events and update SOC UI."""
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QGraphicsScene, QFileDialog, QTableWidgetItem, QTabWidget, QGraphicsTextItem, QGraphicsItem, QGraphicsLineItem
from PyQt5.QtGui import QPen, QBrush
from PyQt5.QtCore import Qt, pyqtSlot, QLineF, QTimer
from .soc_layout import SOCLayout
from .radial_layout import RadialLayout
from core.events import Event
from core.device_discovery import discover_and_update
from datetime import datetime
from modules.devices import DevicesModule

class SOCTab(QWidget):
    """User Interface tab for SOC: network map, logs, raw events, AI scores, and charts."""
    def __init__(self, parent=None):
        super().__init__(parent)
        # Build UI
        widget, ctrls = SOCLayout().build()
        self.ctrls = ctrls
        self.raw_table = ctrls['raw_table']
        self.ai_table = ctrls['ai_table']
        self.group_table = ctrls['group_table']
        self.chart_canvas = ctrls['chart_canvas']
        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)
        if 'filter_input' in ctrls:
            ctrls['filter_input'].textChanged.connect(self._on_filter_alerts)
        self.scene = QGraphicsScene(self)
        self.scene.selectionChanged.connect(self._on_node_selected)
        ctrls['map_view'].setScene(self.scene)
        self._radial_layout = RadialLayout(ring_spacing=80, node_radius=10)
        self._static_edges = set()
        # Basic state
        self._snort_plugins = []
        self._live = False
        self._scheduled = False
        self._group_counts = {}
        self._chart_ax = None
        self._focus_ip = None
        self._log('SOC tab initialized')
        self.ctrls['group_table'].setSortingEnabled(True)
        # Defer heavy init to event loop
        QTimer.singleShot(0, self._init_background)

    @pyqtSlot()
    def _on_node_selected(self):
        """Handle node selection events from the scene."""
        # Placeholder: update focus_ip or display details if needed
        selected = self.scene.selectedItems()
        if selected:
            # For example, set focus to the first selected item
            # self._focus_ip = ...
            pass

    def _init_background(self):
        """Deferred initialization: load modules, plugins, start capture, and batch timer."""
        # Initialize modules
        from modules.devices import DevicesModule as _DevMod
        self._devices = _DevMod(); self._devices.initialize({})
        import psutil, socket
        self._local_ips = {a.address for adds in psutil.net_if_addrs().values() for a in adds if a.family == socket.AF_INET}
        from modules.capture import CaptureModule
        from modules.features import FeaturesModule
        from modules.detection import DetectionModule
        from modules.scanner import ScannerModule
        self._capture = CaptureModule(); self._capture.initialize({'network_interface': None, 'filter': ''})
        self._features = FeaturesModule(); self._features.initialize({})
        self._detection = DetectionModule(); self._detection.initialize({'network_interface': None, 'filter': ''})
        self._scanner = ScannerModule(); self._scanner.initialize({})
        # Load plugins
        from core.plugin_loader import load_plugins
        import os
        cfg = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'plugins_config.yaml'))
        pdir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugins'))
        self._snort_plugins = load_plugins(cfg, pdir) or []
        # Start capture
        self._capture._start_sniffer()
        # Batch update timer
        self._update_timer = QTimer(self)
        self._update_timer.timeout.connect(self._process_buffer_batch)
        self._update_timer.start(200)

    @pyqtSlot()
    def _process_buffer_batch(self):
        """Process a batch of events from buffer and update UI."""
        # Fetch batch from persistent buffer
        batch = self._capture.event_buffer.pop_batch(50)
        for ev in batch:
            self._on_raw_event(ev)
            # process AI and threat logic as before
        # Redraw chart if needed
        # ...existing batch UI update code...

    def _toggle_live(self):
        '''Function _toggle_live - description.'''
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
        """
        Handle clicks on the map view: right-click simulates a threat, left-click shows device info with history.
        """
        from PyQt5.QtCore import QEvent, Qt
        from PyQt5.QtWidgets import QMessageBox
        # Only handle mouse press events on the map viewport
        if source is self.ctrls['map_view'].viewport() and event.type() == QEvent.MouseButtonPress:
            # Debug log
            try:
                pos = event.pos()
                self._log(f"eventFilter: MouseButtonPress at view coords {pos}")
            except Exception:
                pass
            # Map to scene coordinates
            scene_pos = self.ctrls['map_view'].mapToScene(event.pos())
            items = self.scene.items(scene_pos)
            for it in items:
                for ip, (ellipse, text) in self._nodes.items():
                    if it is ellipse or it is text:
                        # Right-click handling disabled
                        # if event.button() == Qt.RightButton:
                        #     pass
                        # Left-click: show device info and history
                        if event.button() == Qt.LeftButton:
                            dev = self._devices.devices.get(ip, {})
                            from datetime import datetime
                            first = dev.get('first_seen')
                            first_str = datetime.fromtimestamp(first).strftime('%H:%M:%S') if first else 'N/A'
                            info = (f"IP: {ip}\n"
                                    f"MAC: {dev.get('mac','')}\n"
                                    f"First seen: {first_str}\n"
                                    f"Packets: {dev.get('count','')}\n")
                            # Append history logs
                            logs = self._node_logs.get(ip, [])
                            if logs:
                                info += "\nTraffic history:\n"
                                for ts, evt, details in logs:
                                    info += f"[{ts}] {evt} {details}\n"
                            QMessageBox.information(self, f"Device info: {ip}", info)
                            return True
            # If click was on map but not on a node, consume event
            return True
        # Default handling
        return super().eventFilter(source, event)

    def _toggle_scheduled(self):
        '''Function _toggle_scheduled - description.'''
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
        '''Function _start_scheduled_scan - description.'''
        self._log('Starting scheduled scan')
        # delegate to capture module or scanner
        self._capture.handle_event(Event('SCAN_REQUEST', None))

    @pyqtSlot(object)
    def _on_worker_threat(self, event):
        '''Function _on_worker_threat - description.'''
        # Debug: log invocation and live state
        self._log(f"_on_worker_threat called: live={self._live}, scheduled={self._scheduled}")
        # Only process if live or scheduled
        if not self._live and not self._scheduled:
            return
        # add alert UI and update node color
        self._add_alert(event)
        ip = event.data.get('src_ip') or event.data.get('ip')
        weight = event.data.get('ai_weight', 0)
        if ip:
            # ensure node exists (create if missing)
            if ip not in self._nodes:
                # add device node without MAC
                from core.events import Event
                self._add_device(Event('DEVICE_DETECTED', {'ip': ip, 'mac': ''}))
            self._log(f"_on_worker_threat: updating node {ip} with weight {weight}")
            # Uwzględnij typ zdarzenia by pokolorować węzeł właściwie
            self._update_node_color(ip, weight, event.type)
    
    @pyqtSlot(object)
    def _on_raw_event(self, ev):
        '''Function _on_raw_event - description.'''
        # Only process if live or scheduled
        if not self._live and not self._scheduled:
            return
        # Debug log raw event
        # Obsługa surowego pakietu
        src = ev.data.get('src_ip')
        dst = ev.data.get('dst_ip')
        src_mac = ev.data.get('src_mac')
        dst_mac = ev.data.get('dst_mac')
        self._log(f"Raw packet event: {src} -> {dst}")
        # Log raw packet to per-node logs
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S')
        # Update source node weight and color if exists
        if src in self._nodes:
            self._node_weights[src] = self._node_weights.get(src, 0) + 1
            self._update_node_color(src, self._node_weights[src])
        # Update destination node weight and color if exists
        if dst in self._nodes:
            self._node_weights[dst] = self._node_weights.get(dst, 0) + 1
            self._update_node_color(dst, self._node_weights[dst])
        # Draw line between nodes
        if src in self._node_positions and dst in self._node_positions:
            x1, y1 = self._node_positions[src]
            x2, y2 = self._node_positions[dst]
            line = QGraphicsLineItem(QLineF(x1, y1, x2, y2))
            line.setPen(QPen(Qt.blue))
            self.scene.addItem(line)
            # remove after 2s
            QTimer.singleShot(2000, lambda l=line: self.scene.removeItem(l))

        # Populate Raw Events table
        tbl = self.raw_table
        if tbl is not None:
            tbl.insertRow(0)
            tbl.setItem(0, 0, QTableWidgetItem(ts))
            tbl.setItem(0, 1, QTableWidgetItem(src or ''))
            tbl.setItem(0, 2, QTableWidgetItem(dst or ''))
            tbl.setItem(0, 3, QTableWidgetItem('RAW_PACKET'))

    def _add_alert(self, event):
        '''Function _add_alert - description.'''
        # find alert table widget
        tbl = self.ctrls.get('log_table') or self.ctrls.get('alert_table')
        if tbl is None:
            # Debug log instead of printing to stdout
            self._log(f"_add_alert: no log_table/alert_table found, ctrls keys={list(self.ctrls.keys())}")
            return
        from PyQt5.QtWidgets import QTableWidgetItem
        from datetime import datetime
        # Insert new alert at top so newest entries appear first
        tbl.insertRow(0)
        ts = event.data.get('timestamp', datetime.now().strftime('%H:%M:%S'))
        evname = event.type
        weight = event.data.get('ai_weight', 0)
        sev = 'Low' if weight < 0.5 else 'Medium' if weight < 1.5 else 'High'
        # Fill alert row
        tbl.setItem(0, 0, QTableWidgetItem(ts))
        tbl.setItem(0, 1, QTableWidgetItem(evname))
        tbl.setItem(0, 2, QTableWidgetItem(sev))
        src = event.data.get('src_ip', '') or event.data.get('ip', '')
        dst = event.data.get('dst_ip', '')
        conf_val = event.data.get('confidence', event.data.get('ai_weight', 0))
        conf = f"{conf_val:.2f}" if isinstance(conf_val, (float, int)) else str(conf_val)
        tbl.setItem(0, 3, QTableWidgetItem(src))
        tbl.setItem(0, 4, QTableWidgetItem(dst))
        tbl.setItem(0, 5, QTableWidgetItem(conf))
        # Update summary counts
        low = sum(1 for r in range(tbl.rowCount()) if tbl.item(r,2).text() == 'Low')
        med = sum(1 for r in range(tbl.rowCount()) if tbl.item(r,2).text() == 'Medium')
        high = sum(1 for r in range(tbl.rowCount()) if tbl.item(r,2).text() == 'High')
        self.ctrls['low_label'].setText(f"Low: {low}")
        self.ctrls['medium_label'].setText(f"Medium: {med}")
        self.ctrls['high_label'].setText(f"High: {high}")
        # Highlight blacklisted IPs in alerts
        from PyQt5.QtGui import QColor
        import ipaddress
        src = event.data.get('src_ip', '')
        dst = event.data.get('dst_ip', '')
        def is_black(ip_str):
            '''Function is_black - description.'''
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                return any(ip_obj in net for net in self._blacklist)
            except Exception:
                return False
        if is_black(src) or is_black(dst):
            # color entire row red background
            for c in range(tbl.columnCount()):
                item = tbl.item(0, c)
                if item:
                    item.setBackground(QColor('#ffcccc'))
        # Zaawansowane powiadomienia: e-mail jeśli AI weight przekracza threshold
        try:
            if float(weight) >= float(self._notif_threshold) and self._smtp_server and self._email_recipients:
                self._send_email_notification(event)
        except Exception:
            pass
        # Update group counts by source IP
        src_ip = event.data.get('src_ip') or event.data.get('ip')
        if src_ip:
            self._group_counts[src_ip] = self._group_counts.get(src_ip, 0) + 1
            # Update group_table widget
            grp_tbl = self.ctrls.get('group_table')
            if grp_tbl:
                # find existing row
                found = False
                for r in range(grp_tbl.rowCount()):
                    if grp_tbl.item(r,0).text() == src_ip:
                        grp_tbl.setItem(r,1, QTableWidgetItem(str(self._group_counts[src_ip])))
                        found = True
                        break
                if not found:
                    grp_tbl.insertRow(0)
                    grp_tbl.setItem(0,0, QTableWidgetItem(src_ip))
                    grp_tbl.setItem(0,1, QTableWidgetItem(str(self._group_counts[src_ip])))
        # Update severity chart
        if hasattr(self, '_chart_ax') and self._chart_ax:
            try:
                self._chart_ax.clear()
                self._chart_ax.bar(['Low','Medium','High'], [low,med,high], color=['green','yellow','red'])
                self.ctrls.get('chart_canvas').draw()
            except Exception:
                pass

    def _add_device(self, event):
        '''Function _add_device - description.'''
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
        # draw node with default gray color
        from PyQt5.QtGui import QColor, QBrush
        default_color = QColor('lightgray')
        ellipse = self.scene.addEllipse(x, y, 20, 20, QPen(Qt.black), QBrush(default_color))
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
        # Label with MAC vendor and device type if available
        mac = event.data.get('mac')
        if mac:
            prefix = ':'.join(mac.split(':')[:3]).upper()
            dev_info = self._mac_map.get(prefix, {})
            vendor = dev_info.get('manufacturer', '')
            dev_type = dev_info.get('type', '')
            if vendor or dev_type:
                label = f"{ip}\n{vendor} {dev_type}".strip()
                text.setPlainText(label)

    def _export_siem(self):
        """Eksportuj logi SOC do pliku CSV lub innego formatu."""
        from PyQt5.QtWidgets import QFileDialog
        from datetime import datetime
        default_name = f"soc_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(self, 'Zapisz logi SIEM', default_name, 'CSV (*.csv);;JSON (*.json)')
        if not path:
            self._log('Eksport SIEM anulowany')
            return
        # Prosty CSV
        if path.lower().endswith('.csv'):
            import csv
            tbl = self.ctrls['log_table']
            try:
                with open(path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # header
                    headers = [tbl.horizontalHeaderItem(i).text() for i in range(tbl.columnCount())]
                    writer.writerow(headers)
                    for r in range(tbl.rowCount()):
                        row = [tbl.item(r,i).text() for i in range(tbl.columnCount())]
                        writer.writerow(row)
                self._log(f'Zapisano logi SIEM: {path}')
            except Exception as e:
                self._log(f'Błąd zapisu SIEM CSV: {e}')
        else:
            # Placeholder for JSON eksport
            try:
                import json
                tbl = self.ctrls['log_table']
                data = []
                for r in range(tbl.rowCount()):
                    data.append({tbl.horizontalHeaderItem(c).text(): tbl.item(r,c).text() for c in range(tbl.columnCount())})
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                self._log(f'Zapisano logi SIEM JSON: {path}')
            except Exception as e:
                self._log(f'Błąd zapisu SIEM JSON: {e}')
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
    # Removed stdout printing to avoid lock issues on shutdown
    def _update_node_color(self, ip, weight, event_type=None):
        """Update the color of a node ellipse based on severity weight or event type."""
        nodes = self._nodes.get(ip)
        if not nodes:
            return
        ellipse, _ = nodes
        from PyQt5.QtGui import QBrush, QColor
        # Determine color thresholds: Low (<0.5)=green, Medium (<1.5)=yellow, High=red
        try:
            w = float(weight)
        except Exception:
            w = 0.0
        # Określ kolor: nowe zagrożenia zawsze czerwone, RAW_PACKET zawsze zielone, dalej wg progów
        # Kolor wg skumulowanej wagi: High>=2=red, Medium>=1=yellow, Low>0=green, else gray
        if w >= 2:
            color = QColor('red')
        elif w >= 1:
            color = QColor('yellow')
        elif w > 0:
            color = QColor('green')
        else:
            color = QColor('lightgray')
        ellipse.setBrush(QBrush(color))
        # Update tooltip with last few events
        logs = self._node_logs.get(ip, [])
        # Take up to last 3 entries
        tooltip_lines = []
        for ts, ev, details in logs[-3:]:
            tooltip_lines.append(f"{ts} {ev}: {details}")
        tooltip_text = "\n".join(tooltip_lines)
        ellipse.setToolTip(tooltip_text)
    
    def _send_email_notification(self, event):
        """Send email notification for SOC event if threshold exceeded."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from datetime import datetime
            # Prepare message content
            ts = event.data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            evname = event.type
            weight = event.data.get('ai_weight', 0)
            src = event.data.get('src_ip', '') or event.data.get('ip', '')
            dst = event.data.get('dst_ip', '')
            body = (f"Time: {ts}\n"
                    f"Event: {evname}\n"
                    f"AI Weight: {weight}\n"
                    f"Source IP: {src}\n"
                    f"Destination IP: {dst}\n")
            msg = MIMEText(body)
            msg['Subject'] = f"SOC Alert: {evname} (Weight {weight})"
            sender = self._smtp_user or f"no-reply@{self._smtp_server}"
            msg['From'] = sender
            msg['To'] = ','.join(self._email_recipients)
            # Connect to SMTP server
            server = smtplib.SMTP(self._smtp_server, self._smtp_port)
            server.ehlo()
            if self._smtp_user and self._smtp_pass:
                server.starttls()
                server.login(self._smtp_user, self._smtp_pass)
            server.sendmail(sender, self._email_recipients, msg.as_string())
            server.quit()
            self._log(f"Email sent to {msg['To']}: {evname}, weight {weight}")
        except Exception as e:
            self._log(f"Failed to send email notification: {e}")

    def _on_filter_alerts(self, text):
        """Filtruj wyświetlane alerty w tabeli zgodnie z wpisanym tekstem."""
        tbl = self.ctrls.get('log_table')
        if not tbl:
            return
        filter_text = text.lower()
        for r in range(tbl.rowCount()):
            row_matches = False
            for c in range(tbl.columnCount()):
                item = tbl.item(r, c)
                if item and filter_text in item.text().lower():
                    row_matches = True
                    break
            tbl.setRowHidden(r, not row_matches)

    @pyqtSlot(object)
    def _on_ai_score(self, event):
        '''Function _on_ai_score - description.'''
        # Handle continuous AI scoring per packet
        if not self._live and not self._scheduled:
            return
        ip = event.data.get('src_ip') or event.data.get('ip')
        weight = event.data.get('ai_weight', 0)
        if ip:
            # Ensure node exists
            if ip not in self._nodes:
                from core.events import Event
                self._add_device(Event('DEVICE_DETECTED', {'ip': ip, 'mac': ''}))
            # Update node color based on AI weight
            self._update_node_color(ip, weight, event.type)

        # Populate AI Scores table
        tbl_ai = self.ai_table
        if tbl_ai is not None:
            from datetime import datetime
            ts_ai = datetime.now().strftime('%H:%M:%S')
            tbl_ai.insertRow(0)
            tbl_ai.setItem(0, 0, QTableWidgetItem(ts_ai))
            tbl_ai.setItem(0, 1, QTableWidgetItem(ip or ''))
            dst_ip = event.data.get('dst_ip', '')
            tbl_ai.setItem(0, 2, QTableWidgetItem(dst_ip))
            tbl_ai.setItem(0, 3, QTableWidgetItem(f"{weight:.2f}"))
            tbl_ai.setItem(0, 4, QTableWidgetItem(event.type))
