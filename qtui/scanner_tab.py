from PyQt5.QtWidgets import QWidget, QVBoxLayout
from PyQt5.QtCore import QTimer, QObject, pyqtSignal, QThread
from qtui.scanner_layout import ScannerLayout
from modules.scanner import ScannerModule
from core.events import Event
from datetime import datetime

# Worker for asynchronous port scanning
def _add_port_scan_worker():
    class PortScanWorker(QObject):
        progress = pyqtSignal(int)
        log = pyqtSignal(str)
        finished = pyqtSignal(list, str)

        def __init__(self, target, ports_list):
            super().__init__()
            self.target = target
            self.ports_list = ports_list

        def run(self):
            import socket, subprocess
            from datetime import datetime
            open_ports = []
            total = len(self.ports_list)
            for idx, port in enumerate(self.ports_list):
                now = datetime.now().strftime('%H:%M:%S')
                self.log.emit(f"[{now}] Skanuję {self.target}:{port}")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    result = s.connect_ex((self.target, port))
                    s.close()
                    if result == 0:
                        open_ports.append(port)
                        self.log.emit(f"[{now}] Port {port} otwarty")
                    else:
                        self.log.emit(f"[{now}] Port {port} zamknięty")
                except Exception as e:
                    self.log.emit(f"[{now}] Błąd skanowania portu {port}: {e}")
                percent = int((idx+1)/total*100)
                self.progress.emit(percent)
            # MAC via ARP
            mac = ''
            try:
                arp = subprocess.run(['arp', '-a', self.target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
                out = arp.stdout.decode(errors='ignore')
                for line in out.splitlines():
                    if self.target in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            mac = parts[1]
                            break
            except:
                pass
            self.progress.emit(100)
            self.finished.emit(open_ports, mac)
    return PortScanWorker
# dynamically inject worker
PortScanWorker = _add_port_scan_worker()

# Worker for asynchronous Discovery (ping sweep) scan
def _add_discovery_worker():
    class DiscoveryWorker(QObject):
        progress = pyqtSignal(int)
        log = pyqtSignal(str)
        finished = pyqtSignal(list)

        def __init__(self, network):
            super().__init__()
            self.network = network

        def run(self):
            import ipaddress, platform, subprocess, socket
            from datetime import datetime
            net = ipaddress.ip_network(self.network, strict=False)
            hosts = list(net.hosts())
            total = len(hosts)
            results = []
            for idx, ip in enumerate(hosts):
                ip_str = str(ip)
                now = datetime.now().strftime('%H:%M:%S')
                self.log.emit(f"[{now}] Ping {ip_str}")
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                reachable = False
                try:
                    res = subprocess.run(['ping', param, '1', ip_str],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
                    if b'TTL=' in res.stdout:
                        reachable = True
                except Exception as e:
                    self.log.emit(f"[{now}] Błąd pingowania {ip_str}: {e}")
                if reachable:
                    mac = ''
                    try:
                        arp = subprocess.run(['arp', '-a', ip_str], stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, timeout=1)
                        out = arp.stdout.decode(errors='ignore')
                        for line in out.splitlines():
                            if ip_str in line:
                                parts = line.split()
                                if len(parts) >= 2:
                                    mac = parts[1]
                                    break
                    except:
                        pass
                    results.append({'ip': ip_str, 'mac': mac})
                    self.log.emit(f"[{now}] Host {ip_str} aktywny")
                percent = int((idx+1)/total*100)
                self.progress.emit(percent)
            self.finished.emit(results)
    return DiscoveryWorker
DiscoveryWorker = _add_discovery_worker()

class ScannerTab(QWidget):
    """Zakładka Scanner: ręczne skanowanie sieci"""
    def __init__(self, parent=None):
        super().__init__(parent)
        # Build UI
        widget, ctrls = ScannerLayout().build()
        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)
        # Controls and scanner module
        self.ctrls = ctrls
        self._scanner_module = ScannerModule()
        self._scanner_module.initialize({})
        # Connect buttons
        self.ctrls['start_btn'].clicked.connect(self._on_start_scan)
        # Connect optional buttons if available
        if 'save_btn' in self.ctrls:
            self.ctrls['save_btn'].clicked.connect(self._on_save)
        if 'export_btn' in self.ctrls:
            self.ctrls['export_btn'].clicked.connect(self._on_export)
        # Timer for polling scan results
        self._scan_timer = QTimer(self)
        self._scan_timer.timeout.connect(self._process_scan_result)
        self._scan_timer.start(1000)
        # Initial log
        if 'cmd_log' in self.ctrls:
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] ScannerTab initialized")

    def _on_start_scan(self):
        scan_type = self.ctrls['scan_type_combo'].currentText()
        target = self.ctrls['target_input'].text()
        subtype = self.ctrls['port_mode_combo'].currentText()

        # Determine ports list
        psel = self.ctrls['port_selection_combo'].currentText()
        # Build ports list
        if psel == 'Własne':
            text = self.ctrls['custom_ports_input'].text()
            ports_list = []
            for part in text.split(','):
                try:
                    ports_list.append(int(part.strip()))
                except ValueError:
                    continue
        elif psel == 'Wszystkie porty':
            # scan ports 1-1024 by default for performance
            ports_list = list(range(1, 1025))
        else:
            try:
                ports_list = [int(psel.split()[0])]
            except Exception:
                ports_list = []

        # Trigger scan
        self._scanner_module.handle_event(
            Event('SCAN_REQUEST', {
                'type': scan_type,
                'target': target,
                'subtype': subtype,
                'ports': ports_list
            })
        )

        # Clear results table
        table = self.ctrls.get('results_table')
        if table:
            table.setRowCount(0)

        # Log start and scan parameters
        if 'cmd_log' in self.ctrls:
            now = datetime.now().strftime('%H:%M:%S')
            self.ctrls['cmd_log'].append(
                f"[{now}] Rozpoczęto {scan_type} na {target} ({subtype})"
            )
            # Log port selection parameters
            psel = self.ctrls['port_selection_combo'].currentText()
            if psel == 'Własne':
                ports = self.ctrls['custom_ports_input'].text()
            elif psel == 'Wszystkie porty':
                ports = 'all'
            else:
                ports = psel
            self.ctrls['cmd_log'].append(
                f"[{now}] Parametry skanowania: zakres={target}, tryb={scan_type}, port_mode={subtype}, porty={ports}"
            )

        # If Port Scan, perform scan immediately with progress and detailed log
        if scan_type == 'Port Scan':
            # Disable polling of generate_event to avoid blocking UI
            self._scan_timer.stop()
            # Start asynchronous port scan
            table = self.ctrls.get('results_table')
            progress = self.ctrls.get('progress_bar')
            if table and progress:
                table.setRowCount(0)
                # Thread and worker setup
                self._scan_thread = QThread(self)
                self._scan_worker = PortScanWorker(target, ports_list)
                self._scan_worker.moveToThread(self._scan_thread)
                # Connect signals
                self._scan_thread.started.connect(self._scan_worker.run)
                self._scan_worker.progress.connect(progress.setValue)
                self._scan_worker.log.connect(lambda msg: self.ctrls['cmd_log'].append(msg))
                def on_finished(open_ports, mac):
                    from PyQt5.QtWidgets import QTableWidgetItem
                    # Populate results
                    table.insertRow(0)
                    table.setItem(0, 0, QTableWidgetItem(target))
                    table.setItem(0, 1, QTableWidgetItem(','.join(map(str, open_ports))))
                    table.setItem(0, 2, QTableWidgetItem(mac))
                    table.setItem(0, 3, QTableWidgetItem(''))
                    # Final log
                    now = datetime.now().strftime('%H:%M:%S')
                    self.ctrls['cmd_log'].append(f"[{now}] Port Scan zakończony: otwarte porty={open_ports}")
                    # Clean up thread
                    self._scan_thread.quit()
                    self._scan_thread.wait()
                self._scan_worker.finished.connect(on_finished)
                # Start thread
                self._scan_thread.start()
            return
        # If Discovery, use DiscoveryWorker in thread
        if scan_type == 'Discovery':
            self._scan_timer.stop()
            progress = self.ctrls.get('progress_bar')
            if progress:
                progress.setValue(0)
            self._disc_thread = QThread(self)
            self._disc_worker = DiscoveryWorker(target)
            self._disc_worker.moveToThread(self._disc_thread)
            # Connect signals
            self._disc_thread.started.connect(self._disc_worker.run)
            self._disc_worker.progress.connect(progress.setValue)
            self._disc_worker.log.connect(lambda msg: self.ctrls['cmd_log'].append(msg))
            def on_disc_finished(results):
                from PyQt5.QtWidgets import QTableWidgetItem
                table = self.ctrls.get('results_table')
                if table:
                    table.setRowCount(0)
                    for row, item in enumerate(results):
                        table.insertRow(row)
                        table.setItem(row, 0, QTableWidgetItem(item['ip']))
                        table.setItem(row, 2, QTableWidgetItem(item.get('mac','')))
                now = datetime.now().strftime('%H:%M:%S')
                self.ctrls['cmd_log'].append(f"[{now}] Discovery zakończony: znaleziono {len(results)} hostów")
                # Clean up
                self._disc_thread.quit()
                self._disc_thread.wait()
                self._scan_timer.start(1000)
            self._disc_worker.finished.connect(on_disc_finished)
            self._disc_thread.start()
            return

    def _process_scan_result(self):
        ev = self._scanner_module.generate_event()
        if ev and ev.type == 'SCAN_COMPLETED':
            results = getattr(self._scanner_module, '_scan_result', [])
            table = self.ctrls.get('results_table')
            if table:
                table.setRowCount(0)
                from PyQt5.QtWidgets import QTableWidgetItem
                # Fill table: ip, scanned ports, mac, vendor
                for row, item in enumerate(results):
                    ip = item.get('ip')
                    ports = item.get('ports', [])
                    mac = item.get('mac', '')
                    table.insertRow(row)
                    table.setItem(row, 0, QTableWidgetItem(str(ip)))
                    table.setItem(row, 1, QTableWidgetItem(','.join(map(str, ports))))
                    table.setItem(row, 2, QTableWidgetItem(mac))
                    table.setItem(row, 3, QTableWidgetItem(''))  # vendor placeholder

            # Log completion
            if 'cmd_log' in self.ctrls:
                self.ctrls['cmd_log'].append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Skanowanie zakończone: {results}"
                )

    def _on_preview_ports(self):
        # Placeholder for preview ports action
        pass

    def _on_save(self):
        # Placeholder for save action
        pass

    def _on_export(self):
        # Placeholder for export to SIEM action
        pass
