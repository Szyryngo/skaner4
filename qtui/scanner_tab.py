"""Module scanner_tab - description."""
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from PyQt5.QtCore import QTimer, QObject, pyqtSignal, QThread
from qtui.scanner_layout import ScannerLayout
from modules.scanner import ScannerModule
from core.events import Event
from datetime import datetime

# Worker for asynchronous port scanning
def _add_port_scan_worker():
    '''Function _add_port_scan_worker - description.'''
    class PortScanWorker(QObject):
        '''Class PortScanWorker - description.'''
        progress = pyqtSignal(int)
        log = pyqtSignal(str)
        finished = pyqtSignal(list, str)

        def __init__(self, target, ports_list):
            '''Function __init__ - description.'''
            super().__init__()
            self.target = target
            self.ports_list = ports_list

        def run(self):
            '''Function run - description.'''
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
    '''Function _add_discovery_worker - description.'''
    class DiscoveryWorker(QObject):
        '''Class DiscoveryWorker - description.'''
        progress = pyqtSignal(int)
        log = pyqtSignal(str)
        finished = pyqtSignal(list)

        def __init__(self, network):
            '''Function __init__ - description.'''
            super().__init__()
            self.network = network

        def run(self):
            '''Function run - description.'''
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
        '''Function __init__ - description.'''
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
        # Load MAC OUI mapping for manufacturer lookup
        import yaml, os
        mac_cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'mac_devices.yaml'))
        try:
            with open(mac_cfg_path, 'r', encoding='utf-8') as f:
                mac_map = yaml.safe_load(f) or {}
        except Exception:
            mac_map = {}
        # Normalize keys
        self._mac_map = {k.rstrip(':').upper(): v for k, v in mac_map.items()}

        # Connect buttons
        self.ctrls['start_btn'].clicked.connect(self._on_start_scan)
        # Connect optional buttons if available
        if 'save_btn' in self.ctrls:
            self.ctrls['save_btn'].clicked.connect(self._on_save)
        if 'export_btn' in self.ctrls:
            self.ctrls['export_btn'].clicked.connect(self._on_export)
        # Timer for polling scan results
        # self._scan_timer = QTimer(self)
        # self._scan_timer.timeout.connect(self._process_scan_result)
        # self._scan_timer.start(1000)
        # Initial log
        if 'cmd_log' in self.ctrls:
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] ScannerTab initialized")
        self._scan_thread = None
        self._scan_worker = None

    def _on_start_scan(self):
        '''Function _on_start_scan - description.'''
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

        # Uruchom asynchroniczny skan w osobnym wątku
        if scan_type == 'Port Scan':
            self._scan_thread = QThread()
            self._scan_worker = PortScanWorker(target, ports_list)
            self._scan_worker.moveToThread(self._scan_thread)
            self._scan_thread.started.connect(self._scan_worker.run)
            self._scan_worker.progress.connect(self.ctrls['progress_bar'].setValue)
            self._scan_worker.log.connect(lambda msg: self.ctrls['cmd_log'].append(msg))
            self._scan_worker.finished.connect(self._on_port_scan_finished)
            self._scan_worker.finished.connect(self._scan_thread.quit)
            self._scan_thread.start()
        elif scan_type == 'Discovery':
            self._scan_thread = QThread()
            self._scan_worker = DiscoveryWorker(target)
            self._scan_worker.moveToThread(self._scan_thread)
            self._scan_thread.started.connect(self._scan_worker.run)
            self._scan_worker.progress.connect(self.ctrls['progress_bar'].setValue)
            self._scan_worker.log.connect(lambda msg: self.ctrls['cmd_log'].append(msg))
            self._scan_worker.finished.connect(self._on_discovery_finished)
            self._scan_worker.finished.connect(self._scan_thread.quit)
            self._scan_thread.start()
        else:
            # fallback: sync module
            self._scanner_module.handle_event(Event('SCAN_REQUEST', {'type': scan_type, 'target': target,'subtype': subtype,'ports': ports_list}))

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

    def _on_port_scan_finished(self, open_ports, mac):
        '''Handler for PortScanWorker finished signal: update results table.'''
        from PyQt5.QtWidgets import QTableWidgetItem
        tbl = self.ctrls.get('results_table')
        if tbl is None:
            return
        row = tbl.rowCount()
        tbl.insertRow(row)
        # IP is in target_input
        ip = self.ctrls['target_input'].text()
        tbl.setItem(row, 0, QTableWidgetItem(ip))
        # Ports list
        ports_str = ','.join(str(p) for p in open_ports) if open_ports else ''
        tbl.setItem(row, 1, QTableWidgetItem(ports_str))
        # MAC address
        tbl.setItem(row, 2, QTableWidgetItem(mac or ''))
        # Manufacturer lookup
        prefix = ':'.join(mac.split(':')[:3]).upper() if mac else ''
        info = self._mac_map.get(prefix, {})
        producer = info.get('manufacturer', '')
        tbl.setItem(row, 3, QTableWidgetItem(producer))
        # Log completion
        self.ctrls['cmd_log'].append(f"Port scan finished for {ip}: ports={ports_str}, mac={mac}")

    def _on_discovery_finished(self, results):
        '''Handler for DiscoveryWorker finished signal: update results table.'''
        from PyQt5.QtWidgets import QTableWidgetItem
        tbl = self.ctrls.get('results_table')
        if tbl is None or not isinstance(results, list):
            return
        for host in results:
            row = tbl.rowCount()
            tbl.insertRow(row)
            ip = host.get('ip', '')
            mac = host.get('mac', '')
            tbl.setItem(row, 0, QTableWidgetItem(ip))
            tbl.setItem(row, 1, QTableWidgetItem(''))
            tbl.setItem(row, 2, QTableWidgetItem(mac))
            prefix = ':'.join(mac.split(':')[:3]).upper() if mac else ''
            info = self._mac_map.get(prefix, {})
            producer = info.get('manufacturer', '')
            tbl.setItem(row, 3, QTableWidgetItem(producer))
            self.ctrls['cmd_log'].append(f"Discovery finished: {ip} {mac}")

    def _process_scan_result(self):
        '''Function _process_scan_result - description.'''
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
        '''Function _on_preview_ports - description.'''
        # Placeholder for preview ports action
        pass

    def _on_save(self):
        '''Handler for save button: export results to CSV file.'''
        import csv
        from datetime import datetime
        tbl = self.ctrls.get('results_table')
        if tbl is None:
            return
        rows = tbl.rowCount()
        cols = tbl.columnCount()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_results_{timestamp}.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                headers = [tbl.horizontalHeaderItem(c).text() for c in range(cols)]
                writer.writerow(headers)
                for r in range(rows):
                    writer.writerow([tbl.item(r, c).text() if tbl.item(r, c) else '' for c in range(cols)])
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Zapisano wyniki do {filename}")
        except Exception as e:
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Błąd zapisu: {e}")

    def _on_export(self):
        '''Handler for export button: send results to SIEM via ScannerModule.'''
        from core.events import Event
        tbl = self.ctrls.get('results_table')
        if tbl is None:
            return
        data = []
        for r in range(tbl.rowCount()):
            row_data = {}
            for c, key in enumerate(['ip','ports','mac','manufacturer']):
                item = tbl.item(r, c)
                row_data[key] = item.text() if item else ''
            data.append(row_data)
        ev = Event('SIEM_EXPORT', {'results': data})
        self._scanner_module.handle_event(ev)
        from datetime import datetime
        self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Eksport do SIEM: {len(data)} rekordów")
