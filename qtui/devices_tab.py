from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTableWidgetItem  
from PyQt5.QtCore import QTimer  
from modules.capture import CaptureModule  
from modules.devices import DevicesModule  
from datetime import datetime
import ipaddress
from scapy.all import arping, Ether
import psutil, ipaddress, socket

from qtui.devices_layout import DevicesLayout

class DevicesTab(QWidget):
    """Zakładka Devices: lista żywych urządzeń"""
    def __init__(self, parent=None):
        super().__init__(parent)
        widget, ctrls = DevicesLayout().build()
        # Osadź zbudowany widget wewnątrz tej zakładki
        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)
        # Zapamiętaj kontrolki dla ewentualnego użycia i wiringu
        self.ctrls = ctrls
        # Add default log wiring for device detection controls
        if 'refresh_btn' in self.ctrls:
            self.ctrls['refresh_btn'].clicked.connect(self._on_refresh)
        if 'cmd_log' in self.ctrls:
            # Log initial load
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Urządzenia załadowane")  
        
        # Initialize capture and devices modules for live updates  
        self._capture = CaptureModule()  
        self._capture.initialize({'network_interface': None, 'filter': ''})  
        # Detect active interface for device sniffing  
        try:  
            test_results = self._capture.test_all_interfaces()  
            active_iface = next((iface for iface, cnt in test_results.items() if isinstance(cnt, int) and cnt > 0), None)  
            if active_iface:  
                self._capture.set_interface(active_iface)  
                self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Aktywny interfejs: {active_iface}")  
            else:  
                self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Brak ruchu na interfejsach")  
        except Exception as e:  
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Błąd testu interfejsów: {e}")  
        # Start sniffing on detected (or default) interface  
        self._capture._start_sniffing()  
        self._devices_module = DevicesModule()  
        self._devices_module.initialize({})  
        # Timer to poll for new device events  
        self._device_timer = QTimer(self)  
        self._device_timer.timeout.connect(self._process_device_events)  
        self._device_timer.start(1000)  

    def _process_device_events(self):  
        """Poll capture and devices module for new events, update UI table and log."""  
        # Process incoming packets  
        pkt_event = self._capture.generate_event()  
        if pkt_event:  
            # Feed to devices module  
            result = self._devices_module.handle_event(pkt_event)  
            events = []  
            if result:  
                try:  
                    for e in result:  
                        events.append(e)  
                except TypeError:  
                    events.append(result)  
            # Also check for timeouts  
            for e in self._devices_module.generate_event():  
                events.append(e)  
            # Handle each event  
            for e in events:  
                if e.type == 'DEVICE_DETECTED':  
                    ip = e.data['ip']  
                    # only show private LAN addresses
                    try:
                        if not ipaddress.ip_address(ip).is_private:
                            continue
                    except Exception:
                        pass
                    mac = e.data['mac']  
                    ts = e.data['first_seen']  
                    time_str = datetime.fromtimestamp(ts).strftime('%H:%M:%S')  
                    count = self._devices_module.devices.get(ip, {}).get('count', 1)  
                    row = self.ctrls['devices'].rowCount()  
                    self.ctrls['devices'].insertRow(row)  
                    self.ctrls['devices'].setItem(row, 0, QTableWidgetItem(ip))  
                    self.ctrls['devices'].setItem(row, 1, QTableWidgetItem(mac))  
                    self.ctrls['devices'].setItem(row, 2, QTableWidgetItem(time_str))  
                    self.ctrls['devices'].setItem(row, 3, QTableWidgetItem(str(count)))  
                    self.ctrls['devices'].setItem(row, 4, QTableWidgetItem('Active'))  
                    self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Wykryto urządzenie: {ip} {mac}")  
                elif e.type == 'DEVICE_INACTIVE':  
                    ip = e.data['ip']  
                    # Remove from table  
                    tbl = self.ctrls['devices']  
                    for r in range(tbl.rowCount()):  
                        item = tbl.item(r, 0)  
                        if item and item.text() == ip:  
                            tbl.removeRow(r)  
                            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Urządzenie nieaktywne: {ip}")  
                            break

    def _on_refresh(self):
        """Perform ARP scan on the network of the selected interface and update the table."""
        tbl = self.ctrls['devices']
        # Clear existing rows
        tbl.setRowCount(0)
        # Determine active interface
        iface = self._capture.config.get('network_interface')
        # Find IPv4 address and netmask
        addrs = psutil.net_if_addrs().get(iface, [])
        ipv4 = next((a for a in addrs if a.family == socket.AF_INET), None)
        if not ipv4:
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Nie można pobrać adresu IPv4 dla interfejsu {iface}")
            return
        network = ipaddress.IPv4Network(f"{ipv4.address}/{ipv4.netmask}", strict=False)
        try:
            ans, _ = arping(str(network), iface=iface, timeout=2, verbose=False)
        except Exception as e:
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Błąd ARP scan: {e}")
            return
        for _, rcv in ans:
            ip = rcv.psrc
            # only include private LAN
            try:
                if not ipaddress.ip_address(ip).is_private:
                    continue
            except Exception:
                pass
            mac = rcv.hwsrc
            ts = datetime.now().strftime('%H:%M:%S')
            row = tbl.rowCount()
            tbl.insertRow(row)
            tbl.setItem(row, 0, QTableWidgetItem(ip))
            tbl.setItem(row, 1, QTableWidgetItem(mac))
            tbl.setItem(row, 2, QTableWidgetItem(ts))
            tbl.setItem(row, 3, QTableWidgetItem('1'))
            tbl.setItem(row, 4, QTableWidgetItem('Active'))
        self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] ARP scan zakończony, znaleziono {len(ans)} urządzeń")
