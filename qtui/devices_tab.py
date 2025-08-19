"""Module devices_tab - description."""
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTableWidgetItem  
from PyQt5.QtCore import QTimer  
from modules.capture import CaptureModule  
from modules.devices import DevicesModule  
from datetime import datetime
import ipaddress
from scapy.all import arping, Ether
import psutil, ipaddress, socket
import yaml, os

from qtui.devices_layout import DevicesLayout

class DevicesTab(QWidget):
    """Zakładka Devices: lista żywych urządzeń"""
    def __init__(self, parent=None, auto_timer=False):
        '''Function __init__ - description.'''
        super().__init__(parent)
        # Build UI
        widget, ctrls = DevicesLayout().build()
        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)
        self.ctrls = ctrls
        # Initial log load
        if 'cmd_log' in self.ctrls:
            self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Urządzenia załadowane")
        # Load MAC OUI mapping
        mac_cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'mac_devices.yaml'))
        try:
            with open(mac_cfg_path, 'r', encoding='utf-8') as f:
                mac_map = yaml.safe_load(f) or {}
        except Exception:
            mac_map = {}
        self._mac_map = {k.rstrip(':').upper(): v for k, v in mac_map.items()}
        # Connect refresh button if available
        if 'refresh_btn' in self.ctrls:
            self.ctrls['refresh_btn'].clicked.connect(self._on_refresh)
        # Initialize capture and devices modules
        self._capture = CaptureModule()
        self._capture.initialize({'network_interface': None, 'filter': ''})
        self._devices_module = DevicesModule()
        self._devices_module.initialize({})
        # Optionally start sniffing and polling if enabled
        self._device_timer = None
        if auto_timer:
            try:
                self._capture._start_sniffer()
            except Exception:
                pass
            self._device_timer = QTimer(self)
            self._device_timer.timeout.connect(self._process_device_events)
            self._device_timer.start(1000)
    def __del__(self):
        """Cleanup timer on deletion to avoid running timers in tests."""
        try:
            self._device_timer.stop()
        except Exception:
            pass

    def _process_device_events(self):
        """Poll capture and devices module for new events, update UI table and log."""
        events = []
        # Process incoming packet events
        pkt_event = self._capture.generate_event()
        if pkt_event:
            result = self._devices_module.handle_event(pkt_event)
            if result:
                try:
                    for e in result:
                        events.append(e)
                except TypeError:
                    events.append(result)
        # Always check for inactivity/timeouts
        gen_evt = self._devices_module.generate_event()
        if gen_evt:
            try:
                for e in gen_evt:
                    events.append(e)
            except TypeError:
                events.append(gen_evt)
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
                ts = e.data.get('first_seen', None)
                time_str = datetime.fromtimestamp(ts).strftime('%H:%M:%S') if ts else ''
                # Safely get device count
                devices_dict = getattr(self._devices_module, 'devices', {})
                count = devices_dict.get(ip, {}).get('count', 1)
                row = self.ctrls['devices'].rowCount()
                self.ctrls['devices'].insertRow(row)
                self.ctrls['devices'].setItem(row, 0, QTableWidgetItem(ip))
                self.ctrls['devices'].setItem(row, 1, QTableWidgetItem(mac))
                self.ctrls['devices'].setItem(row, 2, QTableWidgetItem(time_str))
                self.ctrls['devices'].setItem(row, 3, QTableWidgetItem(str(count)))
                self.ctrls['devices'].setItem(row, 4, QTableWidgetItem('Active'))
                # Identify device type by MAC OUI
                oui = ':'.join(mac.split(':')[:3]).upper()
                info = self._mac_map.get(oui, {})
                dtype = f"{info.get('manufacturer','Unknown')} ({info.get('type','Unknown')})"
                self.ctrls['devices'].setItem(row, 5, QTableWidgetItem(dtype))
                self.ctrls['cmd_log'].append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Wykryto urządzenie: {ip} {mac}"
                )
            elif e.type == 'DEVICE_INACTIVE':
                ip = e.data['ip']
                tbl = self.ctrls['devices']
                for r in range(tbl.rowCount()):
                    item = tbl.item(r, 0)
                    if item and item.text() == ip:
                        tbl.removeRow(r)
                        self.ctrls['cmd_log'].append(
                            f"[{datetime.now().strftime('%H:%M:%S')}] Urządzenie nieaktywne: {ip}"
                        )
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
            # MAC OUI lookup
            mac_oui = self._mac_map.get(mac.upper(), 'Nieznany')
            tbl.setItem(row, 5, QTableWidgetItem(mac_oui))  
            # Identify device type by MAC OUI
            prefix = ':'.join(mac.split(':')[:3]).upper()
            info = self._mac_map.get(prefix, {})
            dtype = f"{info.get('manufacturer','Unknown')} ({info.get('type','Unknown')})"
            tbl.setItem(row, 6, QTableWidgetItem(dtype))
        self.ctrls['cmd_log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] ARP scan zakończony, znaleziono {len(ans)} urządzeń")
