from scapy.all import sniff, ARP, IP
from core.events import Event
import threading

class DevicesSniffer:
    def __init__(self, iface=None, event_callback=None):
        self.iface = iface
        self.event_callback = event_callback  # Funkcja do publikowania eventów
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _sniff_loop(self):
        sniff(
            iface=self.iface,
            filter="arp or ip",
            prn=self._handle_packet,
            store=0,
            stop_filter=lambda x: self._stop.is_set()
        )

    def _handle_packet(self, pkt):
        if ARP in pkt:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            event = Event('DEVICE_DETECTED', {'ip': ip, 'mac': mac, 'proto': 'ARP'})
            if self.event_callback:
                self.event_callback(event)
        elif IP in pkt:
            ip = pkt[IP].src
            event = Event('DEVICE_DETECTED', {'ip': ip, 'proto': 'IP'})
            if self.event_callback:
                self.event_callback(event)
