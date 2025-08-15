from core.interfaces import ModuleBase
from core.events import Event
import time


class DevicesModule(ModuleBase):
    """
	Moduł śledzący urządzenia w sieci na podstawie pakietów ARP/IP.
	Publikuje event DEVICE_DETECTED.
	"""

    def initialize(self, config):
        """Inicjalizuje moduł (np. parametry monitorowania)."""
        self.config = config
        self.devices = {}
        self.active_hosts = {}
        self.timeout = 300

    def handle_event(self, event):
        """Obsługuje eventy NEW_PACKET do wykrywania urządzeń w sieci."""
        if event.type == 'NEW_PACKET':
            pkt = event.data
            src_ip = pkt.get('src_ip')
            mac = pkt.get('src_mac')
            now = time.time()
            if src_ip and mac:
                is_new = src_ip not in self.active_hosts
                self.active_hosts[src_ip] = now
                if is_new:
                    yield Event('DEVICE_DETECTED', {'ip': src_ip, 'mac':
                        mac, 'first_seen': now})

    def generate_event(self):
        """
		Generuje eventy DEVICE_INACTIVE dla hostów nieaktywnych powyżej timeout.
		"""
        now = time.time()
        to_remove = [ip for ip, ts in self.active_hosts.items() if now - ts >
            self.timeout]
        for ip in to_remove:
            del self.active_hosts[ip]
            yield Event('DEVICE_INACTIVE', {'ip': ip})
