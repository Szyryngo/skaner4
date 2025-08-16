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
        # devices: mapping ip -> {'mac': mac, 'count': packet_count, 'last_seen': timestamp}
        self.devices = {}
        # active_hosts: mapping ip -> last seen timestamp for timeout logic
        self.active_hosts = {}
        # timeout (seconds) for marking hosts inactive
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
                # update last seen timestamp for timeout logic
                self.active_hosts[src_ip] = now
                if is_new:
                    # first time seen; initialize device record
                    self.devices[src_ip] = {'mac': mac, 'count': 1, 'last_seen': now}
                    yield Event('DEVICE_DETECTED', {'ip': src_ip, 'mac': mac, 'first_seen': now})
                else:
                    # update existing device record
                    info = self.devices.get(src_ip, {})
                    info['count'] = info.get('count', 0) + 1
                    info['last_seen'] = now
                    self.devices[src_ip] = info

    def generate_event(self):
        """
		Generuje eventy DEVICE_INACTIVE dla hostów nieaktywnych powyżej timeout.
		"""
        now = time.time()
        to_remove = [ip for ip, ts in self.active_hosts.items() if now - ts > self.timeout]
        for ip in to_remove:
            # remove inactive host
            del self.active_hosts[ip]
            if ip in self.devices:
                del self.devices[ip]
            yield Event('DEVICE_INACTIVE', {'ip': ip})
