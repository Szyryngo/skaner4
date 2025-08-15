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
		self.active_hosts = {}  # {ip: last_seen_timestamp}
		self.timeout = 300  # sekundy, po których host uznawany jest za nieaktywny

	def handle_event(self, event):
		"""Obsługuje eventy NEW_PACKET do wykrywania urządzeń w sieci."""
		if event.type == 'NEW_PACKET':
			pkt = event.data
			src_ip = pkt.get("src_ip")
			mac = pkt.get("src_mac")
			now = time.time()
			if src_ip and mac:
				is_new = src_ip not in self.active_hosts
				self.active_hosts[src_ip] = now
				if is_new:
					# Publikuj event DEVICE_DETECTED dla nowego hosta
					yield Event("DEVICE_DETECTED", {"ip": src_ip, "mac": mac, "first_seen": now})

	def generate_event(self):
		"""
		Generuje eventy DEVICE_INACTIVE dla hostów nieaktywnych powyżej timeout.
		"""
		now = time.time()
		# Znajdź hosty nieaktywne
		to_remove = [ip for ip, ts in self.active_hosts.items() if now - ts > self.timeout]
		for ip in to_remove:
			# Usuń z listy aktywnych
			del self.active_hosts[ip]
			# Publikuj event dla nieaktywnego urządzenia
			yield Event('DEVICE_INACTIVE', {'ip': ip})
