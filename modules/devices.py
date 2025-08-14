
from core.interfaces import ModuleBase
from core.events import Event

class DevicesModule(ModuleBase):
	"""
	Moduł śledzący urządzenia w sieci na podstawie pakietów ARP/IP.
	Publikuje event DEVICE_DETECTED.
	"""
	def initialize(self, config):
		"""Inicjalizuje moduł (np. parametry monitorowania)."""
		self.config = config
		self.devices = {}

	def handle_event(self, event):
		"""Obsługuje eventy NEW_PACKET do wykrywania urządzeń w sieci."""
		if event.type == 'NEW_PACKET':
			print(f"[DevicesModule] Otrzymano NEW_PACKET: {event.data}")
			ip = event.data.get('src_ip')
			if ip and ip not in self.devices:
				print(f"[DevicesModule] Wykryto nowe urządzenie: {ip}")
				self.devices[ip] = {'last_seen': event.data}
				self._last_detected = ip

	def generate_event(self):
		"""
		Generuje event DEVICE_DETECTED jeśli wykryto nowe urządzenie.
		"""
		if hasattr(self, '_last_detected'):
			ip = self._last_detected
			print(f"[DevicesModule] Generuję DEVICE_DETECTED dla: {ip}")
			del self._last_detected
			return Event('DEVICE_DETECTED', {'ip': ip})
		return None
