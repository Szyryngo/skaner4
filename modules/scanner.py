
from core.interfaces import ModuleBase
from core.events import Event

class ScannerModule(ModuleBase):
	"""
	Moduł do ręcznego skanowania sieci (light/stealth i full scan).
	Publikuje event SCAN_COMPLETED.
	"""
	def initialize(self, config):
		"""Inicjalizuje moduł (np. parametry skanowania)."""
		self.config = config
		self._scan_requested = False
		self._scan_result = None

	def handle_event(self, event):
		"""Obsługuje eventy (np. polecenia z UI)."""
		if event.type == 'SCAN_REQUEST':
			self._scan_requested = True

	def generate_event(self):
		"""
		Generuje event SCAN_COMPLETED po zakończeniu skanowania (ping sweep na podsieci 192.168.0.0/24).
		"""
		if self._scan_requested:
			self._scan_requested = False
			import platform, subprocess
			base = '192.168.0.'
			found = []
			for i in range(1, 10):  # Skanuj tylko 9 hostów dla szybkości
				ip = f'{base}{i}'
				param = '-n' if platform.system().lower()=='windows' else '-c'
				try:
					result = subprocess.run(['ping', param, '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
					if b'TTL=' in result.stdout or b'ttl=' in result.stdout:
						found.append(ip)
				except Exception:
					pass
			self._scan_result = found
			return Event('SCAN_COMPLETED', {'result': f'Aktywne hosty: {found}'})
		return None
