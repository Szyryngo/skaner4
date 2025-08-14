
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

	def handle_event(self, event):
		"""Obsługuje eventy (np. polecenia z UI)."""
		if event.type == 'SCAN_REQUEST':
			# TODO: rozpocznij skanowanie
			pass

	def generate_event(self):
		"""
		Generuje event SCAN_COMPLETED po zakończeniu skanowania (szkielet).
		"""
		# TODO: implement scan result event
		return None
