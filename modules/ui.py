
from core.interfaces import ModuleBase

class UIModule(ModuleBase):
	"""
	Moduł interfejsu webowego (Flask dashboard).
	"""
	def initialize(self, config):
		"""Inicjalizuje moduł UI (np. konfiguracja Flask)."""
		self.config = config
		# TODO: inicjalizacja Flask

	def handle_event(self, event):
		"""Obsługuje eventy do wyświetlania w UI."""
		# TODO: obsługa eventów do dashboardu
		pass

	def generate_event(self):
		"""UI nie generuje eventów (szkielet)."""
		return None
