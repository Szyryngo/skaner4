
from core.interfaces import ModuleBase
from core.events import Event

class FeaturesModule(ModuleBase):
	"""
	Moduł agregujący pakiety w flow i generujący cechy ruchu.
	Odbiera NEW_PACKET, publikuje NEW_FEATURES.
	"""
	def initialize(self, config):
		"""Inicjalizuje moduł (np. parametry agregacji)."""
		self.config = config
		self.flows = {}

	def handle_event(self, event):
		"""Obsługuje event NEW_PACKET, agreguje do flow."""
		if event.type == 'NEW_PACKET':
			# TODO: agregacja pakietu do flow
			pass

	def generate_event(self):
		"""
		Generuje event NEW_FEATURES na podstawie zebranych flow (szkielet).
		"""
		# TODO: implement real feature extraction
		return None
