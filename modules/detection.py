
from core.interfaces import ModuleBase
from core.events import Event

class DetectionModule(ModuleBase):
	"""
	Moduł AI do detekcji anomalii i klasyfikacji zagrożeń.
	Odbiera NEW_FEATURES, publikuje NEW_THREAT.
	"""
	def initialize(self, config):
		"""Inicjalizuje moduł (np. ładowanie modeli AI)."""
		self.config = config
		# TODO: załaduj modele AI

	def handle_event(self, event):
		"""Obsługuje event NEW_FEATURES, wykonuje detekcję i loguje do konsoli."""
		if event.type == 'NEW_FEATURES':
			print(f"[DetectionModule] Otrzymano NEW_FEATURES: {event.data}")
			self._last_features = event.data

	def generate_event(self):
		"""
		Generuje event NEW_THREAT na podstawie ostatnich cech (symulacja zagrożenia co drugi event).
		"""
		if hasattr(self, '_last_features'):
			threat = {'ip': '192.168.0.2', 'threat_type': 'test', 'confidence': 0.9}
			print(f"[DetectionModule] Generuję NEW_THREAT: {threat}")
			del self._last_features
			return Event('NEW_THREAT', threat)
		return None
