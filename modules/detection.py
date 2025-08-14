
from core.interfaces import ModuleBase
from core.events import Event

class DetectionModule(ModuleBase):
	"""
	Moduł AI do detekcji anomalii i klasyfikacji zagrożeń.
	Odbiera NEW_FEATURES, publikuje NEW_THREAT.
	"""
	def initialize(self, config):
		"""Inicjalizuje moduł (ładowanie modeli AI)."""
		self.config = config
		# Przykładowy model IsolationForest do detekcji anomalii
		import os
		from sklearn.ensemble import IsolationForest
		import numpy as np
		self.model_path = os.path.join('data', 'models', 'isolation_forest.joblib')
		try:
			from joblib import load
			self.model = load(self.model_path)
			print(f"[DetectionModule] Załadowano model AI z {self.model_path}")
		except Exception:
			print(f"[DetectionModule] Brak modelu AI, trenuję nowy model...")
			# Trenuj na losowych danych (symulacja, do podmiany na prawdziwe dane)
			X = np.random.normal(0, 1, (100, 3))
			self.model = IsolationForest(contamination=0.1, random_state=42)
			self.model.fit(X)
			from joblib import dump
			os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
			dump(self.model, self.model_path)
			print(f"[DetectionModule] Zapisano nowy model AI do {self.model_path}")

	def handle_event(self, event):
		"""Obsługuje event NEW_FEATURES, wykonuje detekcję AI."""
		if event.type == 'NEW_FEATURES':
			print(f"[DetectionModule] Otrzymano NEW_FEATURES: {event.data}")
			# Wyciągnij cechy do predykcji (przykład: packet_count, total_bytes, flow_id)
			features = event.data
			X = [
				float(features.get('packet_count', 0)),
				float(features.get('total_bytes', 0)),
				float(features.get('flow_id', 0)),
			]
			self._last_features = X
			self._last_features_meta = features

	def generate_event(self):
		"""
		Generuje event NEW_THREAT na podstawie predykcji AI IsolationForest.
		"""
		if hasattr(self, '_last_features'):
			import numpy as np
			X = np.array(self._last_features).reshape(1, -1)
			pred = self.model.predict(X)[0]  # -1 = anomalia, 1 = normalny
			score = self.model.decision_function(X)[0]
			features = self._last_features_meta
			del self._last_features
			del self._last_features_meta
			if pred == -1:
				# Dodaj wagę AI do meta, by GUI mogło ją wyświetlić
				threat = {
					'ip': features.get('src_ip', 'unknown'),
					'threat_type': 'anomaly',
					'confidence': float(-score),
					'ai_weight': float(-score),
					'details': features
				}
				print(f"[DetectionModule] AI wykryło zagrożenie: {threat}")
				return Event('NEW_THREAT', threat)
		return None
