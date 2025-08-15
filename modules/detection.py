from core.interfaces import ModuleBase
from core.events import Event
import os
import numpy as np

class DetectionModule(ModuleBase):
	"""
	Moduł AI do detekcji anomalii i klasyfikacji zagrożeń.
	Odbiera NEW_FEATURES, publikuje NEW_THREAT.
	"""
	def initialize(self, config):
		"""Inicjalizuje moduł (ładowanie modeli AI)."""
		self.config = config
		# Paths to models
		self.if_model_path = os.path.join('data', 'models', 'isolation_forest.joblib')
		self.nn_model_path = os.path.join('data', 'models', 'nn_model.h5')
		# Try to load neural network model if available
		self.use_nn = False
		# Dynamic import to load NN model if TensorFlow is installed
		try:
			tf = __import__('tensorflow')
			self.nn_model = tf.keras.models.load_model(self.nn_model_path)
			print(f"[DetectionModule] Załadowano model NN z {self.nn_model_path}")
			self.use_nn = True
		except Exception:
			print(f"[DetectionModule] Brak modelu NN lub brak TensorFlow, będzie używany IsolationForest")
		# Load or train IsolationForest
		from sklearn.ensemble import IsolationForest
		try:
			from joblib import load
			self.if_model = load(self.if_model_path)
			print(f"[DetectionModule] Załadowano model IF z {self.if_model_path}")
		except Exception:
			print(f"[DetectionModule] Brak modelu IF, trenuję nowy model...")
			X0 = np.random.normal(0, 1, (100, 3))
			self.if_model = IsolationForest(contamination=0.1, random_state=42)
			self.if_model.fit(X0)
			from joblib import dump
			os.makedirs(os.path.dirname(self.if_model_path), exist_ok=True)
			dump(self.if_model, self.if_model_path)
			print(f"[DetectionModule] Zapisano nowy model IF do {self.if_model_path}")

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
		Generuje event NEW_THREAT na podstawie predykcji AI (NN lub IF).
		"""
		if not hasattr(self, '_last_features'):
			return None
		X = np.array(self._last_features).reshape(1, -1)
		features = self._last_features_meta
		del self._last_features
		del self._last_features_meta
		# Use NN model if loaded
		if self.use_nn:
			prob = float(self.nn_model.predict(X)[0][0])
			if prob > 0.5:
				threat = {
					'ip': features.get('src_ip', 'unknown'),
					'threat_type': 'anomaly',
					'confidence': prob,
					'ai_weight': prob,
					'details': features
				}
				print(f"[DetectionModule] NN wykryło zagrożenie: {threat}")
				return Event('NEW_THREAT', threat)
			return None
		# Fallback to IsolationForest
		pred = self.if_model.predict(X)[0]
		score = self.if_model.decision_function(X)[0]
		if pred == -1:
			threat = {
				'ip': features.get('src_ip', 'unknown'),
				'threat_type': 'anomaly',
				'confidence': float(-score),
				'ai_weight': float(-score),
				'details': features
			}
			print(f"[DetectionModule] IF wykryło zagrożenie: {threat}")
			return Event('NEW_THREAT', threat)
		return None
