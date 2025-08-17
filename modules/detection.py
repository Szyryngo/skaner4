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
        # Path to Isolation Forest model
        self.if_model_path = os.path.join('data', 'models', 'isolation_forest.joblib')
        # Path to neural network model saved by NNLayout
        self.nn_model_path = os.path.join('data', 'models', 'nn_model.keras')
        # Try loading neural network model
        self.use_nn = False
        try:
            import tensorflow as tf
            self.nn_model = tf.keras.models.load_model(self.nn_model_path)
            # Debug: NN model loaded
            self.use_nn = True
        except Exception:
            # Debug: NN model unavailable, falling back to IsolationForest
            pass
        # Load or train Isolation Forest model
        from sklearn.ensemble import IsolationForest
        try:
            from joblib import load
            self.if_model = load(self.if_model_path)
            # Debug: IF model loaded
        except Exception:
            # Debug: IF model missing, training new model
            X0 = np.random.normal(0, 1, (100, 3))
            self.if_model = IsolationForest(contamination=0.1, random_state=42)
            self.if_model.fit(X0)
            from joblib import dump
            os.makedirs(os.path.dirname(self.if_model_path), exist_ok=True)
            dump(self.if_model, self.if_model_path)
            # Debug: New IF model saved

    def handle_event(self, event):
        """Obsługuje event NEW_FEATURES, wykonuje detekcję AI."""
        if event.type == 'NEW_FEATURES':
            # Debug logging disabled
            features = event.data
            X = [float(features.get('packet_count', 0)), float(features.get
                ('total_bytes', 0)), float(features.get('flow_id', 0))]
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
        # Use neural network if enabled and model loaded
        if self.use_nn and hasattr(self, 'nn_model'):
            prob = float(self.nn_model.predict(X)[0][0])
            if prob > 0.5:
                threat = {
                    'ip': features.get('src_ip', 'unknown'),
                    'threat_type': 'anomaly',
                    'confidence': prob,
                    'ai_weight': prob,
                    'details': features
                }
                # Debug: NN detected threat
                return Event('NEW_THREAT', threat)
            return None
        # Fallback to Isolation Forest
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
            # Debug: IF detected threat
            return Event('NEW_THREAT', threat)
        return None
