"""Detection Module - detect anomalies and classify threats using AI models and Snort rules.

This module loads TensorFlow neural network and Isolation Forest models,
integrates with SnortRulesPlugin to track rule matches, processes NEW_FEATURES and SNORT_ALERT events,
and emits NEW_THREAT events when a threat is detected."""
from core.interfaces import ModuleBase
from core.events import Event
import os
import numpy as np
from plugins.snort_rules_plugin import SnortRulesPlugin


class DetectionModule(ModuleBase):
    """AI-based module for threat detection and classification.

    Listens for SNORT_ALERT to record rule matches and NEW_FEATURES to perform AI inference.
    Emits NEW_THREAT events with threat metadata when anomalies are detected.
    """

    def initialize(self, config):
        """Initialize detection module with configuration and load models.

        Parameters
        ----------
        config : dict
            Configuration settings including model paths and plugin options.
        """
        self.config = config
        # Initialize Snort rules plugin and prepare rule flags
        self.snort_plugin = SnortRulesPlugin()
        self.snort_plugin.initialize(config)
        # List of rule IDs for features
        self.rule_sids = [rule['sid'] for rule in self.snort_plugin.rules if rule.get('sid')]
        # Set to collect sids detected since last feature event
        self._snort_sids = set()
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
        # Load or train Isolation Forest model with dynamic feature dimension
        from sklearn.ensemble import IsolationForest
        expected_dim = 3 + len(self.rule_sids)  # packet_count, total_bytes, flow_id + one flag per rule
        # Store expected feature dimension for padding/truncating
        self.expected_dim = expected_dim
        # Debug: print expected dimension and rule SIDs
        print(f"[DEBUG] DetectionModule.initialize: expected_dim={self.expected_dim}, rule_sids={self.rule_sids}")
        try:
            from joblib import load
            self.if_model = load(self.if_model_path)
            # If existing model has different feature count, retrain
            if hasattr(self.if_model, 'n_features_in_') and self.if_model.n_features_in_ != expected_dim:
                raise ValueError('Feature shape mismatch')
        except Exception:
            # Remove mismatched model file if exists
            try:
                if os.path.exists(self.if_model_path):
                    os.remove(self.if_model_path)
            except Exception:
                pass
            # Train new model with correct dimension
            X0 = np.random.normal(0, 1, (100, expected_dim))
            self.if_model = IsolationForest(contamination=0.1, random_state=42)
            self.if_model.fit(X0)
            from joblib import dump
            os.makedirs(os.path.dirname(self.if_model_path), exist_ok=True)
            dump(self.if_model, self.if_model_path)

    def handle_event(self, event):
        """Handle SNORT_ALERT and NEW_FEATURES events to prepare for threat inference.

        SNORT_ALERT: collect rule SID for feature augmentation.
        NEW_FEATURES: assemble feature vector and store for inference.

        Parameters
        ----------
        event : Event
            Incoming event object to process.

        Returns
        -------
        None
        """
        # Collect Snort rule matches by SID
        if event.type == 'SNORT_ALERT':
            sid = event.data.get('sid')
            if sid:
                self._snort_sids.add(sid)
            return None
        # Process features event
        if event.type == 'NEW_FEATURES':
            features = event.data
            # Construct base features: packet_count, total_bytes, flow_id
            base = [
                float(features.get('packet_count', 0)),
                float(features.get('total_bytes', 0)),
                float(features.get('flow_id', 0))
            ]
            # Append flags for each Snort rule in consistent order
            flags = [1.0 if sid in self._snort_sids else 0.0 for sid in self.rule_sids]
            # Reset collected SIDs
            self._snort_sids.clear()
            # Combine features and adjust to expected dimension
            X = base + flags
            # Debug: report feature vector length vs expected
            try:
                print(f"[DEBUG] handle_event: len(X)={len(X)}, expected_dim={self.expected_dim}")
            except Exception:
                pass
            # Pad or trim to match expected_dim
            if len(X) < self.expected_dim:
                X = X + [0.0] * (self.expected_dim - len(X))
            elif len(X) > self.expected_dim:
                X = X[:self.expected_dim]
            self._last_features = X
            self._last_features_meta = features

    def generate_event(self):
        """Perform AI inference and generate a NEW_THREAT event if a threat is detected.

        Chooses between neural network and Isolation Forest models based on availability,
        computes prediction, builds threat data dictionary, and returns NEW_THREAT event.

        Returns
        -------
        Event or None
            Event with type 'NEW_THREAT' and threat details, or None if no threat.
        """
        if not hasattr(self, '_last_features'):
            return None
        X = np.array(self._last_features).reshape(1, -1)
        features = self._last_features_meta
        del self._last_features
        del self._last_features_meta
        # Debug: report model and feature vector info
        try:
            print(f"[DEBUG] generate_event: X.shape={X.shape}, model_n_features_in={getattr(self.if_model,'n_features_in_', None)}")
        except Exception:
            pass
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
        # Ensure feature vector matches model dimension
        try:
            expected = getattr(self.if_model, 'n_features_in_', X.shape[1])
        except Exception:
            expected = X.shape[1]
        if X.shape[1] < expected:
            # pad with zeros
            X = np.pad(X, ((0, 0), (0, expected - X.shape[1])), constant_values=0)
        elif X.shape[1] > expected:
            # trim extra features
            X = X[:, :expected]
        # Fallback to Isolation Forest
        # Fit or reload model if shape mismatch
        from sklearn.ensemble import IsolationForest
        try:
            pred = self.if_model.predict(X)[0]
            score = self.if_model.decision_function(X)[0]
        except ValueError:
            # Retrain model with current feature dimension
            dim = X.shape[1]
            X0 = np.random.normal(0, 1, (100, dim))
            self.if_model = IsolationForest(contamination=0.1, random_state=42)
            self.if_model.fit(X0)
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
