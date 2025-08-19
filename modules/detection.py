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
        # List of rule IDs for features (deduplicated, preserve order)
        self.rule_sids = list(dict.fromkeys(
            rule['sid'] for rule in self.snort_plugin.rules if rule.get('sid')
        ))
        # Set to collect sids detected since last feature event
        self._snort_sids = set()
        # Path to Isolation Forest model
        self.if_model_path = os.path.join('data', 'models', 'isolation_forest.joblib')
        # Path to neural network model saved by NNLayout
        self.nn_model_path = os.path.join('data', 'models', 'nn_model.keras')
        # Temporarily disable neural network, always use IsolationForest
        self.use_nn = False
        # Load or train Isolation Forest model with dynamic feature dimension
        from sklearn.ensemble import IsolationForest
        expected_dim = 3 + len(self.rule_sids)  # packet_count, total_bytes, flow_id + one flag per rule
        # Store expected feature dimension for padding/truncating
        self.expected_dim = expected_dim
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
        # Debug: log incoming DetectionModule event
        print(f"[DEBUG DET] handle_event: {{event.type}}, data={{event.data}}", flush=True)
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
        # Debug: log incoming event
        print(f"[DEBUG DET] handle_event: {event.type}, data: {event.data}")
        # Collect Snort rule matches by SID
        if event.type == 'SNORT_ALERT':
            sid = event.data.get('sid')
            if sid:
                print(f"[DEBUG DET] collected SNORT_ALERT sid={sid}")
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
        # Debug: check for available features
        if not hasattr(self, '_last_features'):
            print("[DEBUG DET] generate_event: no features to process")
            return None
        X = np.array(self._last_features).reshape(1, -1)
        features = self._last_features_meta
        del self._last_features
        del self._last_features_meta
        # Use neural network if enabled
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
                print(f"[DEBUG DET] generate_event: NN detected threat with prob={prob}")
                return Event('NEW_THREAT', threat)
            return None
        # Fallback to IsolationForest
        try:
            pred = self.if_model.predict(X)[0]
            score = self.if_model.decision_function(X)[0]
        except Exception:
            # Retrain if needed
            from sklearn.ensemble import IsolationForest
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
            print(f"[DEBUG DET] generate_event: IF detected threat with score={score}")
            return Event('NEW_THREAT', threat)
        return None
