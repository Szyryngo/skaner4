"""
Unit tests for DetectionPlugin: verify that detection works with a dummy IF model override.
"""
import os
import sys
import unittest
# ensure project root is on sys.path for importing plugins and core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from plugins.detection_plugin import DetectionPlugin
from core.events import Event

class DummyIFModel:
    """Dummy IsolationForest model always predicts anomaly (-1) and fixed score."""
    def predict(self, X):
        return [-1]
    def decision_function(self, X):
        return [-0.5]

class TestDetectionPlugin(unittest.TestCase):
    def setUp(self):
        # Initialize plugin with test snort rules and skip NN
        self.plugin = DetectionPlugin()
        rule_file = os.path.abspath(os.path.join(os.path.dirname(__file__), 'snort_test.rules'))
        self.plugin.initialize({'rule_file': rule_file, 'skip_nn': True})
        # Override IF model for deterministic anomaly
        self.plugin._module.if_model = DummyIFModel()
        self.plugin._module.use_nn = False

    def test_no_features_before_event(self):
        # generate_event before any features should return None
        ev = self.plugin.generate_event()
        self.assertIsNone(ev)

    def test_anomaly_detection(self):
        # Use first rule SID for SNORT_ALERT
        rule_sids = getattr(self.plugin._module, 'rule_sids', [])
        self.assertTrue(rule_sids, "No rule_sids loaded")
        sid = rule_sids[0]
        # Send SNORT_ALERT and NEW_FEATURES
        self.plugin.handle_event(Event('SNORT_ALERT', {'sid': sid}))
        features = {'packet_count': 1, 'total_bytes': 100, 'flow_id': 1, 'src_ip': '127.0.0.1'}
        self.plugin.handle_event(Event('NEW_FEATURES', features))
        ev = self.plugin.generate_event()
        # Should generate NEW_THREAT
        self.assertIsNotNone(ev, "generate_event returned None for anomaly detection")
        self.assertEqual(ev.type, 'NEW_THREAT')
        # Data should contain our flow_id and confidence
        self.assertIn('ai_weight', ev.data)
        self.assertGreater(ev.data['ai_weight'], 0)

if __name__ == '__main__':
    unittest.main()
