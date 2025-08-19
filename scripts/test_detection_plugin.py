"""
Test DetectionPlugin: initialize detection plugin, send SNORT_ALERT and NEW_FEATURES events, then check for NEW_THREAT output.
"""
import sys, os, time
# Ensure project root is on PYTHONPATH
dir_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if dir_path not in sys.path:
    sys.path.insert(0, dir_path)

from plugins.detection_plugin import DetectionPlugin
from core.events import Event

if __name__ == '__main__':
    print("Starting DetectionPlugin test...")
    # Specify path to snort.rules and skip NN loading
    config = {'rule_file': 'config/snort.rules', 'skip_nn': True}
    plugin = DetectionPlugin()
    plugin.initialize(config)
    # Inicjalizacja synchroniczna
    print("Initialization complete.")
    module = plugin._module
    print(f"Loaded rule_sids: {module.rule_sids}")
    # Prepare test events
    # Use first available rule SID if present
    module = plugin._module
    # Wymuszenie trybu IsolationForest i generowanie anomalii
    print("Forcing IsolationForest fallback and anomaly features")
    plugin._module.use_nn = False
    test_sid = module.rule_sids[0] if hasattr(module, 'rule_sids') and module.rule_sids else None
    if test_sid:
        print(f"Sending SNORT_ALERT with sid={test_sid}")
        plugin.handle_event(Event('SNORT_ALERT', {'sid': test_sid}))
    else:
        print("No rule SIDs loaded; skipping SNORT_ALERT.")
    # Send a dummy features event
    features = {'packet_count': 1, 'total_bytes': 1000000, 'flow_id': 1, 'src_ip': '127.0.0.1'}
    print("Sending NEW_FEATURES event")
    plugin.handle_event(Event('NEW_FEATURES', features))
    # Debug: pokaż przygotowane cechy i sprawdź predykcję IsolationForest
    try:
        feats = module._last_features
        print(f"Prepared features vector: {feats}")
        import numpy as _np
        X_dbg = _np.array(feats).reshape(1, -1)
        pred = module.if_model.predict(X_dbg)[0]
        score = module.if_model.decision_function(X_dbg)[0]
        print(f"Model predict: {pred}, decision_function: {score}")
    except Exception as _e:
        print(f"Debug error: {_e}")
    # Test generate_event
    ev = None
    try:
        ev = plugin.generate_event()
    except Exception as e:
        print(f"Error in plugin.generate_event: {e}")
    if ev:
        print(f"Generated event: {ev.type}, data: {ev.data}")
    else:
        print("No NEW_THREAT event generated.")
