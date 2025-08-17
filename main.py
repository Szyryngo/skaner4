import sys
import yaml
from core.orchestrator import Orchestrator


def run_qt_gui():
    """
Parameters
----------

Returns
-------

"""
    # Initialize and run the Qt GUI, catching any exceptions during setup or execution
    try:
        from qtui.main_window import MainWindow
        from PyQt5.QtWidgets import QApplication
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    import os
    config_path = 'config/config.yaml'
    default_config = """window_width: 1280
window_height: 800
gui: qt
ai_model_path: data/models/
filter: ''
network_interface: ''
ui_port: 5000
"""
    import os
    config_path = 'config/config.yaml'
    default_config = """window_width: 1280
window_height: 800
gui: qt
ai_model_path: data/models/
filter: ''
network_interface: ''
ui_port: 5000
"""
    if not os.path.exists(config_path):
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(default_config)
    plugins_config_path = 'config/plugins_config.yaml'
    default_plugins_config = """plugins:
  - path: example_plugin.py
    class: ExamplePlugin
    enabled: true
"""
    if not os.path.exists(plugins_config_path):
        with open(plugins_config_path, 'w', encoding='utf-8') as f:
            f.write(default_plugins_config)
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        gui_mode = cfg.get('gui', 'qt')
    except Exception:
        gui_mode = 'qt'
    if gui_mode == 'qt':
        run_qt_gui()
    else:
        orchestrator = Orchestrator()
        orchestrator.run()
