"""Module orchestrator - main orchestrator loop, loading modules and plugins."""
from core.events import Event
from core.plugin_loader import load_plugins
from core.config_manager import ConfigManager
from modules.capture import CaptureModule
from modules.features import FeaturesModule
from modules.detection import DetectionModule
from modules.optimizer import OptimizerModule
from modules.devices import DevicesModule
from modules.scanner import ScannerModule
from modules.devices_sniffer_module import DevicesSnifferModule
import os


class Orchestrator:
    """Manage modules and plugins, process events, and coordinate application flow."""

    def __init__(self, config_dir='config', plugins_dir='plugins'):
        """Initialize orchestrator with config and plugin directories.

        Parameters
        ----------
        config_dir : str
            Path to the configuration directory.
        plugins_dir : str
            Path to the plugin modules directory.
        """
        '''Function __init__ - description.'''
        self.config_dir = config_dir
        self.plugins_dir = plugins_dir
        self.modules = []
        self.plugins = []
        self.event_queue = []
        self.gui = None

    def initialize(self):
        """Load configuration and initialize all plugins.

        Reads YAML config files and calls initialize() on each module and plugin based on loaded settings.
        """
        config_path = os.path.join(self.config_dir, 'config.yaml')
        plugins_config_path = os.path.join(self.config_dir,
            'plugins_config.yaml')
        config = ConfigManager(config_path).load()
        # Load and initialize plugins
        self.plugins = load_plugins(plugins_config_path, self.plugins_dir)
        for plugin in self.plugins:
            plugin.initialize(config)

    def set_gui(self, gui):
        """Set a reference to the GUI instance for event callbacks.

        Parameters
        ----------
        gui : object
            GUI object implementing handle_event(event).
        """
        self.gui = gui

    def run(self):
        """Start the main event loop.

        Initializes modules, starts packet sniffing, and processes events in parallel.

        SNORT_ALERT events are printed to console; DEVICE_DETECTED events are forwarded to the GUI when set.
        """
        self.initialize()
        # Start all non-UI plugins first
        for plugin in self.plugins:
            if plugin.__class__.__name__ != 'DashboardPlugin':
                try:
                    plugin.start()
                except Exception:
                    pass

        # Run event dispatch loop in background thread
        import threading, time
        def _dispatch_loop():
            while True:
                for plugin in self.plugins:
                    try:
                        result = plugin.generate_event()
                    except Exception:
                        continue
                    if not result:
                        continue
                    events = result if isinstance(result, list) else [result]
                    for ev in events:
                        for target in self.plugins:
                            try:
                                target.handle_event(ev)
                            except Exception:
                                pass
                time.sleep(0.05)
        threading.Thread(target=_dispatch_loop, daemon=True).start()

        # Finally, start the Dashboard (UI) plugin, which will block on its event loop
        for plugin in self.plugins:
            if plugin.__class__.__name__ == 'DashboardPlugin':
                try:
                    plugin.start()
                except Exception:
                    pass
                break
        import concurrent.futures
        from concurrent.futures import ThreadPoolExecutor, as_completed
        # Wykorzystanie puli wątków do równoległego generowania zdarzeń
    # In event-driven model, plugins may run their own loops or timers
    # Orchestrator now delegates fully to plugins
