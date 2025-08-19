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
        """Load configuration and initialize all modules and plugins.

        Reads YAML config files and calls initialize() on each module and plugin based on loaded settings.
        """
        config_path = os.path.join(self.config_dir, 'config.yaml')
        plugins_config_path = os.path.join(self.config_dir,
            'plugins_config.yaml')
        config = ConfigManager(config_path).load()
        self.modules = [CaptureModule(), FeaturesModule(), DetectionModule(
            ), OptimizerModule(), DevicesModule(), DevicesSnifferModule(),
            ScannerModule()]
        for module in self.modules:
            module.initialize(config)
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
        # Jeśli jest CaptureModule, rozpocznij sniffing pakietów
        for module in self.modules:
            if hasattr(module, '_start_sniffing'):
                try:
                    module._start_sniffing()
                except Exception:
                    pass
        import concurrent.futures
        from concurrent.futures import ThreadPoolExecutor, as_completed
        # Wykorzystanie puli wątków do równoległego generowania zdarzeń
        with ThreadPoolExecutor(max_workers=len(self.modules + self.plugins)) as executor:
            while True:
                # Generowanie zdarzeń równolegle
                futures = {executor.submit(obj.generate_event): obj for obj in (self.modules + self.plugins)}
                for fut in as_completed(futures):
                    try:
                        result = fut.result()
                        # przyjmuj tylko Event lub listę Event
                        if isinstance(result, Event):
                            self.event_queue.append(result)
                        elif hasattr(result, '__iter__'):
                            for ev in result:
                                if isinstance(ev, Event):
                                    self.event_queue.append(ev)
                    except Exception as e:
                        print(f'Błąd generate_event w module {futures[fut].__class__.__name__}: {e}')
                # Obsługa kolejki zdarzeń
                while self.event_queue:
                    event = self.event_queue.pop(0)
                    for obj in (self.modules + self.plugins):
                        try:
                            result = obj.handle_event(event)
                            if not result:
                                continue
                            # Obsługa pojedynczego eventu
                            if isinstance(result, Event):
                                # drukuj SNORT_ALERT do konsoli
                                if result.type == 'SNORT_ALERT':
                                    sid = result.data.get('sid')
                                    msg = result.data.get('msg')
                                    src = result.data.get('src_ip')
                                    dst = result.data.get('dst_ip')
                                    print(f'[SNORT_ALERT] SID={sid} MSG="{msg}" SRC={src} DST={dst}')
                                self.event_queue.append(result)
                                # GUI obsługuje tylko DEVICE_DETECTED
                                if self.gui and result.type == 'DEVICE_DETECTED':
                                    self.gui.handle_event(result)
                            # Obsługa wielu eventów
                            elif hasattr(result, '__iter__'):
                                for e in result:
                                    if isinstance(e, Event):
                                        if e.type == 'SNORT_ALERT':
                                            sid = e.data.get('sid')
                                            msg = e.data.get('msg')
                                            src = e.data.get('src_ip')
                                            dst = e.data.get('dst_ip')
                                            print(f'[SNORT_ALERT] SID={sid} MSG="{msg}" SRC={src} DST={dst}')
                                        self.event_queue.append(e)
                                        if self.gui and e.type == 'DEVICE_DETECTED':
                                            self.gui.handle_event(e)
                        except Exception as e:
                            print(f'Błąd w module/pluginie {obj.__class__.__name__}: {e}')
                # Krótkie opóźnienie między iteracjami
                import time
                time.sleep(1)
