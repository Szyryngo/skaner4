import importlib
import yaml
import os


def load_plugins(config_path, plugins_dir):
    """
	Ładuje pluginy z katalogu plugins_dir na podstawie config_path (plugins_config.yaml).
	Zwraca listę instancji pluginów.
	"""
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    plugins = []
    for plugin_info in config.get('plugins', []):
        if not plugin_info.get('enabled', True):
            continue
        module_name = plugin_info['path'].replace('/', '.').replace('\\', '.')[
            :-3] if plugin_info['path'].endswith('.py') else plugin_info['path'
            ]
        try:
            module = importlib.import_module(f'plugins.{module_name}')
            plugin_class = getattr(module, plugin_info.get('class', 'Plugin'))
            plugins.append(plugin_class())
        except Exception as e:
            print(f'Błąd ładowania pluginu {module_name}: {e}')
    return plugins
