"""Plugin Loader - load and initialize plugins defined in YAML configuration."""
import importlib
import yaml
import os


def load_plugins(config_path, plugins_dir):
    """Load and instantiate plugins as per plugins_config.yaml.

    Reads the configuration file at config_path, dynamically imports each enabled plugin
    from plugins_dir, initializes it with its config, and returns plugin instances.

    Parameters
    ----------
    config_path : str
        Path to the plugins_config.yaml file.
    plugins_dir : str
        Directory from which to import plugin modules.

    Returns
    -------
    list
        List of initialized plugin instances.
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
            plugin = plugin_class()
            # Initialize plugin with optional config
            plugin.initialize(plugin_info.get('config', {}))
            plugins.append(plugin)
        except Exception as e:
            # print(f'Błąd ładowania pluginu {module_name}: {e}')
            pass
    return plugins
