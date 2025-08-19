"""Configuration Manager - load and save YAML configuration files."""
import yaml


class ConfigManager:
    """Manage loading and saving application configurations in YAML format."""

    def __init__(self, config_path):
        """Initialize ConfigManager with path to YAML file.

        Parameters
        ----------
        config_path : str
            Filesystem path to the YAML configuration file.
        """
        self.config_path = config_path
        self.config = None

    def load(self):
        """Load configuration from YAML file.

        Reads and parses the YAML file at config_path into a Python dict.

        Returns
        -------
        dict
            Parsed configuration data.
        """
        with open(self.config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)
        return self.config

    def save(self, config=None):
        """Save configuration to YAML file.

        Writes provided config dict (or last loaded config) back to disk.

        Parameters
        ----------
        config : dict, optional
            Configuration data to save. If None, uses the last loaded config.
        """
        to_save = config if config is not None else self.config
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(to_save, f, allow_unicode=True)
