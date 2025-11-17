"""
Dynamic plugin loader for the penetration testing framework
"""

import importlib
import inspect
import sys
from pathlib import Path
from typing import List, Dict, Type, Any
from plugins.base import BasePlugin, PluginCategory


class PluginLoader:
    """Dynamically loads and manages plugins"""

    def __init__(self, plugin_dir: str = "plugins", config: Any = None, logger: Any = None):
        self.plugin_dir = Path(plugin_dir)
        self.config = config
        self.logger = logger
        self.plugins: Dict[str, Type[BasePlugin]] = {}
        self.plugin_instances: Dict[str, BasePlugin] = {}
        self.load_order: List[str] = []

    def discover_plugins(self) -> int:
        """
        Discover all available plugins

        Returns:
            Number of plugins discovered
        """
        count = 0

        # Add plugin directory to path
        if str(self.plugin_dir.parent) not in sys.path:
            sys.path.insert(0, str(self.plugin_dir.parent))

        # Walk through plugin directories
        for category_dir in self.plugin_dir.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith('__'):
                continue

            # Look for Python files in category directories
            for plugin_file in category_dir.glob("*.py"):
                if plugin_file.name.startswith('__'):
                    continue

                try:
                    # Import the module
                    module_name = f"plugins.{category_dir.name}.{plugin_file.stem}"
                    module = importlib.import_module(module_name)

                    # Find BasePlugin subclasses
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if (issubclass(obj, BasePlugin) and
                            obj != BasePlugin and
                            not inspect.isabstract(obj)):

                            self.plugins[name] = obj
                            count += 1
                            if self.logger:
                                self.logger.debug(f"Discovered plugin: {name}")

                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Failed to load plugin from {plugin_file}: {e}")

        return count

    def load_plugin(self, plugin_name: str) -> bool:
        """
        Load and instantiate a specific plugin

        Args:
            plugin_name: Name of the plugin class

        Returns:
            True if successful, False otherwise
        """
        if plugin_name not in self.plugins:
            if self.logger:
                self.logger.error(f"Plugin not found: {plugin_name}")
            return False

        try:
            plugin_class = self.plugins[plugin_name]
            plugin_instance = plugin_class(self.config, self.logger)

            # Check if plugin is enabled
            if self.config and not self.config.is_plugin_enabled(plugin_name):
                if self.logger:
                    self.logger.info(f"Plugin disabled by config: {plugin_name}")
                plugin_instance.enabled = False

            self.plugin_instances[plugin_name] = plugin_instance

            if self.logger:
                self.logger.info(f"Loaded plugin: {plugin_name}")

            return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to instantiate plugin {plugin_name}: {e}")
            return False

    def load_all_plugins(self) -> int:
        """
        Load all discovered plugins

        Returns:
            Number of plugins loaded
        """
        count = 0
        for plugin_name in self.plugins.keys():
            if self.load_plugin(plugin_name):
                count += 1

        # Calculate load order based on dependencies
        self._calculate_load_order()

        return count

    def _calculate_load_order(self):
        """Calculate the order in which plugins should be executed based on dependencies"""
        loaded = set()
        order = []

        def load_with_deps(plugin_name: str):
            if plugin_name in loaded:
                return

            if plugin_name not in self.plugin_instances:
                return

            plugin = self.plugin_instances[plugin_name]

            # Load dependencies first
            for dep in plugin.dependencies:
                if dep in self.plugin_instances:
                    load_with_deps(dep)

            order.append(plugin_name)
            loaded.add(plugin_name)

        # Load all plugins with their dependencies
        for plugin_name in self.plugin_instances.keys():
            load_with_deps(plugin_name)

        self.load_order = order

    def get_plugin(self, plugin_name: str) -> BasePlugin:
        """Get a loaded plugin instance"""
        return self.plugin_instances.get(plugin_name)

    def get_plugins_by_category(self, category: PluginCategory) -> List[BasePlugin]:
        """Get all plugins of a specific category"""
        return [
            plugin for plugin in self.plugin_instances.values()
            if plugin.category == category and plugin.enabled
        ]

    def get_all_plugins(self) -> List[BasePlugin]:
        """Get all loaded and enabled plugins"""
        return [p for p in self.plugin_instances.values() if p.enabled]

    def get_plugin_info(self) -> List[Dict[str, Any]]:
        """Get information about all loaded plugins"""
        return [plugin.get_info() for plugin in self.plugin_instances.values()]

    def reload_plugin(self, plugin_name: str) -> bool:
        """
        Reload a specific plugin

        Args:
            plugin_name: Name of the plugin to reload

        Returns:
            True if successful, False otherwise
        """
        if plugin_name not in self.plugins:
            return False

        # Remove old instance
        if plugin_name in self.plugin_instances:
            del self.plugin_instances[plugin_name]

        # Reload the module
        try:
            plugin_class = self.plugins[plugin_name]
            module = inspect.getmodule(plugin_class)
            importlib.reload(module)

            # Re-discover and load
            return self.load_plugin(plugin_name)

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to reload plugin {plugin_name}: {e}")
            return False

    def get_execution_order(self) -> List[str]:
        """Get the calculated plugin execution order"""
        return self.load_order
