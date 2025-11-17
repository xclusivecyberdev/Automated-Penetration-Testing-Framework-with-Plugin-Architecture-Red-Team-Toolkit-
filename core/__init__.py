"""
RedTeam Penetration Testing Framework
Core module initialization
"""

__version__ = "1.0.0"
__author__ = "RedTeam Security"

from .framework import PentestFramework
from .plugin_loader import PluginLoader
from .config import Config
from .logger import Logger

__all__ = ['PentestFramework', 'PluginLoader', 'Config', 'Logger']
