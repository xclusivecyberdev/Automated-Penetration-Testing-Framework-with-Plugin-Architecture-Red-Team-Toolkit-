"""
Configuration management for the penetration testing framework
"""

import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ScanMode:
    """Scan mode configuration"""
    name: str
    rate_limit: int  # requests per second
    timeout: int  # seconds
    retries: int
    delay: float  # seconds between requests
    stealth: bool


@dataclass
class Target:
    """Target configuration"""
    name: str
    type: str  # 'host', 'network', 'url'
    value: str  # IP, CIDR, or URL
    ports: Optional[List[int]] = None
    exclude_ports: Optional[List[int]] = None
    credentials: Optional[Dict[str, str]] = None
    tags: List[str] = field(default_factory=list)
    priority: int = 5  # 1-10, 10 being highest


class Config:
    """Main configuration class"""

    SCAN_MODES = {
        'safe': ScanMode(
            name='safe',
            rate_limit=5,
            timeout=10,
            retries=2,
            delay=1.0,
            stealth=True
        ),
        'normal': ScanMode(
            name='normal',
            rate_limit=20,
            timeout=5,
            retries=1,
            delay=0.5,
            stealth=False
        ),
        'aggressive': ScanMode(
            name='aggressive',
            rate_limit=100,
            timeout=3,
            retries=0,
            delay=0.1,
            stealth=False
        ),
        'stealth': ScanMode(
            name='stealth',
            rate_limit=2,
            timeout=15,
            retries=3,
            delay=2.0,
            stealth=True
        )
    }

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.targets: List[Target] = []
        self.enabled_plugins: List[str] = []
        self.disabled_plugins: List[str] = []
        self.scan_mode: ScanMode = self.SCAN_MODES['normal']
        self.output_dir: Path = Path("output")
        self.max_threads: int = 10
        self.user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.proxy: Optional[str] = None
        self.session_name: Optional[str] = None

        if config_file:
            self.load_from_file(config_file)

    def load_from_file(self, config_file: str):
        """Load configuration from YAML file"""
        config_path = Path(config_file)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")

        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)

        # Load scan mode
        mode_name = data.get('scan_mode', 'normal')
        if mode_name in self.SCAN_MODES:
            self.scan_mode = self.SCAN_MODES[mode_name]

        # Load targets
        for target_data in data.get('targets', []):
            target = Target(
                name=target_data.get('name', ''),
                type=target_data.get('type', 'host'),
                value=target_data['value'],
                ports=target_data.get('ports'),
                exclude_ports=target_data.get('exclude_ports'),
                credentials=target_data.get('credentials'),
                tags=target_data.get('tags', []),
                priority=target_data.get('priority', 5)
            )
            self.targets.append(target)

        # Load plugin configuration
        self.enabled_plugins = data.get('enabled_plugins', [])
        self.disabled_plugins = data.get('disabled_plugins', [])

        # Load general settings
        self.max_threads = data.get('max_threads', 10)
        self.user_agent = data.get('user_agent', self.user_agent)
        self.proxy = data.get('proxy')
        self.output_dir = Path(data.get('output_dir', 'output'))

    def set_scan_mode(self, mode_name: str):
        """Set the scan mode"""
        if mode_name not in self.SCAN_MODES:
            raise ValueError(f"Invalid scan mode: {mode_name}")
        self.scan_mode = self.SCAN_MODES[mode_name]

    def add_target(self, target: Target):
        """Add a target to the configuration"""
        self.targets.append(target)

    def get_targets_by_type(self, target_type: str) -> List[Target]:
        """Get all targets of a specific type"""
        return [t for t in self.targets if t.type == target_type]

    def is_plugin_enabled(self, plugin_name: str) -> bool:
        """Check if a plugin is enabled"""
        if self.disabled_plugins and plugin_name in self.disabled_plugins:
            return False
        if self.enabled_plugins:
            return plugin_name in self.enabled_plugins
        return True  # Enable all by default if no filter specified

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'scan_mode': self.scan_mode.name,
            'targets': [
                {
                    'name': t.name,
                    'type': t.type,
                    'value': t.value,
                    'ports': t.ports,
                    'tags': t.tags,
                    'priority': t.priority
                }
                for t in self.targets
            ],
            'enabled_plugins': self.enabled_plugins,
            'max_threads': self.max_threads,
            'output_dir': str(self.output_dir)
        }
