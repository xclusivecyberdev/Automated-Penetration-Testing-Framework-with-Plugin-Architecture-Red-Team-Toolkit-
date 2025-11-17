"""
Base plugin class for all penetration testing modules
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


class PluginCategory(Enum):
    """Plugin categories"""
    RECON = "reconnaissance"
    VULN_SCAN = "vulnerability_scanning"
    EXPLOIT = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    REPORTING = "reporting"
    AUXILIARY = "auxiliary"


class Severity(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def get_score(self) -> int:
        """Get numeric score for severity"""
        scores = {
            'info': 0,
            'low': 3,
            'medium': 5,
            'high': 8,
            'critical': 10
        }
        return scores.get(self.value, 0)


@dataclass
class PluginResult:
    """Result from a plugin execution"""
    plugin_name: str
    target: str
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0  # seconds

    def add_vulnerability(
        self,
        title: str,
        description: str,
        severity: Severity,
        evidence: Optional[str] = None,
        cve: Optional[str] = None,
        remediation: Optional[str] = None,
        **kwargs
    ):
        """Add a vulnerability to the results"""
        vuln = {
            'title': title,
            'description': description,
            'severity': severity.value,
            'severity_score': severity.get_score(),
            'evidence': evidence,
            'cve': cve,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.vulnerabilities.append(vuln)

    def add_error(self, error: str):
        """Add an error message"""
        self.errors.append(error)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'plugin_name': self.plugin_name,
            'target': self.target,
            'success': self.success,
            'timestamp': self.timestamp.isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'data': self.data,
            'errors': self.errors,
            'duration': self.duration
        }


class BasePlugin(ABC):
    """Base class for all plugins"""

    def __init__(self, config: Any, logger: Any):
        self.config = config
        self.logger = logger
        self.name = self.__class__.__name__
        self.enabled = True
        self.timeout = config.scan_mode.timeout if config else 30

    @property
    @abstractmethod
    def category(self) -> PluginCategory:
        """Plugin category"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass

    @property
    def version(self) -> str:
        """Plugin version"""
        return "1.0.0"

    @property
    def author(self) -> str:
        """Plugin author"""
        return "RedTeam Security"

    @property
    def dependencies(self) -> List[str]:
        """Plugin dependencies (other plugin names that must run first)"""
        return []

    @abstractmethod
    async def run(self, target: Any) -> PluginResult:
        """
        Execute the plugin against a target

        Args:
            target: Target object containing target information

        Returns:
            PluginResult object with findings
        """
        pass

    def validate_target(self, target: Any) -> bool:
        """
        Validate if this plugin can run against the target

        Args:
            target: Target object

        Returns:
            True if plugin can run, False otherwise
        """
        return True

    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.name,
            'category': self.category.value,
            'description': self.description,
            'version': self.version,
            'author': self.author,
            'enabled': self.enabled,
            'dependencies': self.dependencies
        }

    def log_info(self, message: str):
        """Log info message"""
        self.logger.info(f"[{self.name}] {message}")

    def log_error(self, message: str):
        """Log error message"""
        self.logger.error(f"[{self.name}] {message}")

    def log_vuln(self, message: str):
        """Log vulnerability found"""
        self.logger.vuln_found(f"[{self.name}] {message}")

    def log_debug(self, message: str):
        """Log debug message"""
        self.logger.debug(f"[{self.name}] {message}")
