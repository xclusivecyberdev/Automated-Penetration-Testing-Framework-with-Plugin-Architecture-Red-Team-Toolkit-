"""
Directory Brute Force Plugin - Discovers hidden directories and files
"""

import aiohttp
import asyncio
from typing import List, Dict, Any
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity


class DirectoryBruteForce(BasePlugin):
    """Directory and file brute force scanner"""

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.VULN_SCAN

    @property
    def description(self) -> str:
        return "Discovers hidden directories, files, and sensitive resources"

    def __init__(self, config: Any, logger: Any):
        super().__init__(config, logger)

        # Common directories and files to check
        self.common_paths = [
            # Admin panels
            "admin", "administrator", "admin.php", "admin.html", "login.php",
            "login", "wp-admin", "phpmyadmin", "cpanel", "control",

            # Configuration files
            ".env", ".git", ".svn", ".htaccess", "web.config", "config.php",
            "configuration.php", "settings.php", "database.yml", "config.json",

            # Backup files
            "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
            "database.sql", "backup.old", "backup.bak", "old",

            # API endpoints
            "api", "api/v1", "api/v2", "graphql", "rest",

            # Common directories
            "uploads", "upload", "files", "images", "media", "assets",
            "static", "css", "js", "dist", "build",

            # Development files
            "test", "testing", "dev", "development", "debug", "phpinfo.php",
            "info.php", "test.php", "test.html",

            # Documentation
            "docs", "documentation", "api-docs", "swagger", "redoc",

            # Logs
            "logs", "log", "error.log", "access.log", "debug.log",

            # Version control
            ".git/HEAD", ".git/config", ".svn/entries", ".hg",

            # CMS specific
            "wp-content", "wp-includes", "readme.html", "license.txt",
            "components", "modules", "plugins", "themes",

            # Sensitive files
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "security.txt", ".well-known",

            # Database
            "db", "database", "mysql", "sql", "mongodb",

            # Application files
            "app", "application", "src", "includes", "lib", "vendor",
        ]

        # Interesting file extensions
        self.extensions = [
            ".php", ".asp", ".aspx", ".jsp", ".html", ".js",
            ".bak", ".old", ".txt", ".log", ".sql", ".zip",
            ".tar.gz", ".config", ".ini", ".yml", ".yaml", ".json"
        ]

    async def run(self, target: Any) -> PluginResult:
        """Execute directory brute force"""
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        try:
            url = self._normalize_url(target.value)
            self.log_info(f"Starting directory enumeration on {url}")

            # Discover paths
            discovered = await self._brute_force_paths(url)

            result.data['paths_tested'] = len(self.common_paths)
            result.data['paths_discovered'] = discovered
            result.success = True

            # Report findings
            for path_info in discovered:
                severity = self._classify_severity(path_info['path'], path_info['status'])

                result.add_vulnerability(
                    title=f"Discovered Resource: {path_info['path']}",
                    description=f"Found accessible resource at {path_info['url']}",
                    severity=severity,
                    evidence=f"URL: {path_info['url']}, Status: {path_info['status']}, "
                             f"Size: {path_info['size']} bytes",
                    remediation=self._get_remediation(path_info['path']),
                    url=path_info['url']
                )

            if discovered:
                self.log_success(f"Discovered {len(discovered)} accessible paths")
            else:
                self.log_info("No interesting paths discovered")

        except Exception as e:
            result.add_error(str(e))
            self.log_error(f"Directory brute force failed: {e}")

        return result

    async def _brute_force_paths(self, base_url: str) -> List[Dict[str, Any]]:
        """Brute force directories and files"""
        discovered = []

        # Limit based on scan mode
        paths_to_test = self.common_paths
        if self.config.scan_mode.stealth:
            paths_to_test = self.common_paths[:20]  # Test fewer paths in stealth mode

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        # Use semaphore to limit concurrent requests
        max_concurrent = min(self.config.scan_mode.rate_limit, 20)
        semaphore = asyncio.Semaphore(max_concurrent)

        async def test_path(path):
            async with semaphore:
                return await self._test_path(base_url, path, timeout)

        # Test all paths concurrently
        tasks = [test_path(path) for path in paths_to_test]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful discoveries
        for result in results:
            if isinstance(result, dict) and result.get('found'):
                discovered.append(result)

        return discovered

    async def _test_path(
        self,
        base_url: str,
        path: str,
        timeout: aiohttp.ClientTimeout
    ) -> Dict[str, Any]:
        """Test a single path"""
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False, allow_redirects=False) as response:
                    # Consider 200, 301, 302, 403 as "found"
                    if response.status in [200, 301, 302, 401, 403]:
                        content = await response.text()

                        return {
                            'found': True,
                            'path': path,
                            'url': url,
                            'status': response.status,
                            'size': len(content)
                        }

        except Exception:
            pass

        return {'found': False}

    def _classify_severity(self, path: str, status: int) -> Severity:
        """Classify the severity of a discovered path"""

        path_lower = path.lower()

        # Critical findings
        critical_indicators = [
            '.env', '.git', 'config.php', 'database.yml', 'web.config',
            '.htaccess', 'backup.sql', 'db.sql', 'phpinfo.php'
        ]
        if any(indicator in path_lower for indicator in critical_indicators):
            return Severity.CRITICAL

        # High severity
        high_indicators = [
            'admin', 'administrator', 'phpmyadmin', 'backup', '.bak',
            'cpanel', 'login', '.old', 'debug'
        ]
        if any(indicator in path_lower for indicator in high_indicators):
            return Severity.HIGH

        # Medium severity
        medium_indicators = [
            'test', 'dev', 'api', 'upload', 'logs', '.log'
        ]
        if any(indicator in path_lower for indicator in medium_indicators):
            return Severity.MEDIUM

        # Access denied (403) is interesting
        if status == 403:
            return Severity.MEDIUM

        # Everything else is low/info
        return Severity.LOW

    def _get_remediation(self, path: str) -> str:
        """Get remediation advice for discovered path"""

        path_lower = path.lower()

        if '.git' in path_lower or '.svn' in path_lower:
            return "Remove version control directories from production servers. Add deny rules in web server configuration."

        if '.env' in path_lower or 'config' in path_lower:
            return "Move configuration files outside web root. Restrict access via web server configuration."

        if 'backup' in path_lower or '.bak' in path_lower or '.old' in path_lower:
            return "Remove backup files from web-accessible directories. Store backups in secure, non-public locations."

        if 'admin' in path_lower or 'phpmyadmin' in path_lower:
            return "Implement strong authentication, IP restrictions, and rename default admin paths."

        if 'phpinfo' in path_lower or 'test' in path_lower or 'debug' in path_lower:
            return "Remove development and debugging files from production servers."

        if 'log' in path_lower:
            return "Prevent access to log files via web server configuration. Move logs outside web root."

        return "Review if this resource should be publicly accessible. Implement appropriate access controls."

    def _normalize_url(self, target: str) -> str:
        """Normalize URL"""
        if not target.startswith('http'):
            return f"http://{target}"
        return target

    def validate_target(self, target: Any) -> bool:
        """Validate if target is suitable for directory brute forcing"""
        return target.type == 'url'
