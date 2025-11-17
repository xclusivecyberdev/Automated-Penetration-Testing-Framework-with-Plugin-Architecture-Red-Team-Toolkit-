"""
CMS Fingerprinting Plugin - Detects and identifies Content Management Systems
"""

import aiohttp
from typing import Dict, Any, Optional
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity


class CMSFingerprint(BasePlugin):
    """CMS detection and fingerprinting plugin"""

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.RECON

    @property
    def description(self) -> str:
        return "Detects and fingerprints Content Management Systems (WordPress, Joomla, Drupal, etc.)"

    def __init__(self, config: Any, logger: Any):
        super().__init__(config, logger)

        # CMS detection signatures
        self.cms_signatures = {
            'wordpress': {
                'paths': ['/wp-admin/', '/wp-login.php', '/wp-content/', '/wp-includes/'],
                'headers': {},
                'content': ['wp-content', 'WordPress', 'wp-includes'],
                'meta': ['generator', 'WordPress']
            },
            'joomla': {
                'paths': ['/administrator/', '/components/', '/modules/', '/templates/'],
                'headers': {},
                'content': ['Joomla!', '/media/jui/', 'com_content'],
                'meta': ['generator', 'Joomla!']
            },
            'drupal': {
                'paths': ['/user/login', '/core/', '/sites/default/', '/misc/drupal.js'],
                'headers': {'X-Generator': 'Drupal'},
                'content': ['Drupal', '/sites/default/files/'],
                'meta': ['generator', 'Drupal']
            },
            'magento': {
                'paths': ['/skin/frontend/', '/js/mage/', '/admin/'],
                'headers': {},
                'content': ['Mage.Cookies', 'Magento'],
                'meta': []
            },
            'shopify': {
                'paths': ['/cart', '/checkout'],
                'headers': {'X-ShopId': '*'},
                'content': ['cdn.shopify.com', 'Shopify'],
                'meta': []
            }
        }

    async def run(self, target: Any) -> PluginResult:
        """Execute CMS fingerprinting"""
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        try:
            # Ensure target is URL
            url = self._normalize_url(target.value)
            self.log_info(f"Starting CMS fingerprinting on {url}")

            # Detect CMS
            cms_detected = await self._detect_cms(url)

            if cms_detected:
                cms_name = cms_detected['name']
                version = cms_detected.get('version', 'Unknown')

                result.data['cms'] = cms_name
                result.data['version'] = version
                result.data['confidence'] = cms_detected.get('confidence', 0)
                result.data['indicators'] = cms_detected.get('indicators', [])

                self.log_info(f"Detected CMS: {cms_name} (version: {version})")

                # Add finding
                result.add_vulnerability(
                    title=f"{cms_name.title()} CMS Detected",
                    description=f"The target is running {cms_name.title()} CMS",
                    severity=Severity.INFO,
                    evidence=f"CMS: {cms_name}, Version: {version}, Confidence: {cms_detected.get('confidence')}%",
                    remediation=f"Ensure {cms_name.title()} is updated to the latest version and properly configured."
                )

                # Check for known vulnerabilities
                await self._check_cms_vulnerabilities(cms_name, version, url, result)

            else:
                self.log_info("No CMS detected")
                result.data['cms'] = None

            result.success = True

        except Exception as e:
            result.add_error(str(e))
            self.log_error(f"CMS fingerprinting failed: {e}")

        return result

    async def _detect_cms(self, url: str) -> Optional[Dict[str, Any]]:
        """Detect CMS from various indicators"""
        detections = {}

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Get homepage
            try:
                async with session.get(url, ssl=False) as response:
                    html = await response.text()
                    headers = response.headers

                    # Check each CMS
                    for cms_name, signatures in self.cms_signatures.items():
                        confidence = 0
                        indicators = []

                        # Check content
                        for content_sig in signatures['content']:
                            if content_sig.lower() in html.lower():
                                confidence += 20
                                indicators.append(f"Content contains: {content_sig}")

                        # Check headers
                        for header, value in signatures['headers'].items():
                            if header in headers:
                                if value == '*' or value in headers[header]:
                                    confidence += 30
                                    indicators.append(f"Header: {header}")

                        # Check meta tags
                        if signatures['meta']:
                            meta_tag = signatures['meta'][0]
                            meta_value = signatures['meta'][1] if len(signatures['meta']) > 1 else ''
                            if meta_tag in html.lower() and meta_value.lower() in html.lower():
                                confidence += 40
                                indicators.append(f"Meta tag: {meta_tag}={meta_value}")

                        # Check specific paths
                        for path in signatures['paths'][:2]:  # Check first 2 paths
                            path_url = url.rstrip('/') + path
                            try:
                                async with session.get(path_url, ssl=False) as path_response:
                                    if path_response.status in [200, 301, 302, 403]:
                                        confidence += 15
                                        indicators.append(f"Path exists: {path}")
                            except:
                                pass

                        if confidence > 30:  # Threshold for detection
                            detections[cms_name] = {
                                'name': cms_name,
                                'confidence': min(confidence, 100),
                                'indicators': indicators
                            }

            except Exception as e:
                self.log_error(f"Error fetching {url}: {e}")
                return None

        # Return the CMS with highest confidence
        if detections:
            best_match = max(detections.values(), key=lambda x: x['confidence'])

            # Try to detect version
            version = await self._detect_version(url, best_match['name'])
            best_match['version'] = version

            return best_match

        return None

    async def _detect_version(self, url: str, cms_name: str) -> str:
        """Attempt to detect CMS version"""
        version_paths = {
            'wordpress': ['/readme.html', '/wp-includes/version.php'],
            'joomla': ['/administrator/manifests/files/joomla.xml'],
            'drupal': ['/CHANGELOG.txt', '/core/CHANGELOG.txt']
        }

        if cms_name not in version_paths:
            return "Unknown"

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for path in version_paths[cms_name]:
                try:
                    version_url = url.rstrip('/') + path
                    async with session.get(version_url, ssl=False) as response:
                        if response.status == 200:
                            content = await response.text()

                            # Simple version extraction (would be more sophisticated in production)
                            if cms_name == 'wordpress':
                                if 'Version' in content:
                                    lines = content.split('\n')
                                    for line in lines:
                                        if 'Version' in line and any(c.isdigit() for c in line):
                                            return line.split()[-1] if line.split() else "Unknown"

                            # Add more version detection logic for other CMS

                except:
                    pass

        return "Unknown"

    async def _check_cms_vulnerabilities(
        self,
        cms_name: str,
        version: str,
        url: str,
        result: PluginResult
    ):
        """Check for known CMS vulnerabilities"""

        # Check for common misconfigurations
        if cms_name == 'wordpress':
            await self._check_wordpress_issues(url, version, result)
        elif cms_name == 'joomla':
            await self._check_joomla_issues(url, version, result)
        elif cms_name == 'drupal':
            await self._check_drupal_issues(url, version, result)

    async def _check_wordpress_issues(self, url: str, version: str, result: PluginResult):
        """Check for WordPress-specific issues"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Check for directory listing
            try:
                async with session.get(f"{url}/wp-content/uploads/", ssl=False) as response:
                    content = await response.text()
                    if 'Index of' in content:
                        result.add_vulnerability(
                            title="WordPress Directory Listing Enabled",
                            description="Directory listing is enabled for wp-content/uploads",
                            severity=Severity.LOW,
                            evidence="Index of /wp-content/uploads/ is accessible",
                            remediation="Disable directory listing in web server configuration"
                        )
            except:
                pass

            # Check for xmlrpc
            try:
                async with session.post(f"{url}/xmlrpc.php", ssl=False) as response:
                    if response.status == 200 or 'XML-RPC' in await response.text():
                        result.add_vulnerability(
                            title="WordPress XML-RPC Enabled",
                            description="XML-RPC interface is enabled and may be abused for attacks",
                            severity=Severity.MEDIUM,
                            evidence="xmlrpc.php is accessible and responding",
                            remediation="Disable XML-RPC if not required, or implement rate limiting"
                        )
            except:
                pass

    async def _check_joomla_issues(self, url: str, version: str, result: PluginResult):
        """Check for Joomla-specific issues"""
        # Placeholder for Joomla checks
        pass

    async def _check_drupal_issues(self, url: str, version: str, result: PluginResult):
        """Check for Drupal-specific issues"""
        # Placeholder for Drupal checks
        pass

    def _normalize_url(self, target: str) -> str:
        """Normalize URL"""
        if not target.startswith('http'):
            return f"http://{target}"
        return target

    def validate_target(self, target: Any) -> bool:
        """Validate if target is suitable for CMS fingerprinting"""
        return target.type == 'url'
