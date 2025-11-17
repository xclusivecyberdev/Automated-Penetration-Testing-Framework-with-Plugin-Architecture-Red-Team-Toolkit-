"""
Service Enumeration Plugin - Detailed service version detection
"""

import asyncio
import aiohttp
from typing import Dict, Any, Optional
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity


class ServiceEnumerator(BasePlugin):
    """Service enumeration and version detection plugin"""

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.RECON

    @property
    def description(self) -> str:
        return "Enumerates services and detects versions for vulnerability assessment"

    @property
    def dependencies(self) -> list:
        return ["PortScanner"]  # Depends on port scanner results

    async def run(self, target: Any) -> PluginResult:
        """Execute service enumeration"""
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        try:
            self.log_info(f"Starting service enumeration on {target.value}")

            services = []

            # Check common web services
            web_services = await self._enumerate_web_services(target.value)
            services.extend(web_services)

            # Check SSH
            ssh_info = await self._enumerate_ssh(target.value)
            if ssh_info:
                services.append(ssh_info)

            # Check FTP
            ftp_info = await self._enumerate_ftp(target.value)
            if ftp_info:
                services.append(ftp_info)

            result.data['services'] = services
            result.success = True

            # Analyze for vulnerabilities
            for service in services:
                await self._analyze_service(service, result)

            self.log_info(f"Enumerated {len(services)} services")

        except Exception as e:
            result.add_error(str(e))
            self.log_error(f"Service enumeration failed: {e}")

        return result

    async def _enumerate_web_services(self, host: str) -> list:
        """Enumerate web services (HTTP/HTTPS)"""
        services = []
        ports = [80, 443, 8080, 8443, 8888]

        for port in ports:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{host}:{port}"

            try:
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(
                        url,
                        allow_redirects=False,
                        ssl=False
                    ) as response:
                        server = response.headers.get('Server', 'Unknown')
                        powered_by = response.headers.get('X-Powered-By', '')

                        service_info = {
                            'type': 'web',
                            'port': port,
                            'protocol': protocol,
                            'server': server,
                            'powered_by': powered_by,
                            'status_code': response.status,
                            'url': url
                        }

                        services.append(service_info)
                        self.log_debug(f"Found web service: {url} - {server}")

            except Exception:
                pass  # Port not open or service not responding

        return services

    async def _enumerate_ssh(self, host: str) -> Optional[Dict[str, Any]]:
        """Enumerate SSH service"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 22),
                timeout=self.timeout
            )

            # Read SSH banner
            banner = await asyncio.wait_for(
                reader.readline(),
                timeout=3.0
            )

            writer.close()
            await writer.wait_closed()

            banner_str = banner.decode('utf-8', errors='ignore').strip()

            return {
                'type': 'ssh',
                'port': 22,
                'banner': banner_str,
                'version': banner_str.replace('SSH-', '')
            }

        except Exception:
            return None

    async def _enumerate_ftp(self, host: str) -> Optional[Dict[str, Any]]:
        """Enumerate FTP service"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 21),
                timeout=self.timeout
            )

            # Read FTP banner
            banner = await asyncio.wait_for(
                reader.readline(),
                timeout=3.0
            )

            writer.close()
            await writer.wait_closed()

            banner_str = banner.decode('utf-8', errors='ignore').strip()

            return {
                'type': 'ftp',
                'port': 21,
                'banner': banner_str
            }

        except Exception:
            return None

    async def _analyze_service(self, service: Dict[str, Any], result: PluginResult):
        """Analyze service for potential vulnerabilities"""

        # Check for outdated web servers
        if service['type'] == 'web':
            server = service.get('server', '').lower()

            # Check for version disclosure
            if any(ver in server for ver in ['/', '1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.', '9.']):
                result.add_vulnerability(
                    title="Web Server Version Disclosure",
                    description=f"The web server discloses its version: {service['server']}",
                    severity=Severity.LOW,
                    evidence=f"Server header: {service['server']}",
                    remediation="Configure the web server to hide version information in HTTP headers."
                )

            # Check for powered-by header
            if service.get('powered_by'):
                result.add_vulnerability(
                    title="Technology Stack Disclosure",
                    description=f"The server discloses technology information: {service['powered_by']}",
                    severity=Severity.LOW,
                    evidence=f"X-Powered-By header: {service['powered_by']}",
                    remediation="Remove or obfuscate X-Powered-By and similar headers."
                )

            # Check for known vulnerable versions
            if 'apache/2.4.49' in server or 'apache/2.4.50' in server:
                result.add_vulnerability(
                    title="Apache Path Traversal Vulnerability (CVE-2021-41773)",
                    description="Apache version appears vulnerable to path traversal attack",
                    severity=Severity.CRITICAL,
                    evidence=f"Server: {server}",
                    cve="CVE-2021-41773",
                    remediation="Upgrade Apache to version 2.4.51 or later immediately."
                )

        # Check for SSH version
        if service['type'] == 'ssh':
            banner = service.get('banner', '').lower()

            # Check for old OpenSSH versions
            if 'openssh' in banner:
                # Very simplified version check
                if any(v in banner for v in ['openssh_5.', 'openssh_6.', 'openssh_7.0', 'openssh_7.1', 'openssh_7.2']):
                    result.add_vulnerability(
                        title="Outdated SSH Server Version",
                        description=f"The SSH server version appears to be outdated: {service['banner']}",
                        severity=Severity.MEDIUM,
                        evidence=f"SSH banner: {service['banner']}",
                        remediation="Upgrade OpenSSH to the latest stable version."
                    )

        # Check FTP
        if service['type'] == 'ftp':
            result.add_vulnerability(
                title="Insecure FTP Service Detected",
                description="FTP transmits credentials and data in cleartext",
                severity=Severity.MEDIUM,
                evidence=f"FTP service running on port 21",
                remediation="Replace FTP with SFTP or FTPS for secure file transfer."
            )

    def validate_target(self, target: Any) -> bool:
        """Validate if target is suitable for service enumeration"""
        return target.type in ['host', 'url']
