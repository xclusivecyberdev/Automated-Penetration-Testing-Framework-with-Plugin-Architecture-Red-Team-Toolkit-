"""
Port Scanner Plugin - Advanced port scanning with service detection
"""

import asyncio
import socket
from typing import List, Dict, Any
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity


class PortScanner(BasePlugin):
    """Advanced port scanning plugin"""

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.RECON

    @property
    def description(self) -> str:
        return "Scans for open ports and detects running services"

    def __init__(self, config: Any, logger: Any):
        super().__init__(config, logger)
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 8888
        ]
        self.service_names = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt"
        }

    async def run(self, target: Any) -> PluginResult:
        """Execute port scan"""
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        try:
            self.log_info(f"Starting port scan on {target.value}")

            # Determine which ports to scan
            ports_to_scan = target.ports if target.ports else self.common_ports

            # Scan ports
            open_ports = await self._scan_ports(target.value, ports_to_scan)

            result.data['open_ports'] = open_ports
            result.data['total_scanned'] = len(ports_to_scan)
            result.success = True

            # Report findings
            if open_ports:
                self.log_info(f"Found {len(open_ports)} open ports")

                # Check for potentially risky services
                for port_info in open_ports:
                    port = port_info['port']
                    service = port_info['service']

                    # Flag risky services
                    if port in [21, 23, 111, 135, 139, 445]:  # Risky ports
                        result.add_vulnerability(
                            title=f"Potentially Insecure Service Detected: {service}",
                            description=f"Port {port} ({service}) is open. This service may be insecure or misconfigured.",
                            severity=Severity.MEDIUM,
                            evidence=f"Open port: {port} - Service: {service}",
                            remediation=f"Review the necessity of {service} service. Consider disabling if not required or implementing proper security controls."
                        )

                    # Flag administrative services
                    if port in [22, 3389, 5900]:  # Remote access
                        result.add_vulnerability(
                            title=f"Remote Administration Service Detected: {service}",
                            description=f"Port {port} ({service}) is open and may allow remote administration.",
                            severity=Severity.INFO,
                            evidence=f"Open port: {port} - Service: {service}",
                            remediation=f"Ensure {service} is properly secured with strong authentication and restricted access."
                        )

            else:
                self.log_info("No open ports found")

        except Exception as e:
            result.add_error(str(e))
            self.log_error(f"Port scan failed: {e}")

        return result

    async def _scan_ports(self, host: str, ports: List[int]) -> List[Dict[str, Any]]:
        """Scan multiple ports asynchronously"""
        # Respect rate limiting
        max_concurrent = min(self.config.scan_mode.rate_limit, 50)
        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_with_semaphore(port):
            async with semaphore:
                return await self._scan_port(host, port)

        # Scan all ports concurrently
        tasks = [scan_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter open ports
        open_ports = []
        for result in results:
            if isinstance(result, dict) and result.get('open'):
                open_ports.append(result)

        return open_ports

    async def _scan_port(self, host: str, port: int) -> Dict[str, Any]:
        """Scan a single port"""
        try:
            # Try to connect
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(
                future,
                timeout=self.config.scan_mode.timeout
            )

            # Get service banner if available
            banner = await self._grab_banner(reader, writer)

            writer.close()
            await writer.wait_closed()

            service_name = self.service_names.get(port, f"Unknown-{port}")

            return {
                'port': port,
                'open': True,
                'service': service_name,
                'banner': banner
            }

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return {'port': port, 'open': False}

    async def _grab_banner(self, reader, writer) -> str:
        """Attempt to grab service banner"""
        try:
            # Wait a bit for banner
            banner_data = await asyncio.wait_for(
                reader.read(1024),
                timeout=2.0
            )
            return banner_data.decode('utf-8', errors='ignore').strip()
        except:
            return ""

    def validate_target(self, target: Any) -> bool:
        """Validate if target is suitable for port scanning"""
        return target.type in ['host', 'network']
