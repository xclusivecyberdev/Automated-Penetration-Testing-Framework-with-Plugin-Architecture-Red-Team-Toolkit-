"""
XSS Detection Plugin - Tests for Cross-Site Scripting vulnerabilities
"""

import aiohttp
import urllib.parse
import re
from typing import List, Dict, Any
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity


class XSSDetector(BasePlugin):
    """Cross-Site Scripting vulnerability scanner"""

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.VULN_SCAN

    @property
    def description(self) -> str:
        return "Detects Cross-Site Scripting (XSS) vulnerabilities in web applications"

    def __init__(self, config: Any, logger: Any):
        super().__init__(config, logger)

        # XSS test payloads
        self.payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",

            # Encoded payloads
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",

            # Event handlers
            "' onmouseover='alert(1)'",
            "\" onload=\"alert(1)\"",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",

            # Special bypasses
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src='x' onerror='alert(1)'>",
            "javascript:alert('XSS')",
            "<ScRiPt>alert('XSS')</sCrIpT>",

            # DOM-based XSS
            "#<script>alert('XSS')</script>",

            # Attribute-based XSS
            "'-alert(1)-'",
            "\"-alert(1)-\"",
        ]

        # Unique marker for detection
        self.marker = "XSS_TEST_MARKER_9876"

    async def run(self, target: Any) -> PluginResult:
        """Execute XSS detection"""
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        try:
            url = self._normalize_url(target.value)
            self.log_info(f"Testing for XSS vulnerabilities on {url}")

            # Test for reflected XSS
            reflected_xss = await self._test_reflected_xss(url)

            # Test for stored XSS (basic check)
            # stored_xss = await self._test_stored_xss(url)

            result.data['tested_payloads'] = len(self.payloads)
            result.data['vulnerable_parameters'] = reflected_xss
            result.success = True

            # Report findings
            for xss_info in reflected_xss:
                result.add_vulnerability(
                    title="Cross-Site Scripting (XSS) Vulnerability",
                    description=f"Reflected XSS vulnerability found in parameter '{xss_info['parameter']}'",
                    severity=Severity.HIGH,
                    evidence=f"Parameter: {xss_info['parameter']}, Payload: {xss_info['payload']}, "
                             f"Type: {xss_info['type']}",
                    cve="CWE-79",
                    remediation="Implement proper output encoding/escaping. Use Content-Security-Policy headers. "
                               "Validate and sanitize all user input. Use modern frameworks with built-in XSS protection.",
                    url=xss_info['url']
                )

            if reflected_xss:
                self.log_vuln(f"Found {len(reflected_xss)} XSS vulnerabilities")
            else:
                self.log_info("No XSS vulnerabilities detected")

        except Exception as e:
            result.add_error(str(e))
            self.log_error(f"XSS detection failed: {e}")

        return result

    async def _test_reflected_xss(self, url: str) -> List[Dict[str, Any]]:
        """Test for reflected XSS vulnerabilities"""
        vulnerabilities = []

        # Parse URL to get parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            self.log_info("No URL parameters found to test")
            return vulnerabilities

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Test each parameter
            for param_name in params.keys():
                self.log_debug(f"Testing parameter: {param_name}")

                # Test payloads
                for payload in self.payloads:
                    if self.config.scan_mode.stealth and len(vulnerabilities) > 0:
                        break

                    # Create test payload with marker
                    test_payload = payload.replace("XSS", self.marker)

                    # Inject payload
                    test_url = self._inject_payload(url, param_name, test_payload)

                    try:
                        # Get response
                        async with session.get(test_url, ssl=False) as response:
                            body = await response.text()

                            # Check if payload is reflected
                            if self._is_vulnerable(body, test_payload):
                                vulnerabilities.append({
                                    'parameter': param_name,
                                    'payload': payload,
                                    'type': 'reflected',
                                    'url': test_url,
                                    'evidence': 'Payload reflected in response without encoding'
                                })
                                self.log_vuln(f"XSS vulnerability found in {param_name}")
                                break

                        # Rate limiting
                        if self.config.scan_mode.delay > 0:
                            import asyncio
                            await asyncio.sleep(self.config.scan_mode.delay)

                    except Exception as e:
                        self.log_debug(f"Error testing XSS on {param_name}: {e}")

        return vulnerabilities

    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Inject payload
        params[param_name] = [payload]

        # Rebuild URL
        new_query = urllib.parse.urlencode(params, doseq=True, safe='<>()\'\"')
        new_parsed = parsed._replace(query=new_query)

        return urllib.parse.urlunparse(new_parsed)

    def _is_vulnerable(self, response_body: str, payload: str) -> bool:
        """Check if the response is vulnerable to XSS"""

        # Check for unencoded payload reflection
        if payload in response_body:
            return True

        # Check for marker in various contexts
        if self.marker in response_body:
            # Check if it's in a dangerous context (not encoded)
            dangerous_contexts = [
                f"<script.*?{self.marker}.*?</script>",
                f"on\\w+=['\"].*?{self.marker}.*?['\"]",
                f"<.*?{self.marker}.*?>",
                f"javascript:.*?{self.marker}",
            ]

            for context in dangerous_contexts:
                if re.search(context, response_body, re.IGNORECASE):
                    return True

        return False

    def _normalize_url(self, target: str) -> str:
        """Normalize URL"""
        if not target.startswith('http'):
            return f"http://{target}"
        return target

    def validate_target(self, target: Any) -> bool:
        """Validate if target is suitable for XSS testing"""
        return target.type == 'url'
