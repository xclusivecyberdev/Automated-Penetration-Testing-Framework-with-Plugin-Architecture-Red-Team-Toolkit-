# Plugin Development Guide

This guide explains how to create custom plugins for the RedTeam Penetration Testing Framework.

## Overview

The framework uses a modular plugin architecture where each security test is implemented as a separate Python class. Plugins are dynamically loaded at runtime and executed in dependency order.

## Plugin Structure

### Basic Plugin Template

```python
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity
from typing import Any

class MyPlugin(BasePlugin):
    """Description of what this plugin does"""

    @property
    def category(self) -> PluginCategory:
        """Plugin category"""
        return PluginCategory.VULN_SCAN

    @property
    def description(self) -> str:
        """Human-readable description"""
        return "Detects XYZ vulnerabilities"

    @property
    def version(self) -> str:
        """Plugin version"""
        return "1.0.0"

    @property
    def author(self) -> str:
        """Plugin author"""
        return "Your Name"

    @property
    def dependencies(self) -> list:
        """List of plugin names that must run first"""
        return []  # e.g., ["PortScanner"]

    async def run(self, target: Any) -> PluginResult:
        """
        Main plugin execution logic

        Args:
            target: Target object with properties like .value, .type, .ports

        Returns:
            PluginResult with findings
        """
        # Create result object
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        try:
            self.log_info(f"Starting scan on {target.value}")

            # Your scanning logic here
            # ...

            result.success = True

        except Exception as e:
            result.add_error(str(e))
            self.log_error(f"Scan failed: {e}")

        return result

    def validate_target(self, target: Any) -> bool:
        """
        Check if this plugin should run against the target

        Args:
            target: Target object

        Returns:
            True if plugin can run, False to skip
        """
        # Example: only run on web targets
        return target.type == 'url'
```

## Plugin Categories

### Available Categories

```python
class PluginCategory(Enum):
    RECON = "reconnaissance"           # Information gathering
    VULN_SCAN = "vulnerability_scanning"  # Vulnerability detection
    EXPLOIT = "exploitation"           # Exploitation testing
    POST_EXPLOIT = "post_exploitation"  # Post-exploitation
    REPORTING = "reporting"            # Reporting/analysis
    AUXILIARY = "auxiliary"            # Helper plugins
```

## Working with Results

### Creating Results

```python
result = PluginResult(
    plugin_name=self.name,
    target=target.value,
    success=False  # Set to True when scan completes
)
```

### Adding Vulnerabilities

```python
result.add_vulnerability(
    title="SQL Injection Found",
    description="Parameter 'id' is vulnerable to SQL injection",
    severity=Severity.CRITICAL,
    evidence="Payload: ' OR '1'='1",
    cve="CWE-89",
    remediation="Use parameterized queries",
    url="http://example.com/page?id=1"
)
```

### Adding Data

```python
# Store scan data (ports, versions, etc.)
result.data['open_ports'] = [80, 443, 8080]
result.data['server_version'] = "Apache/2.4.41"
```

### Adding Errors

```python
result.add_error("Connection timeout")
result.add_error("Invalid target format")
```

## Severity Levels

```python
class Severity(Enum):
    INFO = "info"           # Informational finding
    LOW = "low"             # Low risk
    MEDIUM = "medium"       # Medium risk
    HIGH = "high"           # High risk, requires attention
    CRITICAL = "critical"   # Critical risk, immediate action needed
```

## Logging

Use built-in logging methods:

```python
self.log_info("Normal information")
self.log_debug("Debug details")
self.log_error("Error occurred")
self.log_vuln("Vulnerability found!")
self.log_success("Operation successful")
```

## Async Operations

All plugins must use async/await pattern:

```python
async def run(self, target: Any) -> PluginResult:
    # Use async HTTP clients
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            content = await response.text()

    # Use asyncio for concurrent operations
    tasks = [self.check_item(item) for item in items]
    results = await asyncio.gather(*tasks)

    return result
```

## Accessing Configuration

```python
# Scan mode settings
timeout = self.config.scan_mode.timeout
rate_limit = self.config.scan_mode.rate_limit
delay = self.config.scan_mode.delay
stealth_mode = self.config.scan_mode.stealth

# General settings
max_threads = self.config.max_threads
user_agent = self.config.user_agent
proxy = self.config.proxy
```

## Rate Limiting

Respect rate limits to avoid overwhelming targets:

```python
import asyncio

# Use semaphore for concurrent requests
semaphore = asyncio.Semaphore(self.config.scan_mode.rate_limit)

async def check_with_limit(item):
    async with semaphore:
        return await self.check_item(item)

# Add delays between requests
await asyncio.sleep(self.config.scan_mode.delay)
```

## Example Plugins

### Simple Reconnaissance Plugin

```python
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity
import aiohttp

class HeaderAnalyzer(BasePlugin):
    """Analyzes HTTP security headers"""

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.RECON

    @property
    def description(self) -> str:
        return "Analyzes HTTP security headers"

    async def run(self, target: Any) -> PluginResult:
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        url = target.value if target.value.startswith('http') else f'http://{target.value}'

        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False) as response:
                    headers = dict(response.headers)

                    # Check for missing security headers
                    security_headers = [
                        'X-Frame-Options',
                        'X-Content-Type-Options',
                        'Strict-Transport-Security',
                        'Content-Security-Policy'
                    ]

                    missing = [h for h in security_headers if h not in headers]

                    if missing:
                        result.add_vulnerability(
                            title="Missing Security Headers",
                            description=f"Missing headers: {', '.join(missing)}",
                            severity=Severity.LOW,
                            evidence=f"Headers present: {list(headers.keys())}",
                            remediation=f"Add the following headers: {', '.join(missing)}"
                        )

                    result.data['headers'] = headers
                    result.success = True

        except Exception as e:
            result.add_error(str(e))

        return result

    def validate_target(self, target: Any) -> bool:
        return target.type == 'url'
```

### Vulnerability Detection Plugin

```python
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity
import aiohttp

class OpenRedirectDetector(BasePlugin):
    """Detects open redirect vulnerabilities"""

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.VULN_SCAN

    @property
    def description(self) -> str:
        return "Detects open redirect vulnerabilities"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.payloads = [
            'http://evil.com',
            '//evil.com',
            '///evil.com',
            'https://evil.com'
        ]

    async def run(self, target: Any) -> PluginResult:
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        # Test redirect parameters
        redirect_params = ['redirect', 'url', 'next', 'return', 'dest']

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for param in redirect_params:
                for payload in self.payloads:
                    test_url = f"{target.value}?{param}={payload}"

                    try:
                        async with session.get(
                            test_url,
                            allow_redirects=False,
                            ssl=False
                        ) as response:
                            # Check if redirects to payload
                            location = response.headers.get('Location', '')

                            if payload in location:
                                result.add_vulnerability(
                                    title="Open Redirect Vulnerability",
                                    description=f"Parameter '{param}' is vulnerable to open redirect",
                                    severity=Severity.MEDIUM,
                                    evidence=f"Redirects to: {location}",
                                    cve="CWE-601",
                                    remediation="Validate redirect URLs against a whitelist",
                                    url=test_url
                                )

                    except Exception:
                        pass

        result.success = True
        return result

    def validate_target(self, target: Any) -> bool:
        return target.type == 'url'
```

## Plugin Installation

1. Create your plugin file in the appropriate directory:
   - `plugins/recon/` - Reconnaissance plugins
   - `plugins/vuln/` - Vulnerability detection plugins
   - `plugins/exploit/` - Exploitation plugins

2. Name your file: `my_plugin.py`

3. The framework will automatically discover and load it on next run

4. Verify it's loaded:
   ```bash
   python main.py list-plugins
   ```

## Testing Plugins

### Unit Testing

```python
import pytest
from plugins.recon.my_plugin import MyPlugin
from core.config import Config, Target
from core.logger import Logger

@pytest.mark.asyncio
async def test_my_plugin():
    config = Config()
    logger = Logger()
    plugin = MyPlugin(config, logger)

    target = Target(name="test", type="url", value="http://example.com")

    result = await plugin.run(target)

    assert result.success is True
    assert len(result.vulnerabilities) >= 0
```

## Best Practices

### 1. Error Handling

```python
try:
    # Your code
    pass
except SpecificException as e:
    result.add_error(f"Specific error: {e}")
    self.log_error(str(e))
except Exception as e:
    result.add_error(f"Unexpected error: {e}")
    self.log_error(str(e))
finally:
    result.success = True  # Mark as completed even if errors
```

### 2. Respect Timeouts

```python
# Use framework timeout
timeout = aiohttp.ClientTimeout(total=self.timeout)

# Or use asyncio timeout
async with asyncio.timeout(self.timeout):
    await long_running_operation()
```

### 3. Rate Limiting

```python
# Check scan mode
if self.config.scan_mode.stealth:
    # Fewer tests, longer delays
    await asyncio.sleep(2.0)
else:
    # Normal delays
    await asyncio.sleep(self.config.scan_mode.delay)
```

### 4. Clear Evidence

```python
result.add_vulnerability(
    title="Clear, specific title",
    description="Detailed explanation of the issue",
    evidence="Exact proof: payload='<script>alert(1)</script>' was reflected",
    remediation="Specific, actionable fix"
)
```

### 5. Dependencies

```python
@property
def dependencies(self) -> list:
    # This plugin needs port scan results
    return ["PortScanner"]

async def run(self, target: Any) -> PluginResult:
    # Access results from dependencies if needed
    # (Framework ensures they run first)
    pass
```

## Common Patterns

### Web Scanning Pattern

```python
async def scan_web_target(self, url: str) -> dict:
    timeout = aiohttp.ClientTimeout(total=self.timeout)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, ssl=False) as response:
            content = await response.text()
            headers = dict(response.headers)

            return {
                'status': response.status,
                'content': content,
                'headers': headers
            }
```

### Network Scanning Pattern

```python
async def scan_port(self, host: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self.timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False
```

### Concurrent Testing Pattern

```python
async def test_multiple_items(self, items: list) -> list:
    semaphore = asyncio.Semaphore(self.config.scan_mode.rate_limit)

    async def test_with_limit(item):
        async with semaphore:
            return await self.test_item(item)

    tasks = [test_with_limit(item) for item in items]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    return [r for r in results if not isinstance(r, Exception)]
```

## Debugging

### Enable Debug Logging

```python
self.log_debug(f"Testing payload: {payload}")
self.log_debug(f"Response status: {response.status}")
self.log_debug(f"Headers: {headers}")
```

### Check Plugin Loading

```bash
# See if your plugin is discovered
python main.py list-plugins | grep MyPlugin

# Run with debug logging
python -c "from core.plugin_loader import PluginLoader; l = PluginLoader(); print(l.discover_plugins())"
```

## Plugin Repository

Share your plugins with the community:

1. Test thoroughly
2. Document usage
3. Include example targets
4. Follow code style
5. Submit pull request

---

Need help? Check existing plugins in `plugins/` for more examples!
