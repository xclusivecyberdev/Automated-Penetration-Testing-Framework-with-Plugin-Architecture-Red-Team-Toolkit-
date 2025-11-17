# 🔒 RedTeam Penetration Testing Framework

A comprehensive, modular penetration testing framework with plugin architecture for automated security assessments. This framework combines reconnaissance, vulnerability scanning, exploitation testing, and reporting into a unified platform.

## 🌟 Features

### Core Capabilities
- **Modular Plugin Architecture**: Dynamically loadable plugins with dependency management
- **Multi-Target Support**: Scan web applications, networks, and individual hosts
- **Comprehensive Scanning**: Port scanning, service enumeration, CMS fingerprinting
- **Vulnerability Detection**: SQL injection, XSS, SSRF, directory brute forcing
- **Exploitation Testing**: Safe exploitation simulations and privilege escalation checks
- **Advanced Reporting**: HTML/PDF reports with risk scoring and remediation guidance
- **Real-Time Monitoring**: Web interface for live scan monitoring
- **Session Management**: Pause, resume, and track multiple scan sessions

### Scan Modes
- **Safe Mode**: Conservative scanning with minimal impact
- **Normal Mode**: Balanced approach for general assessments
- **Aggressive Mode**: Comprehensive scanning with higher detection rates
- **Stealth Mode**: Slow, careful scanning to avoid detection

## 📋 Requirements

- Python 3.8+
- Linux/Unix environment (recommended)
- Network access to target systems
- Appropriate authorization for security testing

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd Automated-Penetration-Testing-Framework-with-Plugin-Architecture-Red-Team-Toolkit-

# Install dependencies
pip install -r requirements.txt

# Make main script executable
chmod +x main.py
```

### Basic Usage

```bash
# Scan a single target
python main.py scan -t http://example.com

# Scan with custom mode
python main.py scan -t http://example.com -m aggressive

# Use configuration file
python main.py scan -c configs/sample_targets.yaml

# List available plugins
python main.py list-plugins

# View scan sessions
python main.py list-sessions
```

### Docker Deployment

```bash
# Build and run CLI
docker-compose up pentest-cli

# Run web interface
docker-compose up pentest-web

# Access web dashboard at http://localhost:5000
```

## 📚 Documentation

### Configuration File

Create a YAML configuration file to define targets and settings:

```yaml
scan_mode: normal

targets:
  - name: my_webapp
    type: url
    value: http://example.com
    priority: 8
    tags:
      - web
      - production

  - name: my_server
    type: host
    value: 192.168.1.100
    ports:
      - 22
      - 80
      - 443

max_threads: 10
output_dir: output
```

### Plugin Categories

#### Reconnaissance Modules
- **PortScanner**: Advanced port scanning with service detection
- **ServiceEnumerator**: Service version detection and analysis
- **CMSFingerprint**: CMS detection (WordPress, Joomla, Drupal, etc.)

#### Vulnerability Detection Modules
- **SQLInjectionDetector**: SQL injection vulnerability scanner
- **XSSDetector**: Cross-site scripting vulnerability scanner
- **SSRFDetector**: Server-side request forgery detection
- **DirectoryBruteForce**: Hidden directory and file discovery

#### Exploitation Modules
- **PrivilegeEscalationChecker**: Privilege escalation vector detection
- **WeakSSHDetector**: SSH security configuration checker

## 🎯 Use Cases

### Web Application Security Testing
```bash
python main.py scan -t https://webapp.example.com -m normal
```

### Network Security Assessment
```bash
python main.py scan -t 192.168.1.0/24 -m aggressive
```

### Compliance Scanning
```bash
python main.py scan -c compliance_targets.yaml -m safe
```

## 📊 Reports

The framework generates comprehensive reports including:

- **Executive Summary**: High-level risk overview
- **Vulnerability Details**: Detailed findings with evidence
- **Risk Scoring**: CVSS-like risk calculation
- **Remediation Guidance**: Step-by-step fix recommendations
- **CVE References**: Links to known vulnerabilities
- **Severity Distribution**: Visual breakdown of findings

Reports are generated in multiple formats:
- HTML (interactive, styled reports)
- JSON (machine-readable data)
- PDF (professional documentation)

## 🔌 Plugin Development

See [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) for detailed plugin creation guide.

### Quick Plugin Example

```python
from plugins.base import BasePlugin, PluginResult, PluginCategory, Severity

class MyCustomPlugin(BasePlugin):
    @property
    def category(self) -> PluginCategory:
        return PluginCategory.VULN_SCAN

    @property
    def description(self) -> str:
        return "My custom security check"

    async def run(self, target: Any) -> PluginResult:
        result = PluginResult(
            plugin_name=self.name,
            target=target.value,
            success=False
        )

        # Your scanning logic here

        return result
```

## 🌐 Web Interface

Start the web interface for real-time monitoring:

```bash
python web/app.py
```

Access the dashboard at `http://localhost:5000`

Features:
- Start/pause scans from browser
- Real-time vulnerability updates
- Session management
- Statistics dashboard
- WebSocket-based live updates

## 🔒 Security & Ethics

### Important Notes

⚠️ **AUTHORIZATION REQUIRED**: Only use this framework on systems you own or have explicit written permission to test.

⚠️ **LEGAL COMPLIANCE**: Unauthorized security testing is illegal. Always obtain proper authorization.

⚠️ **RESPONSIBLE DISCLOSURE**: Report discovered vulnerabilities responsibly to affected parties.

### Safe Usage Guidelines

1. **Always obtain written authorization** before scanning
2. **Use safe mode** for production systems
3. **Implement rate limiting** to avoid DoS conditions
4. **Review findings** before reporting
5. **Follow responsible disclosure** practices

## 🛠️ Advanced Usage

### Session Management

```bash
# Resume a paused session
python main.py scan --resume <session-id>

# View session details
python main.py show-session <session-id>

# List all sessions
python main.py list-sessions
```

### Custom Configuration

```bash
# Create configuration template
python main.py create-config -t example.com -o my_config.yaml

# Edit configuration
vim my_config.yaml

# Run with configuration
python main.py scan -c my_config.yaml
```

## 📈 Performance Tuning

### Rate Limiting

Adjust scan speed in configuration:

```yaml
scan_mode: custom  # Define custom mode
rate_limit: 50     # Requests per second
timeout: 10        # Request timeout (seconds)
delay: 0.5         # Delay between requests (seconds)
```

### Threading

Control concurrent operations:

```yaml
max_threads: 20    # Maximum concurrent threads
```

## 🐛 Troubleshooting

### Common Issues

**Issue**: Plugins not loading
```bash
# Check plugin directory
ls -la plugins/

# Verify Python path
python -c "import sys; print(sys.path)"
```

**Issue**: Connection timeouts
```yaml
# Increase timeout in config
scan_mode: safe
timeout: 30
```

**Issue**: Permission denied
```bash
# Run with appropriate permissions
# Some scans may require elevated privileges
sudo python main.py scan -t <target>
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Write tests for new plugins
4. Follow PEP 8 style guidelines
5. Submit pull request with detailed description

## 📝 License

This framework is for educational and authorized security testing purposes only.

## 🙏 Acknowledgments

Inspired by industry-standard tools:
- Metasploit Framework
- OpenVAS
- Burp Suite
- OWASP ZAP

## 📞 Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Check documentation in `/docs`
- Review example configurations in `/configs`

## 🔄 Version History

### v1.0.0 (Current)
- Initial release
- Core plugin system
- 7 security scanning plugins
- HTML/JSON/PDF reporting
- Web interface
- Session management
- Docker support

---

**Remember**: With great power comes great responsibility. Use this framework ethically and legally.
