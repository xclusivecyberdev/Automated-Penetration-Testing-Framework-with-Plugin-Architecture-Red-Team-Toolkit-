# Usage Guide

Comprehensive guide for using the RedTeam Penetration Testing Framework.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Command Reference](#command-reference)
4. [Configuration](#configuration)
5. [Scan Modes](#scan-modes)
6. [Working with Reports](#working-with-reports)
7. [Web Interface](#web-interface)
8. [Advanced Usage](#advanced-usage)
9. [Best Practices](#best-practices)

## Installation

### Standard Installation

```bash
# Clone repository
git clone <repo-url>
cd Automated-Penetration-Testing-Framework-with-Plugin-Architecture-Red-Team-Toolkit-

# Install dependencies
pip install -r requirements.txt

# Verify installation
python main.py --version
```

### Docker Installation

```bash
# Build image
docker build -t pentest-framework .

# Run scan
docker run -v $(pwd)/output:/app/output pentest-framework scan -t example.com

# Run web interface
docker-compose up pentest-web
```

### Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install
pip install -r requirements.txt
```

## Quick Start

### Single Target Scan

```bash
# Scan a website
python main.py scan -t http://example.com

# Scan a server
python main.py scan -t 192.168.1.100

# Scan with specific mode
python main.py scan -t example.com -m aggressive
```

### Multi-Target Scan

```bash
# Create config file
cat > targets.yaml << EOF
scan_mode: normal
targets:
  - name: web1
    type: url
    value: http://example.com
  - name: web2
    type: url
    value: http://test.com
EOF

# Run scan
python main.py scan -c targets.yaml
```

## Command Reference

### scan

Run a penetration test scan.

```bash
python main.py scan [OPTIONS]

Options:
  -c, --config PATH        Configuration file path
  -t, --target TEXT        Target URL or IP address
  -m, --mode [safe|normal|aggressive|stealth]  Scan mode
  -o, --output PATH        Output directory
  --resume TEXT            Resume session ID
  --name TEXT              Session name
```

Examples:

```bash
# Basic scan
python main.py scan -t http://example.com

# Safe mode scan
python main.py scan -t example.com -m safe

# Named session
python main.py scan -t example.com --name "Production Audit"

# Resume paused scan
python main.py scan --resume 20240115_143022

# Custom output directory
python main.py scan -t example.com -o /tmp/scan_results
```

### list-plugins

List all available plugins.

```bash
python main.py list-plugins
```

Output shows:
- Plugin name
- Category
- Description
- Version
- Enabled/disabled status

### list-sessions

List previous scan sessions.

```bash
python main.py list-sessions [OPTIONS]

Options:
  --limit INTEGER  Number of sessions to show (default: 10)
```

### show-session

Show details of a specific session.

```bash
python main.py show-session SESSION_ID
```

Example:

```bash
python main.py show-session 20240115_143022
```

### create-config

Create a sample configuration file.

```bash
python main.py create-config -t TARGET -o OUTPUT_FILE

Options:
  -t, --target TEXT   Target URL or host
  -o, --output TEXT   Output config file (default: targets.yaml)
```

Example:

```bash
python main.py create-config -t http://example.com -o my_scan.yaml
```

## Configuration

### Configuration File Format

```yaml
# Scan mode
scan_mode: normal  # safe, normal, aggressive, stealth

# Target definitions
targets:
  # Web application
  - name: webapp_prod
    type: url
    value: https://app.example.com
    priority: 10  # 1-10, higher = more important
    tags:
      - production
      - critical

  # Network host
  - name: database_server
    type: host
    value: 192.168.1.50
    ports:  # Specific ports to scan
      - 22
      - 3306
      - 5432
    exclude_ports:  # Ports to skip
      - 25
    priority: 8

  # Network range
  - name: internal_network
    type: network
    value: 192.168.1.0/24
    priority: 5

# Plugin configuration
enabled_plugins:  # Only run these (empty = all)
  - PortScanner
  - ServiceEnumerator
  - SQLInjectionDetector

disabled_plugins:  # Skip these
  - DirectoryBruteForce

# General settings
max_threads: 10
output_dir: output
user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Proxy settings (optional)
proxy: http://127.0.0.1:8080
```

### Target Types

#### URL Target

```yaml
- name: my_website
  type: url
  value: https://example.com
```

Best for:
- Web applications
- Web services
- API endpoints

#### Host Target

```yaml
- name: my_server
  type: host
  value: 192.168.1.100
  ports: [22, 80, 443, 3306]
```

Best for:
- Individual servers
- Network devices
- Specific systems

#### Network Target

```yaml
- name: my_network
  type: network
  value: 192.168.1.0/24
```

Best for:
- Network ranges
- Subnets
- Mass scanning

## Scan Modes

### Safe Mode

Conservative, minimal-impact scanning.

```yaml
scan_mode: safe
```

Characteristics:
- Rate: 5 requests/second
- Timeout: 10 seconds
- Retries: 2
- Delay: 1 second
- Stealth: Yes

Use when:
- Scanning production systems
- Fragile applications
- High-traffic sites
- Compliance requirements

### Normal Mode

Balanced approach for general assessments.

```yaml
scan_mode: normal
```

Characteristics:
- Rate: 20 requests/second
- Timeout: 5 seconds
- Retries: 1
- Delay: 0.5 seconds
- Stealth: No

Use when:
- Standard security assessments
- Development/staging environments
- Balanced speed vs. safety

### Aggressive Mode

Fast, comprehensive scanning.

```yaml
scan_mode: aggressive
```

Characteristics:
- Rate: 100 requests/second
- Timeout: 3 seconds
- Retries: 0
- Delay: 0.1 seconds
- Stealth: No

Use when:
- Authorized testing environments
- Time-constrained assessments
- Maximum coverage needed
- Robust target systems

### Stealth Mode

Slow, careful scanning to avoid detection.

```yaml
scan_mode: stealth
```

Characteristics:
- Rate: 2 requests/second
- Timeout: 15 seconds
- Retries: 3
- Delay: 2 seconds
- Stealth: Yes

Use when:
- IDS/IPS present
- Want to avoid detection
- Red team engagements
- Testing monitoring systems

## Working with Reports

### Generating Reports

Reports are automatically generated after scan completion in multiple formats:

- `report_<session_id>.html` - Interactive HTML report
- `report_<session_id>.json` - Machine-readable data
- `report_<session_id>.pdf` - PDF report (if WeasyPrint installed)

### Report Sections

#### Executive Summary

High-level overview:
- Total vulnerabilities
- Risk assessment
- Recommended actions

#### Statistics

- Targets scanned
- Plugins executed
- Vulnerability counts by severity
- Average risk score

#### Vulnerability Details

For each vulnerability:
- Title and description
- Severity level
- Risk score (0-10)
- Evidence/proof
- CVE reference (if applicable)
- Remediation steps
- Affected URL/target

### Viewing Reports

```bash
# HTML report (open in browser)
firefox output/report_20240115_143022.html

# JSON report (process with tools)
cat output/report_20240115_143022.json | jq '.vulnerabilities[] | select(.severity=="critical")'
```

### Report Customization

Modify report templates in `reporting/templates/`:
- Edit HTML/CSS styling
- Add custom sections
- Include company branding

## Web Interface

### Starting the Web Server

```bash
# Start server
python web/app.py

# Access dashboard
firefox http://localhost:5000
```

### Web Features

#### Dashboard

- Real-time scan status
- Live vulnerability updates
- Statistics display
- Session management

#### Starting Scans

1. Enter target URL/IP
2. Select scan mode
3. Optional: Name the session
4. Click "Start Scan"
5. Monitor progress in real-time

#### WebSocket Updates

The interface uses WebSockets for live updates:
- Scan progress
- New vulnerabilities
- Status changes
- Completion notifications

### API Endpoints

```bash
# Get plugin list
curl http://localhost:5000/api/plugins

# Get sessions
curl http://localhost:5000/api/sessions

# Get session details
curl http://localhost:5000/api/session/20240115_143022

# Start scan
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target": "http://example.com", "mode": "normal"}'

# Get scan status
curl http://localhost:5000/api/scan/status

# Pause scan
curl -X POST http://localhost:5000/api/scan/pause
```

## Advanced Usage

### Session Management

#### Pausing Scans

Press `Ctrl+C` during scan to pause:

```bash
python main.py scan -t example.com
# Press Ctrl+C
^C
Scan paused. Session ID: 20240115_143022
```

#### Resuming Scans

```bash
python main.py scan --resume 20240115_143022
```

#### Session Details

```bash
# View session info
python main.py show-session 20240115_143022

# List all sessions
python main.py list-sessions --limit 20
```

### Plugin Management

#### Enabling Specific Plugins

```yaml
enabled_plugins:
  - PortScanner
  - ServiceEnumerator
  - SQLInjectionDetector
```

#### Disabling Plugins

```yaml
disabled_plugins:
  - DirectoryBruteForce  # Too noisy
  - XSSDetector          # Not needed
```

### Output Management

#### Custom Output Directory

```bash
python main.py scan -t example.com -o /custom/path
```

#### Session Logs

Logs are stored in `logs/`:

```bash
# View latest log
tail -f logs/pentest_framework_*.log

# Search for vulnerabilities
grep "VULN" logs/pentest_framework_*.log
```

## Best Practices

### 1. Authorization

✅ DO:
- Obtain written authorization
- Define scope clearly
- Document approval
- Respect boundaries

❌ DON'T:
- Scan without permission
- Exceed authorized scope
- Test production without approval

### 2. Target Selection

✅ DO:
- Start with safe mode
- Test one target first
- Verify scope
- Use appropriate mode

❌ DON'T:
- Scan entire networks blindly
- Use aggressive mode on production
- Skip target validation

### 3. Monitoring

✅ DO:
- Monitor scan progress
- Watch for errors
- Review findings
- Check logs

❌ DON'T:
- Leave scans unattended
- Ignore errors
- Skip result validation

### 4. Reporting

✅ DO:
- Generate comprehensive reports
- Include remediation steps
- Prioritize by risk
- Follow up on critical issues

❌ DON'T:
- Report without context
- Skip severity assessment
- Ignore false positives

### 5. Rate Limiting

✅ DO:
- Use safe mode for production
- Respect server resources
- Implement delays
- Monitor target load

❌ DON'T:
- DoS the target
- Ignore timeouts
- Overwhelm services

### 6. Security

✅ DO:
- Secure scan results
- Encrypt sensitive data
- Control access to reports
- Store safely

❌ DON'T:
- Share reports publicly
- Leave results exposed
- Commit sensitive data to git

## Troubleshooting

### Common Issues

#### No vulnerabilities found

```bash
# Check plugins loaded
python main.py list-plugins

# Verify target accessible
curl -I http://example.com

# Use more aggressive mode
python main.py scan -t example.com -m aggressive
```

#### Timeout errors

```yaml
# Increase timeout in config
scan_mode: safe
timeout: 30
```

#### Plugin not loading

```bash
# Check plugin syntax
python -m py_compile plugins/vuln/my_plugin.py

# Verify plugin directory
ls -la plugins/*/

# Check logs
grep "ERROR" logs/pentest_framework_*.log
```

#### Permission denied

```bash
# Some scans require privileges
sudo python main.py scan -t example.com

# Or adjust file permissions
chmod +x main.py
```

### Getting Help

1. Check documentation in `/docs`
2. Review example configs in `/configs`
3. Examine existing plugins in `/plugins`
4. Check logs in `/logs`
5. Create GitHub issue with details

---

Happy (ethical) hacking! 🔒
