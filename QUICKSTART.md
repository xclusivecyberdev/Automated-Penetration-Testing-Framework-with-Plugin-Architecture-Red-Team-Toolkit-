# Quick Start Guide

Get started with the RedTeam Penetration Testing Framework in 5 minutes!

## Installation

```bash
# Navigate to the framework directory
cd Automated-Penetration-Testing-Framework-with-Plugin-Architecture-Red-Team-Toolkit-

# Install dependencies
pip install -r requirements.txt
```

## Basic Usage

### 1. Test Installation

```bash
# Check that everything works
python main.py --version

# List available plugins
python main.py list-plugins
```

You should see 7+ plugins loaded across different categories.

### 2. Run Your First Scan

```bash
# Scan a test target (use your own authorized target)
python main.py scan -t http://testphp.vulnweb.com

# This will:
# - Run all enabled plugins
# - Detect vulnerabilities
# - Generate reports
# - Save results in output/
```

### 3. View Results

```bash
# Find your report
ls -lh output/

# Open HTML report in browser
firefox output/report_*.html

# Or view JSON report
cat output/report_*.json | jq .
```

## Using Different Scan Modes

### Safe Mode (Production Systems)

```bash
python main.py scan -t http://your-production-site.com -m safe
```

- Slowest, safest
- 5 requests/second
- Good for production

### Normal Mode (Default)

```bash
python main.py scan -t http://test-site.com -m normal
```

- Balanced speed/safety
- 20 requests/second
- General purpose

### Aggressive Mode (Test Environments)

```bash
python main.py scan -t http://test-lab.local -m aggressive
```

- Fastest scanning
- 100 requests/second
- Test environments only

### Stealth Mode (Evasion)

```bash
python main.py scan -t http://target.com -m stealth
```

- Very slow, careful
- 2 requests/second
- Avoid detection

## Multi-Target Scanning

### Create a Config File

```bash
# Create config
cat > my_targets.yaml << EOF
scan_mode: normal

targets:
  - name: webapp
    type: url
    value: http://testphp.vulnweb.com
    priority: 10

  - name: server
    type: host
    value: scanme.nmap.org
    priority: 8
EOF

# Run scan
python main.py scan -c my_targets.yaml
```

## Using the Web Interface

### Start the Web Server

```bash
# Start server
python web/app.py

# Open browser
firefox http://localhost:5000
```

### Use the Dashboard

1. Enter target URL
2. Select scan mode
3. Click "Start Scan"
4. Watch real-time updates
5. View results

## Docker Usage

### Build and Run

```bash
# Build image
docker build -t pentest-framework .

# Run CLI scan
docker run -v $(pwd)/output:/app/output \
  pentest-framework scan -t http://testphp.vulnweb.com

# Or use docker-compose for web interface
docker-compose up pentest-web
```

## Session Management

### Pause and Resume

```bash
# Start a scan
python main.py scan -t http://example.com --name "My Audit"

# Press Ctrl+C to pause
^C

# View sessions
python main.py list-sessions

# Resume the scan
python main.py scan --resume <session-id>
```

## Example: Complete Workflow

```bash
# 1. Create config for your targets
python main.py create-config -t http://myapp.com -o myapp.yaml

# 2. Edit config as needed
vim myapp.yaml

# 3. Run scan
python main.py scan -c myapp.yaml --name "MyApp Security Audit"

# 4. View progress
tail -f logs/pentest_framework_*.log

# 5. After completion, view report
firefox output/report_*.html

# 6. Review vulnerabilities
cat output/report_*.json | jq '.vulnerabilities[] | select(.severity=="critical")'
```

## Testing Individual Plugins

### List Plugins

```bash
python main.py list-plugins
```

### Enable Only Specific Plugins

Edit config:

```yaml
scan_mode: normal

targets:
  - name: test
    type: url
    value: http://testphp.vulnweb.com

enabled_plugins:
  - PortScanner
  - SQLInjectionDetector
```

## Common Test Targets

**WARNING: Only use these for testing with permission!**

### Intentionally Vulnerable Apps

- http://testphp.vulnweb.com (Acunetix test site)
- http://testhtml5.vulnweb.com (HTML5 test site)
- http://testasp.vulnweb.com (ASP test site)

### Your Own Test Lab

Set up your own:

```bash
# DVWA (Damn Vulnerable Web App)
docker run -p 80:80 vulnerables/web-dvwa

# Then scan
python main.py scan -t http://localhost
```

## Understanding Reports

### HTML Report Sections

1. **Executive Summary**: High-level overview
2. **Statistics**: Numbers and metrics
3. **Severity Distribution**: Critical, High, Medium, Low counts
4. **Vulnerability Details**: Full findings with:
   - Title and description
   - Severity level
   - Risk score (0-10)
   - Evidence/proof
   - CVE reference
   - Remediation steps

### Risk Scores

- **0-3**: Low risk
- **4-6**: Medium risk
- **7-8**: High risk
- **9-10**: Critical risk

## Troubleshooting

### No plugins found

```bash
# Check directory structure
ls -la plugins/*/

# Verify Python can import
python -c "from plugins.base import BasePlugin; print('OK')"
```

### Connection errors

```bash
# Test target is reachable
curl -I http://your-target.com

# Check firewall/network
ping your-target.com
```

### Permission denied

```bash
# Make script executable
chmod +x main.py

# Or use python directly
python main.py scan -t target.com
```

## Next Steps

1. Read the full [README](README.md)
2. Check [Usage Guide](docs/USAGE_GUIDE.md)
3. Learn [Plugin Development](docs/PLUGIN_DEVELOPMENT.md)
4. Review sample configs in `configs/`
5. Explore existing plugins in `plugins/`

## Safety Reminders

⚠️ **IMPORTANT**:

1. **Only scan authorized targets**
2. **Get written permission**
3. **Use safe mode on production**
4. **Report responsibly**
5. **Follow the law**

## Getting Help

- Check documentation in `/docs`
- Review examples in `/configs`
- Examine plugin code in `/plugins`
- Create an issue on GitHub

---

Happy (ethical) hacking! 🔒
