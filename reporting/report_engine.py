"""
Report generation engine - Creates HTML and PDF security reports
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from jinja2 import Template, Environment, FileSystemLoader
from .risk_scorer import RiskScorer


class ReportEngine:
    """Generate comprehensive security reports"""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.risk_scorer = RiskScorer()

        # Setup Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        template_dir.mkdir(exist_ok=True)

        try:
            self.jinja_env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=True
            )
        except:
            self.jinja_env = None

    def generate_report(
        self,
        session_data: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        statistics: Dict[str, Any],
        output_format: str = "html"
    ) -> str:
        """
        Generate comprehensive security report

        Args:
            session_data: Session information
            vulnerabilities: List of discovered vulnerabilities
            statistics: Scan statistics
            output_format: Output format (html, json, pdf)

        Returns:
            Path to generated report
        """

        # Enrich vulnerabilities with risk scores
        enriched_vulns = self._enrich_vulnerabilities(vulnerabilities)

        # Calculate aggregate risk
        aggregate_risk = self.risk_scorer.calculate_aggregate_risk(enriched_vulns)

        # Get prioritized list
        prioritized_vulns = self.risk_scorer.get_remediation_priority(enriched_vulns)

        # Generate executive summary
        executive_summary = self.risk_scorer.generate_executive_summary(aggregate_risk)

        # Prepare report data
        report_data = {
            'session': session_data,
            'vulnerabilities': prioritized_vulns,
            'statistics': statistics,
            'aggregate_risk': aggregate_risk,
            'executive_summary': executive_summary,
            'generated_at': datetime.now().isoformat(),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Generate report based on format
        if output_format == "html":
            return self._generate_html_report(report_data)
        elif output_format == "json":
            return self._generate_json_report(report_data)
        elif output_format == "pdf":
            return self._generate_pdf_report(report_data)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def _enrich_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich vulnerabilities with risk scores"""

        enriched = []

        for vuln in vulnerabilities:
            # Calculate risk score
            risk_data = self.risk_scorer.calculate_risk_score(
                vuln,
                asset_value=vuln.get('asset_value', 5),
                exploitability=vuln.get('exploitability', 'network'),
                impact=vuln.get('impact', 'partial')
            )

            vuln['risk_score_data'] = risk_data
            enriched.append(vuln)

        return enriched

    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report"""

        # Use inline template if external template not available
        html_template = self._get_html_template()

        try:
            if self.jinja_env:
                template = self.jinja_env.from_string(html_template)
            else:
                template = Template(html_template)

            html_content = template.render(**data)

        except Exception as e:
            # Fallback to simple HTML
            html_content = self._generate_simple_html(data)

        # Save report
        session_id = data['session'].get('session_id', 'unknown')
        report_path = self.output_dir / f"report_{session_id}.html"

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(report_path)

    def _generate_json_report(self, data: Dict[str, Any]) -> str:
        """Generate JSON report"""

        session_id = data['session'].get('session_id', 'unknown')
        report_path = self.output_dir / f"report_{session_id}.json"

        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

        return str(report_path)

    def _generate_pdf_report(self, data: Dict[str, Any]) -> str:
        """Generate PDF report (using HTML to PDF conversion)"""

        try:
            from weasyprint import HTML

            # First generate HTML
            html_path = self._generate_html_report(data)

            # Convert to PDF
            session_id = data['session'].get('session_id', 'unknown')
            pdf_path = self.output_dir / f"report_{session_id}.pdf"

            HTML(html_path).write_pdf(pdf_path)

            return str(pdf_path)

        except ImportError:
            # WeasyPrint not available, just return HTML
            print("WeasyPrint not installed. Generating HTML report instead.")
            return self._generate_html_report(data)

    def _get_html_template(self) -> str:
        """Get HTML template"""

        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; background: white; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; margin: -20px -20px 30px; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin: 30px 0 20px; }
        h3 { color: #555; margin: 20px 0 10px; }
        .meta { font-size: 0.9em; opacity: 0.9; }
        .summary-box { background: #f8f9fa; border-left: 4px solid #667eea; padding: 20px; margin: 20px 0; border-radius: 4px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: white; border: 1px solid #ddd; padding: 20px; text-align: center; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2.5em; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; font-size: 0.9em; margin-top: 5px; }
        .vuln-card { background: white; border: 1px solid #ddd; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid; }
        .vuln-card.critical { border-left-color: #dc3545; }
        .vuln-card.high { border-left-color: #fd7e14; }
        .vuln-card.medium { border-left-color: #ffc107; }
        .vuln-card.low { border-left-color: #28a745; }
        .vuln-card.info { border-left-color: #17a2b8; }
        .severity-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; color: white; font-size: 0.85em; font-weight: bold; }
        .severity-badge.critical { background: #dc3545; }
        .severity-badge.high { background: #fd7e14; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #28a745; }
        .severity-badge.info { background: #17a2b8; }
        .risk-score { font-size: 1.2em; font-weight: bold; }
        .evidence { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 4px; font-family: monospace; font-size: 0.9em; overflow-x: auto; }
        .remediation { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; margin: 10px 0; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #667eea; color: white; }
        tr:hover { background: #f8f9fa; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid #ddd; text-align: center; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Penetration Test Report</h1>
            <div class="meta">
                <p>Session ID: {{ session.session_id }}</p>
                <p>Generated: {{ timestamp }}</p>
                <p>Status: {{ session.status }}</p>
            </div>
        </header>

        <section class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-box">
                <p>{{ executive_summary }}</p>
            </div>
        </section>

        <section class="statistics">
            <h2>Scan Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{{ statistics.total_targets }}</div>
                    <div class="stat-label">Targets Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ statistics.completed_plugins }}</div>
                    <div class="stat-label">Plugins Executed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ statistics.total_vulnerabilities }}</div>
                    <div class="stat-label">Vulnerabilities Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ "%.2f"|format(aggregate_risk.average_risk_score) }}</div>
                    <div class="stat-label">Average Risk Score</div>
                </div>
            </div>

            <h3>Severity Distribution</h3>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                <tr><td>Critical</td><td>{{ aggregate_risk.critical_count }}</td></tr>
                <tr><td>High</td><td>{{ aggregate_risk.high_count }}</td></tr>
                <tr><td>Medium</td><td>{{ aggregate_risk.medium_count }}</td></tr>
                <tr><td>Low</td><td>{{ aggregate_risk.low_count }}</td></tr>
                <tr><td>Info</td><td>{{ aggregate_risk.info_count }}</td></tr>
            </table>
        </section>

        <section class="vulnerabilities">
            <h2>Vulnerability Details</h2>
            {% for vuln in vulnerabilities %}
            <div class="vuln-card {{ vuln.severity }}">
                <h3>{{ vuln.title }}</h3>
                <p>
                    <span class="severity-badge {{ vuln.severity }}">{{ vuln.severity|upper }}</span>
                    {% if vuln.risk_score_data %}
                    <span class="risk-score">Risk Score: {{ "%.2f"|format(vuln.risk_score_data.risk_score) }}/10</span>
                    {% endif %}
                    {% if vuln.cve %}
                    <span style="margin-left: 10px; color: #666;">{{ vuln.cve }}</span>
                    {% endif %}
                </p>

                <p><strong>Target:</strong> {{ vuln.target }}</p>
                <p><strong>Plugin:</strong> {{ vuln.plugin }}</p>

                <p><strong>Description:</strong></p>
                <p>{{ vuln.description }}</p>

                {% if vuln.evidence %}
                <p><strong>Evidence:</strong></p>
                <div class="evidence">{{ vuln.evidence }}</div>
                {% endif %}

                {% if vuln.remediation %}
                <p><strong>Remediation:</strong></p>
                <div class="remediation">{{ vuln.remediation }}</div>
                {% endif %}

                {% if vuln.url %}
                <p><strong>URL:</strong> <a href="{{ vuln.url }}">{{ vuln.url }}</a></p>
                {% endif %}
            </div>
            {% endfor %}
        </section>

        <div class="footer">
            <p>This report was automatically generated by the RedTeam Penetration Testing Framework</p>
            <p>Report generated on {{ timestamp }}</p>
        </div>
    </div>
</body>
</html>
        """

    def _generate_simple_html(self, data: Dict[str, Any]) -> str:
        """Generate simple HTML report (fallback)"""

        html = "<html><head><title>Penetration Test Report</title></head><body>"
        html += f"<h1>Penetration Test Report</h1>"
        html += f"<p>Session: {data['session'].get('session_id', 'unknown')}</p>"
        html += f"<p>Generated: {data['timestamp']}</p>"
        html += f"<h2>Vulnerabilities Found: {len(data['vulnerabilities'])}</h2>"

        for vuln in data['vulnerabilities']:
            html += f"<div style='border: 1px solid #ccc; margin: 10px; padding: 10px;'>"
            html += f"<h3>{vuln.get('title', 'Unknown')}</h3>"
            html += f"<p><strong>Severity:</strong> {vuln.get('severity', 'unknown')}</p>"
            html += f"<p>{vuln.get('description', '')}</p>"
            html += "</div>"

        html += "</body></html>"

        return html
