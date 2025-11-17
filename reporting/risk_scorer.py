"""
Risk scoring model for vulnerability assessment
"""

from typing import Dict, Any, List
from plugins.base import Severity


class RiskScorer:
    """
    Calculate risk scores based on CVSS-like methodology
    considering severity, exploitability, and business impact
    """

    def __init__(self):
        # Base scores for severity levels
        self.severity_scores = {
            'critical': 10.0,
            'high': 8.0,
            'medium': 5.0,
            'low': 3.0,
            'info': 0.0
        }

        # Exploitability factors
        self.exploitability_factors = {
            'network': 1.0,      # Remotely exploitable
            'adjacent': 0.9,     # Adjacent network
            'local': 0.7,        # Local access required
            'physical': 0.5      # Physical access required
        }

        # Impact factors
        self.impact_factors = {
            'complete': 1.0,     # Complete system compromise
            'partial': 0.7,      # Partial compromise
            'limited': 0.4       # Limited impact
        }

    def calculate_risk_score(
        self,
        vulnerability: Dict[str, Any],
        asset_value: int = 5,  # 1-10
        exploitability: str = 'network',
        impact: str = 'partial'
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score

        Args:
            vulnerability: Vulnerability details
            asset_value: Importance of the asset (1-10)
            exploitability: How easily exploitable (network, adjacent, local, physical)
            impact: Potential impact (complete, partial, limited)

        Returns:
            Dictionary with risk score and details
        """

        # Get base severity score
        severity = vulnerability.get('severity', 'info')
        base_score = self.severity_scores.get(severity, 0.0)

        # Apply exploitability factor
        exploit_factor = self.exploitability_factors.get(exploitability, 1.0)

        # Apply impact factor
        impact_factor = self.impact_factors.get(impact, 0.7)

        # Calculate technical score (base * exploitability)
        technical_score = base_score * exploit_factor

        # Apply impact to get impact score
        impact_score = technical_score * impact_factor

        # Normalize asset value (0-1)
        asset_factor = asset_value / 10.0

        # Calculate final risk score (0-10)
        # Risk = (Technical Score * Impact Factor) * Asset Value Weight
        risk_score = impact_score * (0.7 + (0.3 * asset_factor))

        # Ensure score is within bounds
        risk_score = min(10.0, max(0.0, risk_score))

        # Determine risk level
        risk_level = self._get_risk_level(risk_score)

        # Calculate likelihood score
        likelihood = self._calculate_likelihood(
            exploit_factor,
            vulnerability.get('cve') is not None
        )

        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'base_score': base_score,
            'technical_score': round(technical_score, 2),
            'impact_score': round(impact_score, 2),
            'likelihood': likelihood,
            'exploitability': exploitability,
            'impact': impact,
            'asset_value': asset_value,
            'severity': severity
        }

    def _get_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 1.0:
            return "Low"
        else:
            return "Informational"

    def _calculate_likelihood(self, exploit_factor: float, has_cve: bool) -> str:
        """Calculate exploitation likelihood"""
        score = exploit_factor

        # Public exploit increases likelihood
        if has_cve:
            score += 0.2

        if score >= 0.9:
            return "High"
        elif score >= 0.6:
            return "Medium"
        else:
            return "Low"

    def calculate_aggregate_risk(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate aggregate risk across all vulnerabilities

        Args:
            vulnerabilities: List of vulnerabilities with risk scores

        Returns:
            Aggregate risk metrics
        """

        if not vulnerabilities:
            return {
                'total_risk_score': 0.0,
                'average_risk_score': 0.0,
                'risk_distribution': {},
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0
            }

        # Count by severity
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        total_risk = 0.0

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            counts[severity] = counts.get(severity, 0) + 1

            # Add to total risk
            risk_data = vuln.get('risk_score_data', {})
            total_risk += risk_data.get('risk_score', 0)

        # Calculate metrics
        avg_risk = total_risk / len(vulnerabilities) if vulnerabilities else 0

        return {
            'total_risk_score': round(total_risk, 2),
            'average_risk_score': round(avg_risk, 2),
            'vulnerability_count': len(vulnerabilities),
            'critical_count': counts['critical'],
            'high_count': counts['high'],
            'medium_count': counts['medium'],
            'low_count': counts['low'],
            'info_count': counts['info'],
            'risk_distribution': counts
        }

    def get_remediation_priority(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Prioritize vulnerabilities for remediation

        Args:
            vulnerabilities: List of vulnerabilities with risk scores

        Returns:
            Sorted list of vulnerabilities by priority
        """

        # Add priority score to each vulnerability
        for vuln in vulnerabilities:
            risk_data = vuln.get('risk_score_data', {})
            risk_score = risk_data.get('risk_score', 0)

            # Priority factors:
            # 1. Risk score (0-10)
            # 2. Has public exploit (+2)
            # 3. Critical severity (+1)

            priority = risk_score

            if vuln.get('cve'):
                priority += 2

            if vuln.get('severity') == 'critical':
                priority += 1

            vuln['priority_score'] = priority

        # Sort by priority (highest first)
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: x.get('priority_score', 0),
            reverse=True
        )

        return sorted_vulns

    def generate_executive_summary(
        self,
        aggregate_risk: Dict[str, Any]
    ) -> str:
        """Generate executive summary text"""

        total_vulns = aggregate_risk['vulnerability_count']
        critical = aggregate_risk['critical_count']
        high = aggregate_risk['high_count']
        avg_risk = aggregate_risk['average_risk_score']

        summary = f"Assessment identified {total_vulns} total vulnerabilities. "

        if critical > 0:
            summary += f"{critical} critical and {high} high severity vulnerabilities require immediate attention. "
        elif high > 0:
            summary += f"{high} high severity vulnerabilities require prompt remediation. "
        else:
            summary += "No critical or high severity vulnerabilities were identified. "

        if avg_risk >= 7.0:
            summary += "The overall risk posture is HIGH and requires urgent action."
        elif avg_risk >= 4.0:
            summary += "The overall risk posture is MEDIUM and requires timely remediation."
        else:
            summary += "The overall risk posture is acceptable but continuous monitoring is recommended."

        return summary
