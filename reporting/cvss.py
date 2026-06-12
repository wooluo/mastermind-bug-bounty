"""
reporting/cvss.py — CVSS Score Calculator

Implements CVSS v3.1 scoring for vulnerability severity assessment.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class CVSSVector(str, Enum):
    """CVSS v3.1 metric enum values."""
    # Attack Vector
    AV_NETWORK = "N"
    AV_ADJACENT = "A"
    AV_LOCAL = "L"
    AV_PHYSICAL = "P"

    # Attack Complexity
    AC_LOW = "L"
    AC_HIGH = "H"

    # Privileges Required
    PR_NONE = "N"
    PR_LOW = "L"
    PR_HIGH = "H"

    # User Interaction
    UI_NONE = "N"
    UI_REQUIRED = "R"

    # Scope
    S_UNCHANGED = "U"
    S_CHANGED = "C"

    # Confidentiality
    C_HIGH = "H"
    C_LOW = "L"
    C_NONE = "N"

    # Integrity
    I_HIGH = "H"
    I_LOW = "L"
    I_NONE = "N"

    # Availability
    A_HIGH = "H"
    A_LOW = "L"
    A_NONE = "N"


@dataclass
class CVSSMetrics:
    """CVSS v3.1 base metrics."""
    attack_vector: str = CVSSVector.AV_NETWORK
    attack_complexity: str = CVSSVector.AC_LOW
    privileges_required: str = CVSSVector.PR_NONE
    user_interaction: str = CVSSVector.UI_NONE
    scope: str = CVSSVector.S_UNCHANGED
    confidentiality: str = CVSSVector.C_HIGH
    integrity: str = CVSSVector.I_HIGH
    availability: str = CVSSVector.A_HIGH


class CVSSCalculator:
    """
    CVSS v3.1 score calculator.

    Usage:
        calculator = CVSSCalculator()
        score = calculator.calculate(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H"
        )
    """

    # CVSS v3.1 scoring formulas
    # Based on https://www.first.org/cvss/specification-document

    def calculate(self, metrics: CVSSMetrics | dict = None, **kwargs) -> dict:
        """
        Calculate CVSS v3.1 base score.

        Args:
            metrics: CVSSMetrics object or dict with metric values
            **kwargs: Individual metric values (if metrics not provided)

        Returns:
            Dictionary with score, severity, and vector string
        """
        if isinstance(metrics, dict):
            metrics = CVSSMetrics(**metrics)
        elif metrics is None:
            metrics = CVSSMetrics(**kwargs)

        # Calculate base score
        base_score = self._calculate_base_score(metrics)

        # Determine severity
        severity = self._get_severity(base_score)

        # Generate vector string
        vector_string = self._generate_vector_string(metrics)

        return {
            "base_score": round(base_score, 1),
            "severity": severity,
            "vector_string": vector_string,
            "metrics": metrics if isinstance(metrics, CVSSMetrics) else CVSSMetrics(**metrics),
        }

    def _calculate_base_score(self, m: CVSSMetrics) -> float:
        """Calculate base score using CVSS v3.1 formula."""
        # Exploitability
        exploitability = 8.22 * self._attack_vector_value(m.attack_vector)
        exploitability *= self._attack_complexity_value(m.attack_complexity)
        exploitability *= self._privileges_required_value(m.privileges_required, m.scope)
        exploitability *= self._user_interaction_value(m.user_interaction)

        # Impact
        impact = self._isc_value(m.confidentiality, m.integrity, m.availability)

        # Scope adjustment
        if m.scope == CVSSVector.S_CHANGED:
            impact = 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02)**15
        else:
            impact = 6.42 * impact

        # Final base score
        if impact <= 0:
            return 0.0

        if m.scope == CVSSVector.S_CHANGED:
            base_score = min(10.0, impact + exploitability)
        else:
            base_score = min(10.0, impact + exploitability)

        return base_score

    def _attack_vector_value(self, av: str) -> float:
        """Get Attack Vector score."""
        values = {CVSSVector.AV_NETWORK: 0.85, CVSSVector.AV_ADJACENT: 0.62,
                  CVSSVector.AV_LOCAL: 0.55, CVSSVector.AV_PHYSICAL: 0.2}
        return values.get(av, 0.85)

    def _attack_complexity_value(self, ac: str) -> float:
        """Get Attack Complexity score."""
        values = {CVSSVector.AC_LOW: 0.77, CVSSVector.AC_HIGH: 0.44}
        return values.get(ac, 0.77)

    def _privileges_required_value(self, pr: str, scope: str) -> float:
        """Get Privileges Required score."""
        if scope == CVSSVector.S_CHANGED:
            values = {CVSSVector.PR_NONE: 0.85, CVSSVector.PR_LOW: 0.68,
                      CVSSVector.PR_HIGH: 0.50}
        else:
            values = {CVSSVector.PR_NONE: 0.85, CVSSVector.PR_LOW: 0.62,
                      CVSSVector.PR_HIGH: 0.27}
        return values.get(pr, 0.85)

    def _user_interaction_value(self, ui: str) -> float:
        """Get User Interaction score."""
        values = {CVSSVector.UI_NONE: 0.85, CVSSVector.UI_REQUIRED: 0.62}
        return values.get(ui, 0.85)

    def _isc_value(self, c: str, i: str, a: str) -> float:
        """Calculate Impact Subscore (ISC)."""
        values = {CVSSVector.C_HIGH: 0.56, CVSSVector.C_LOW: 0.22, CVSSVector.C_NONE: 0.0}
        conf = values.get(c, 0.56)

        values = {CVSSVector.I_HIGH: 0.56, CVSSVector.I_LOW: 0.22, CVSSVector.I_NONE: 0.0}
        integ = values.get(i, 0.56)

        values = {CVSSVector.A_HIGH: 0.56, CVSSVector.A_LOW: 0.22, CVSSVector.A_NONE: 0.0}
        avail = values.get(a, 0.56)

        isc = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
        return isc

    def _get_severity(self, score: float) -> str:
        """Get severity rating from score."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        return "NONE"

    def _generate_vector_string(self, m: CVSSMetrics) -> str:
        """Generate CVSS vector string."""
        return (
            f"CVSS:3.1/AV:{m.attack_vector}/AC:{m.attack_complexity}/"
            f"PR:{m.privileges_required}/UI:{m.user_interaction}/S:{m.scope}/"
            f"C:{m.confidentiality}/I:{m.integrity}/A:{m.availability}"
        )

    def estimate_from_vuln_class(self, vuln_class: str) -> dict:
        """
        Estimate CVSS metrics from vulnerability class.

        Provides reasonable defaults for common vulnerability types.

        Args:
            vuln_class: Vulnerability classification

        Returns:
            CVSS score dict
        """
        # Default metrics for different vulnerability types
        vuln_metrics = {
            "remote_code_execution": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                "user_interaction": "N", "scope": "C", "confidentiality": "H",
                "integrity": "H", "availability": "H"
            },
            "sql_injection": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                "user_interaction": "N", "scope": "C", "confidentiality": "H",
                "integrity": "H", "availability": "H"
            },
            "xss": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                "user_interaction": "R", "scope": "U", "confidentiality": "L",
                "integrity": "L", "availability": "N"
            },
            "ssrf": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                "user_interaction": "N", "scope": "C", "confidentiality": "H",
                "integrity": "H", "availability": "H"
            },
            "authentication_bypass": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                "user_interaction": "N", "scope": "U", "confidentiality": "H",
                "integrity": "H", "availability": "H"
            },
            "idor": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "L",
                "user_interaction": "N", "scope": "U", "confidentiality": "H",
                "integrity": "H", "availability": "L"
            },
            "information_disclosure": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                "user_interaction": "N", "scope": "U", "confidentiality": "H",
                "integrity": "N", "availability": "N"
            },
            "missing_security_headers": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                "user_interaction": "N", "scope": "U", "confidentiality": "N",
                "integrity": "L", "availability": "N"
            },
            "exposed_admin_panel": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                "user_interaction": "N", "scope": "U", "confidentiality": "H",
                "integrity": "H", "availability": "H"
            },
            "sensitive_data_exposure": {
                "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                "user_interaction": "N", "scope": "U", "confidentiality": "H",
                "integrity": "N", "availability": "N"
            },
        }

        # Get metrics for this vuln type
        metrics = vuln_metrics.get(vuln_class.replace("-", "_"), vuln_metrics["information_disclosure"])

        return self.calculate(metrics)


# Convenience functions
def calculate_cvss(**kwargs) -> dict:
    """Quick CVSS calculation."""
    return CVSSCalculator().calculate(**kwargs)


def estimate_cvss(vuln_class: str) -> dict:
    """Quick CVSS estimation from vuln class."""
    return CVSSCalculator().estimate_from_vuln_class(vuln_class)
