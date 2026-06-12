"""
reporting/generator.py — Report Generator

Main report generator with support for multiple output formats.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.types import HuntState
from reporting.templates import TemplateEngine
from reporting.cvss import CVSSCalculator


class ReportGenerator:
    """
    Main report generator.

    Supports multiple formats:
    - Markdown (.md)
    - HTML (.html)
    - JSON (.json)
    - PDF (optional, requires reportlab)
    """

    def __init__(self, template_engine: TemplateEngine | None = None):
        """
        Initialize report generator.

        Args:
            template_engine: Optional custom template engine
        """
        self.template = template_engine or TemplateEngine()
        self.cvss = CVSSCalculator()

    def generate(
        self,
        state: HuntState,
        format: str = "markdown",
        output_file: Path | None = None,
    ) -> str:
        """
        Generate a report.

        Args:
            state: Hunt state with findings
            format: Output format (markdown, html, json, pdf)
            output_file: Optional output file path

        Returns:
            Report content as string
        """
        format = format.lower()

        if format in ("md", "markdown"):
            content = self.template.render_markdown(state)
        elif format == "html":
            content = self.template.render_html(state)
        elif format == "json":
            content = self.template.render_json(state)
        elif format == "pdf":
            content = self._generate_pdf(state)
        else:
            raise ValueError(f"Unsupported format: {format}")

        # Save to file if specified
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(content)

        return content

    def generate_all(
        self,
        state: HuntState,
        output_dir: Path,
    ) -> dict[str, Path]:
        """
        Generate reports in all supported formats.

        Args:
            state: Hunt state with findings
            output_dir: Directory to save reports

        Returns:
            Dictionary mapping format to output file path
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        hunt_id = state.hunt_id
        files = {}

        # Generate markdown
        md_path = output_dir / f"{hunt_id}_report.md"
        self.generate(state, format="markdown", output_file=md_path)
        files["markdown"] = md_path

        # Generate HTML
        html_path = output_dir / f"{hunt_id}_report.html"
        self.generate(state, format="html", output_file=html_path)
        files["html"] = html_path

        # Generate JSON
        json_path = output_dir / f"{hunt_id}_report.json"
        self.generate(state, format="json", output_file=json_path)
        files["json"] = json_path

        # Try PDF
        try:
            pdf_path = output_dir / f"{hunt_id}_report.pdf"
            self.generate(state, format="pdf", output_file=pdf_path)
            files["pdf"] = pdf_path
        except Exception:
            # PDF generation is optional
            pass

        return files

    def _generate_pdf(self, state: HuntState) -> bytes:
        """
        Generate PDF report.

        Requires reportlab library.

        Args:
            state: Hunt state with findings

        Returns:
            PDF content as bytes
        """
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib import colors
        except ImportError:
            raise ImportError(
                "PDF generation requires reportlab. "
                "Install it with: pip install reportlab"
            )

        # Create PDF content
        # (Full implementation would be quite long, this is a simplified version)
        markdown = self.template.render_markdown(state)

        # For now, return a placeholder
        # In a full implementation, you'd convert markdown to PDF
        return f"PDF generation for hunt {state.hunt_id}\n\n{markdown}".encode()

    def generate_summary(self, state: HuntState) -> str:
        """
        Generate a brief text summary.

        Args:
            state: Hunt state with findings

        Returns:
            Summary text
        """
        lines = [
            f"Bug Bounty Hunt Summary",
            f"=" * 40,
            f"",
            f"Target: {state.target.url}",
            f"Hunt ID: {state.hunt_id}",
            f"Status: {state.status.value}",
            f"",
            f"Findings: {len(state.findings)} total",
        ]

        # Count by severity
        from reporting.templates import TemplateEngine
        template = TemplateEngine()
        counts = template._group_by_severity_counts(state.findings)

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = counts.get(severity.lower(), 0)
            if count > 0:
                lines.append(f"  {severity}: {count}")

        lines.append("")
        lines.append(f"Endpoints discovered: {len(state.target.endpoints_discovered)}")
        lines.append(f"JS files analyzed: {len(state.target.js_files)}")

        return "\n".join(lines)

    def generate_executive_summary(self, state: HuntState) -> dict[str, Any]:
        """
        Generate an executive summary for stakeholders.

        Args:
            state: Hunt state with findings

        Returns:
            Dictionary with executive summary data
        """
        template = TemplateEngine()
        counts = template._group_by_severity_counts(state.findings)

        # Calculate risk score
        risk_score = 0
        risk_score += counts.get("critical", 0) * 10
        risk_score += counts.get("high", 0) * 5
        risk_score += counts.get("medium", 0) * 2
        risk_score += counts.get("low", 0) * 1

        # Determine overall risk level
        if risk_score >= 50:
            overall_risk = "CRITICAL"
        elif risk_score >= 20:
            overall_risk = "HIGH"
        elif risk_score >= 10:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        return {
            "target": state.target.url,
            "hunt_id": state.hunt_id,
            "overall_risk": overall_risk,
            "risk_score": risk_score,
            "total_findings": len(state.findings),
            "findings_by_severity": counts,
            "recommendations": self._generate_recommendations(state),
        }

    def _generate_recommendations(self, state: HuntState) -> list[str]:
        """Generate remediation recommendations based on findings."""
        recommendations = []

        findings_by_type = {}
        for finding in state.findings:
            if finding.vuln_class not in findings_by_type:
                findings_by_type[finding.vuln_class] = []
            findings_by_type[finding.vuln_class].append(finding)

        # Generate recommendations by type
        if "sql_injection" in findings_by_type:
            recommendations.append(
                "Implement parameterized queries and input validation to prevent SQL injection. "
                "Use prepared statements and ORM frameworks."
            )

        if "xss" in findings_by_type:
            recommendations.append(
                "Implement proper output encoding and Content Security Policy (CSP) to prevent XSS. "
                "Validate and sanitize all user input."
            )

        if "authentication_bypass" in findings_by_type:
            recommendations.append(
                "Review and strengthen authentication mechanisms. "
                "Implement multi-factor authentication and proper session management."
            )

        if "missing_security_headers" in findings_by_type:
            recommendations.append(
                "Add security headers including Content-Security-Policy, X-Frame-Options, "
                "X-Content-Type-Options, and Strict-Transport-Security."
            )

        if "information_disclosure" in findings_by_type:
            recommendations.append(
                "Review error messages and debug output. Ensure sensitive information is not leaked "
                "in error responses."
            )

        if "ssrf" in findings_by_type:
            recommendations.append(
                "Implement strict allowlists for external URLs and validate user redirects. "
                "Network segmentation for internal services."
            )

        if not recommendations:
            recommendations.append("Continue security best practices and regular security assessments.")

        return recommendations
