"""
reporting/templates.py — Report Template Engine

Provides template system for generating reports in various formats.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.types import HuntState, Finding, Severity
from reporting.cvss import CVSSCalculator, estimate_cvss


class TemplateEngine:
    """
    Template engine for report generation.

    Supports:
    - Markdown
    - HTML
    - JSON
    """

    def __init__(self, template_dir: Path | None = None):
        """Initialize template engine."""
        self.template_dir = template_dir or Path(__file__).parent / "templates"
        self.cvss = CVSSCalculator()

    def render_markdown(self, state: HuntState) -> str:
        """
        Generate Markdown report.

        Args:
            state: Current hunt state

        Returns:
            Markdown formatted report
        """
        lines = []

        # Header
        lines.append(f"# Bug Bounty Report")
        lines.append(f"**Target:** {state.target.url}")
        lines.append(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Hunt ID:** {state.hunt_id}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")

        # Statistics
        findings_by_severity = self._group_by_severity(state.findings)
        lines.append(f"**Total Findings:** {len(state.findings)}")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = len(findings_by_severity.get(severity, []))
            lines.append(f"| {severity} | {count} |")
        lines.append("")

        # Tech Stack
        if state.target.tech_stack:
            lines.append("### Technology Stack")
            lines.append("")
            for tech, version in state.target.tech_stack.items():
                lines.append(f"- **{tech}:** {version}")
            lines.append("")

        # WAF/CDN
        if state.target.waf_cdn:
            lines.append(f"### WAF/CDN")
            lines.append(f"{state.target.waf_cdn}")
            lines.append("")

        # Findings
        lines.append("## Findings")
        lines.append("")

        for finding in self._sort_findings(state.findings):
            lines.extend(self._render_finding_markdown(finding))
            lines.append("")

        # Technical Details
        lines.append("## Technical Details")
        lines.append("")
        lines.append(f"**Endpoints Discovered:** {len(state.target.endpoints_discovered)}")
        lines.append(f"**JS Files Analyzed:** {len(state.target.js_files)}")
        lines.append(f"**Phases Completed:** {', '.join([p.value for p in state.completed_phases])}")
        lines.append("")

        return "\n".join(lines)

    def _render_finding_markdown(self, finding: Finding) -> list[str]:
        """Render a single finding in Markdown format."""
        lines = []

        # CVSS score
        cvss_data = estimate_cvss(finding.vuln_class)

        lines.append(f"### {finding.vuln_class.replace('_', ' ').title()}")
        lines.append(f"**Severity:** {finding.severity.value.upper()}")
        lines.append(f"**Target:** {finding.target_url}")
        lines.append(f"**CVSS Score:** {cvss_data['base_score']} ({cvss_data['severity']})")
        lines.append(f"**Vector:** {cvss_data['vector_string']}")
        lines.append("")

        if finding.impact:
            lines.append(f"#### Impact")
            lines.append(finding.impact)
            lines.append("")

        if finding.evidence:
            lines.append(f"#### Evidence")
            lines.append(finding.evidence)
            lines.append("")

        if finding.poc_steps:
            lines.append("#### Proof of Concept")
            for i, step in enumerate(finding.poc_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Generate curl POC
        lines.append("#### Curl Command")
        lines.append(self._generate_curl_poc(finding))
        lines.append("")

        return lines

    def render_html(self, state: HuntState) -> str:
        """
        Generate HTML report.

        Args:
            state: Current hunt state

        Returns:
            HTML formatted report
        """
        html = ['''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Bug Bounty Report</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; border-bottom: 2px solid #007bff; }
        h2 { color: #555; margin-top: 30px; }
        h3 { color: #666; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        .finding { border: 1px solid #ddd; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .critical { border-left: 5px solid #dc3545; }
        .high { border-left: 5px solid #fd7e14; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #28a745; }
        .info { border-left: 5px solid #17a2b8; }
        .severity { font-weight: bold; text-transform: uppercase; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
''']

        # Header
        html.append(f"<h1>Bug Bounty Report</h1>")
        html.append(f"<p><strong>Target:</strong> {state.target.url}</p>")
        html.append(f"<p><strong>Date:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>")
        html.append(f"<p><strong>Hunt ID:</strong> {state.hunt_id}</p>")

        # Executive Summary
        html.append("<h2>Executive Summary</h2>")
        html.append('<div class="summary">')

        findings_by_severity = self._group_by_severity(state.findings)
        html.append(f"<p><strong>Total Findings:</strong> {len(state.findings)}</p>")

        html.append("<table>")
        html.append("<tr><th>Severity</th><th>Count</th></tr>")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = len(findings_by_severity.get(severity, []))
            html.append(f"<tr><td>{severity}</td><td>{count}</td></tr>")
        html.append("</table>")
        html.append("</div>")

        # Findings
        html.append("<h2>Findings</h2>")

        for finding in self._sort_findings(state.findings):
            cvss_data = estimate_cvss(finding.vuln_class)
            severity_class = finding.severity.value.lower()

            html.append(f'<div class="finding {severity_class}">')
            html.append(f"<h3>{finding.vuln_class.replace('_', ' ').title()}</h3>")
            html.append(f"<p><span class='severity'>{finding.severity.value.upper()}</span> | ")
            html.append(f"Target: {finding.target_url} | ")
            html.append(f"CVSS: {cvss_data['base_score']} ({cvss_data['severity']})</p>")

            if finding.impact:
                html.append(f"<h4>Impact</h4><p>{finding.impact}</p>")

            if finding.evidence:
                html.append(f"<h4>Evidence</h4><p>{finding.evidence}</p>")

            if finding.poc_steps:
                html.append("<h4>Proof of Concept</h4><ol>")
                for step in finding.poc_steps:
                    html.append(f"<li>{step}</li>")
                html.append("</ol>")

            html.append(f"<h4>Curl Command</h4>")
            html.append(f"<pre>{self._generate_curl_poc(finding)}</pre>")

            html.append("</div>")

        html.append("</body></html>")

        return "\n".join(html)

    def render_json(self, state: HuntState) -> str:
        """
        Generate JSON report.

        Args:
            state: Current hunt state

        Returns:
            JSON formatted report
        """
        findings_data = []

        for finding in state.findings:
            cvss_data = estimate_cvss(finding.vuln_class)
            findings_data.append({
                "id": finding.id,
                "vuln_class": finding.vuln_class,
                "target_url": finding.target_url,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
                "impact": finding.impact,
                "poc_steps": finding.poc_steps,
                "status": finding.status.value,
                "timestamp": finding.timestamp,
                "cvss": {
                    "base_score": cvss_data["base_score"],
                    "severity": cvss_data["severity"],
                    "vector": cvss_data["vector_string"],
                },
            })

        report = {
            "hunt_id": state.hunt_id,
            "target": {
                "url": state.target.url,
                "scope": state.target.scope,
                "tech_stack": state.target.tech_stack,
                "waf_cdn": state.target.waf_cdn,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(state.findings),
                "by_severity": self._group_by_severity_counts(state.findings),
                "endpoints_discovered": len(state.target.endpoints_discovered),
                "js_files_analyzed": len(state.target.js_files),
            },
            "findings": findings_data,
        }

        return json.dumps(report, indent=2)

    def _group_by_severity(self, findings: list[Finding]) -> dict[str, list[Finding]]:
        """Group findings by severity."""
        grouped = {}
        for finding in findings:
            severity = finding.severity.value.upper()
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)
        return grouped

    def _group_by_severity_counts(self, findings: list[Finding]) -> dict[str, int]:
        """Get count of findings by severity."""
        grouped = self._group_by_severity(findings)
        return {k: len(v) for k, v in grouped.items()}

    def _sort_findings(self, findings: list[Finding]) -> list[Finding]:
        """Sort findings by severity (critical first)."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity.value, 5), f.timestamp),
            reverse=True
        )

    def _generate_curl_poc(self, finding: Finding) -> str:
        """Generate curl command for a finding."""
        # Parse URL
        from urllib.parse import urlparse
        parsed = urlparse(finding.target_url)

        cmd = f"curl -X {finding.poc_steps[0].split()[-1] if finding.poc_steps else 'GET'} '{finding.target_url}' \\\n"

        # Add common headers
        cmd += "  -H 'User-Agent: Mozilla/5.0' \\\n"

        # Add vulnerability-specific modifications
        if "sql" in finding.vuln_class.lower():
            cmd += f"  -H 'Cookie: id=1\\' OR 1=1--' \\\n"
        elif "xss" in finding.vuln_class.lower():
            cmd += f"  -H 'Cookie: search=<script>alert(1)</script>' \\\n"
        elif "auth" in finding.vuln_class.lower():
            cmd += f"  -H 'Authorization: Bearer invalid_token' \\\n"

        cmd += "  -v"

        return cmd
