"""
core/executors/nuclei_executor.py — Nuclei wrapper

Nuclei is a vulnerability scanner based on templates:
- CVE detection
- Misconfiguration detection
- Exposure detection
- Custom vulnerability scanning
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .base import ToolBase, ToolResult, ToolStatus
from shared.types import HuntState, Finding, Severity
from shared.utils import now_iso


class NucleiExecutor(ToolBase):
    """
    Executor for nuclei scanner.

    Usage:
        executor = NucleiExecutor(state)
        result = executor.run(
            targets=["https://example.com"],
            severity=["critical", "high"],
            tags=["cve", "exposure"]
        )
    """

    @property
    def tool_name(self) -> str:
        return "nuclei"

    @property
    def executable_name(self) -> str:
        return "nuclei"

    def run(
        self,
        targets: list[str] | None = None,
        urls: list[str] | None = None,
        templates: list[str] | None = None,
        tags: list[str] | None = None,
        severity: list[str] | None = None,
        exclude_severity: list[str] | None = None,
        workflows: bool = False,
        bulk_size: int = 25,
        concurrent_requests: int = 25,
        rate_limit: int = 150,
        output_file: Path | None = None,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Run nuclei scan.

        Args:
            targets: List of targets to scan
            urls: List of URLs to scan
            templates: List of template paths/URLs
            tags: List of template tags to include
            severity: List of severities to include
            exclude_severity: List of severities to exclude
            workflows: Enable workflows
            bulk_size: Target bulk size
            concurrent_requests: Concurrent requests
            rate_limit: Rate limit per second
            output_file: Optional output file path
            timeout: Scan timeout

        Returns:
            ToolResult with discovered vulnerabilities
        """
        if not self.is_available():
            return ToolResult(
                status=ToolStatus.NOT_FOUND,
                error_message=f"{self.tool_name} is not installed or not in PATH"
            )

        # Build command
        cmd = [
            self.executable_name,
            "-silent",
            "-json",
        ]

        if templates:
            for tpl in templates:
                cmd.extend(["-templates", tpl])

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        if exclude_severity:
            cmd.extend(["-exclude-severity", ",".join(exclude_severity)])

        if workflows:
            cmd.append("-workflows")

        cmd.extend(["-bulk-size", str(bulk_size)])
        cmd.extend(["-c", str(concurrent_requests)])
        cmd.extend(["-rl", str(rate_limit)])

        if output_file:
            cmd.extend(["-o", str(output_file)])

        # Add input source
        input_data = None
        if urls:
            cmd.append("-stdin")
            input_data = "\n".join(urls)
        elif targets:
            cmd.append("-stdin")
            input_data = "\n".join(targets)
        else:
            cmd.append("-stdin")
            input_data = self.state.target.url

        # Execute
        result = self._execute_command(
            cmd,
            timeout=timeout,
        )

        if result.status != ToolStatus.SUCCESS:
            return result

        # Parse output
        parsed = self.parse_output(result.raw_output)
        result.parsed_data = parsed

        # Extract findings
        result.findings = self.extract_findings(parsed)

        return result

    def parse_output(self, raw_output: str) -> dict:
        """Parse nuclei JSON output."""
        vulnerabilities = []
        summary = {
            "total": 0,
            "by_severity": {},
            "by_type": {},
        }

        for line in raw_output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)

                vuln = {
                    "template_id": data.get("template-id", ""),
                    "template_path": data.get("template", ""),
                    "info": data.get("info", {}),
                    "type": data.get("type", ""),
                    "host": data.get("host", ""),
                    "matched_at": data.get("matched-at", ""),
                    "severity": data.get("info", {}).get("severity", "unknown"),
                    "tags": data.get("info", {}).get("tags", []),
                }

                # Extract response data if available
                if "response" in data:
                    vuln["response"] = data["response"]

                vulnerabilities.append(vuln)

                # Update summary
                summary["total"] += 1
                sev = vuln["severity"]
                summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

                for tag in vuln.get("tags", []):
                    summary["by_type"][tag] = summary["by_type"].get(tag, 0) + 1

            except json.JSONDecodeError:
                continue

        return {
            "vulnerabilities": vulnerabilities,
            "summary": summary,
        }

    def extract_findings(self, parsed_data: dict) -> list[Finding]:
        """Extract findings from nuclei results."""
        findings = []

        for vuln in parsed_data.get("vulnerabilities", []):
            # Map nuclei severity to our Severity enum
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(
                vuln.get("severity", "unknown").lower(),
                Severity.MEDIUM
            )

            # Build evidence
            info = vuln.get("info", {})
            evidence_parts = [
                f"Template: {vuln.get('template_id', '')}",
                f"Type: {vuln.get('type', '')}",
                f"Matched at: {vuln.get('matched_at', '')}",
            ]

            if info.get("description"):
                evidence_parts.append(f"Description: {info['description']}")

            if info.get("reference"):
                evidence_parts.append(f"Reference: {', '.join(info['reference'])}")

            evidence = "\n".join(evidence_parts)

            # Build PoC steps
            poc_steps = [
                f"1. Target: {vuln.get('host', '')}",
                f"2. Vulnerable endpoint: {vuln.get('matched_at', '')}",
                f"3. Template: {vuln.get('template_path', '')}",
            ]

            if vuln.get("response"):
                poc_steps.append("4. Response contains vulnerability indicator")

            findings.append(self._generate_finding(
                vuln_class=self._classify_vuln(vuln),
                target_url=vuln.get("matched_at", vuln.get("host", "")),
                severity=severity,
                evidence=evidence,
                poc_steps=poc_steps,
                confidence=0.8,
                impact=info.get("description", ""),
            ))

        return findings

    def _classify_vuln(self, vuln: dict) -> str:
        """Classify vulnerability type."""
        info = vuln.get("info", {})
        tags = vuln.get("tags", [])

        # Common classifications
        if any(t in tags for t in ["cve", "rce"]):
            return "remote_code_execution"
        elif any(t in tags for t in ["sqli", "sql"]):
            return "sql_injection"
        elif any(t in tags for t in ["xss", "reflected", "stored"]):
            return "xss"
        elif any(t in tags for t in ["ssrf", "redirect"]):
            return "ssrf"
        elif any(t in tags for t in ["lfi", "file"]):
            return "local_file_inclusion"
        elif any(t in tags for t in ["idor", "idor"]):
            return "idor"
        elif any(t in tags for t in ["auth", "bypass"]):
            return "authentication_bypass"
        elif any(t in tags for t in ["exposure", "panel", "admin"]):
            return "exposed_admin_panel"
        elif any(t in tags for t in ["config", "backup", "git"]):
            return "sensitive_data_exposure"
        elif any(t in tags for t in ["misconfig", "config"]):
            return "misconfiguration"
        elif "tech" in tags:
            return "technology_detection"
        else:
            # Use name from info
            name = info.get("name", "unknown")
            return name.lower().replace(" ", "_").replace("-", "_")
