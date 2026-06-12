"""
core/executors/httpx_executor.py — HTTPX wrapper

HTTPX is a fast and multi-purpose HTTP toolkit used for:
- Port scanning
- Service discovery
- Header analysis
- Technology fingerprinting
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from dataclasses import dataclass

from .base import ToolBase, ToolResult, ToolStatus
from shared.types import HuntState, Finding, Severity
from shared.utils import now_iso


class HttpxExecutor(ToolBase):
    """
    Executor for httpx tool.

    Usage:
        executor = HttpxExecutor(state)
        result = executor.run(
            targets=["https://example.com"],
            ports=[80, 443, 8080],
            probes="x"
        )
    """

    @property
    def tool_name(self) -> str:
        return "httpx"

    @property
    def executable_name(self) -> str:
        return "httpx"

    def run(
        self,
        targets: list[str] | None = None,
        urls: list[str] | None = None,
        ports: list[int] | None = None,
        probes: str = "x",  # x = all probes
        status_code: bool = True,
        content_length: bool = True,
        headers: bool = True,
        tech_detect: bool = True,
        server: bool = True,
        method: bool = True,
        network: bool = False,
        pipeline: bool = False,
        output_file: Path | None = None,
        timeout: int = 60,
    ) -> ToolResult:
        """
        Run httpx scan.

        Args:
            targets: List of targets to scan (domains/ IPs)
            urls: List of full URLs to probe
            ports: List of ports to scan (for targets)
            probes: Probe level (x = all)
            status_code: Show status codes
            content_length: Show content length
            headers: Show response headers
            tech_detect: Detect technologies
            server: Show server header
            method: Show HTTP method
            network: Follow network (CNAME, etc)
            pipeline: Use HTTP/1.1 pipeline
            output_file: Optional output file path
            timeout: Request timeout

        Returns:
            ToolResult with discovered endpoints and findings
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

        if status_code:
            cmd.append("-status-code")

        if content_length:
            cmd.append("-content-length")

        if headers:
            cmd.append("-headers")

        if tech_detect:
            cmd.append("-tech-detect")

        if server:
            cmd.append("-server")

        if method:
            cmd.append("-method")

        if network:
            cmd.append("-network")

        if pipeline:
            cmd.append("-pipeline")

        if probes:
            cmd.extend(["-probe", probes])

        if timeout:
            cmd.extend(["-timeout", str(timeout)])

        if output_file:
            cmd.extend(["-o", str(output_file)])

        # Add input source (stdin or file)
        input_data = None
        if urls:
            # Use stdin for URLs
            cmd.append("-stdin")
            input_data = "\n".join(urls)
        elif targets:
            # Use stdin for targets
            cmd.append("-stdin")
            target_input = []
            for target in targets:
                if ports:
                    for port in ports:
                        target_input.append(f"{target}:{port}")
                else:
                    target_input.append(target)
            input_data = "\n".join(target_input)
        else:
            # Use target URL from state
            cmd.append("-stdin")
            input_data = self.state.target.url

        # Execute
        result = self._execute_command(
            cmd,
            timeout=timeout + 10,
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
        """Parse httpx JSON output."""
        endpoints = []
        technologies = {}
        servers = {}
        issues = []

        for line in raw_output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)

                endpoint = {
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code", 0),
                    "content_length": data.get("content_length", 0),
                    "method": data.get("method", "GET"),
                }

                if "headers" in data:
                    endpoint["headers"] = data["headers"]

                if "server" in data:
                    server = data["server"]
                    endpoint["server"] = server
                    servers[data.get("host", data.get("url", ""))] = server

                if "technologies" in data:
                    techs = data["technologies"]
                    endpoint["technologies"] = techs
                    for tech in techs:
                        host = data.get("host", data.get("url", ""))
                        if host not in technologies:
                            technologies[host] = []
                        technologies[host].extend(techs)

                endpoints.append(endpoint)

                # Check for common issues
                if data.get("status_code") == 500:
                    issues.append({
                        "type": "internal_server_error",
                        "url": data.get("url"),
                        "severity": "medium",
                    })

                if "application" in str(data.get("content-type", "")):
                    content_type = data.get("content-type", "")
                    if "json" in content_type:
                        endpoint["content_type"] = "application/json"

            except json.JSONDecodeError:
                continue

        return {
            "endpoints": endpoints,
            "technologies": technologies,
            "servers": servers,
            "issues": issues,
            "total_endpoints": len(endpoints),
        }

    def extract_findings(self, parsed_data: dict) -> list[Finding]:
        """Extract findings from httpx results."""
        findings = []

        # Check for information disclosure in errors
        for issue in parsed_data.get("issues", []):
            if issue.get("type") == "internal_server_error":
                findings.append(self._generate_finding(
                    vuln_class="information_disclosure",
                    target_url=issue.get("url", ""),
                    severity=Severity.MEDIUM,
                    evidence=f"HTTP 500 Internal Server Error detected at {issue.get('url')}",
                ))

        # Check for missing security headers
        for endpoint in parsed_data.get("endpoints", []):
            headers = endpoint.get("headers", {})
            missing = []
            critical_missing = []

            # Critical headers
            if not any(h.lower() in ["content-security-policy", "csp"] for h in headers.keys()):
                critical_missing.append("Content-Security-Policy")
            if "x-frame-options" not in [h.lower() for h in headers.keys()]:
                critical_missing.append("X-Frame-Options")
            if "x-content-type-options" not in [h.lower() for h in headers.keys()]:
                critical_missing.append("X-Content-Type-Options")

            # Less critical
            if "strict-transport-security" not in [h.lower() for h in headers.keys()]:
                missing.append("Strict-Transport-Security")
            if "referrer-policy" not in [h.lower() for h in headers.keys()]:
                missing.append("Referrer-Policy")

            if critical_missing:
                findings.append(self._generate_finding(
                    vuln_class="missing_security_headers",
                    target_url=endpoint.get("url", ""),
                    severity=Severity.MEDIUM,
                    evidence=f"Missing critical headers: {', '.join(critical_missing)}",
                    poc_steps=[
                        f"1. Send request to: {endpoint.get('url')}",
                        f"2. Observe response headers are missing: {', '.join(critical_missing)}",
                    ],
                ))

            # Check for server disclosure
            server = endpoint.get("server", "")
            if server and any(v in server.lower() for v in ["nginx", "apache", "cloudflare", "apache/2"]):
                findings.append(self._generate_finding(
                    vuln_class="server_disclosure",
                    target_url=endpoint.get("url", ""),
                    severity=Severity.INFO,
                    evidence=f"Server header disclosed: {server}",
                ))

        return findings
