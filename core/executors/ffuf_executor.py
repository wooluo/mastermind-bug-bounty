"""
core/executors/ffuf_executor.py — FFUF wrapper

FFUF (Fuzz Faster U Fool) is a web fuzzing tool:
- Directory fuzzing
- Parameter discovery
- Virtual host discovery
- Fuzzing with filtering
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .base import ToolBase, ToolResult, ToolStatus
from shared.types import HuntState, Finding, Severity
from shared.utils import now_iso


class FfufExecutor(ToolBase):
    """
    Executor for ffuf fuzzer.

    Usage:
        executor = FfufExecutor(state)
        result = executor.run(
            url="https://example.com/FUZZ",
            wordlist="/path/to/wordlist.txt"
        )
    """

    @property
    def tool_name(self) -> str:
        return "ffuf"

    @property
    def executable_name(self) -> str:
        return "ffuf"

    def run(
        self,
        url: str,
        wordlist: str | Path | None = None,
        method: str = "GET",
        data: str | None = None,
        headers: dict | None = None,
        match_status: str | None = None,
        filter_status: str | None = None,
        match_size: int | None = None,
        filter_size: int | None = None,
        match_words: int | None = None,
        filter_words: int | None = None,
        match_lines: int | None = None,
        filter_lines: int | None = None,
        recursion: bool = False,
        recursion_depth: int = 1,
        delay: int | None = None,
        rate: int | None = None,
        timeout: int = 300,
        output_file: Path | None = None,
    ) -> ToolResult:
        """
        Run ffuf fuzzing.

        Args:
            url: Target URL with FUZZ keyword
            wordlist: Path to wordlist file
            method: HTTP method
            data: POST data
            headers: Custom headers
            match_status: Match responses with this status
            filter_status: Filter out responses with this status
            match_size: Match responses with this size
            filter_size: Filter out responses with this size
            match_words: Match responses with this word count
            filter_words: Filter out responses with this word count
            match_lines: Match responses with this line count
            filter_lines: Filter out responses with this line count
            recursion: Enable recursive scanning
            recursion_depth: Maximum recursion depth
            delay: Delay between requests
            rate: Requests per second
            timeout: Scan timeout
            output_file: Optional output file path

        Returns:
            ToolResult with discovered paths/endpoints
        """
        if not self.is_available():
            return ToolResult(
                status=ToolStatus.NOT_FOUND,
                error_message=f"{self.tool_name} is not installed or not in PATH"
            )

        # Default wordlist
        if not wordlist:
            wordlist = self._get_default_wordlist()

        # Build command
        cmd = [
            self.executable_name,
            "-u", url,
            "-w", str(wordlist),
            "-mc", match_status or "200,204,301,302,307,401,403",
            "-json",  # Output in JSON format
        ]

        if method and method.upper() != "GET":
            cmd.extend(["-X", method.upper()])

        if data:
            cmd.extend(["-d", data])

        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

        if filter_status:
            cmd.extend(["-fc", filter_status])

        if match_size:
            cmd.extend(["-ms", str(match_size)])

        if filter_size:
            cmd.extend(["-fs", str(filter_size)])

        if match_words:
            cmd.extend(["-mw", str(match_words)])

        if filter_words:
            cmd.extend(["-fw", str(filter_words)])

        if match_lines:
            cmd.extend(["-ml", str(match_lines)])

        if filter_lines:
            cmd.extend(["-fl", str(filter_lines)])

        if recursion:
            cmd.append("-recursion")
            cmd.extend(["-recursion-depth", str(recursion_depth)])

        if delay:
            cmd.extend(["-p", f"{delay}-{delay+100}"])  # Random delay

        if rate:
            cmd.extend(["-rate", str(rate)])

        if output_file:
            cmd.extend(["-o", str(output_file)])

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

    def _get_default_wordlist(self) -> str:
        """Get path to default wordlist."""
        # Try common wordlist locations
        paths = [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/opt/wordlists/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]

        for path in paths:
            if Path(path).exists():
                return path

        # Fallback to a small embedded list
        return "-"

    def parse_output(self, raw_output: str) -> dict:
        """Parse ffuf JSON output."""
        results = []
        stats = {}

        # ffuf outputs JSON lines
        for line in raw_output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)

                # Check if this is a result line or status
                if "result" in data:
                    result_data = data["result"]
                    result = {
                        "url": result_data.get("url", ""),
                        "status": result_data.get("status", 0),
                        "length": result_data.get("length", 0),
                        "words": result_data.get("words", 0),
                        "lines": result_data.get("lines", 0),
                        "file": result_data.get("input", {}).get("FUZZ", ""),
                    }

                    # Add headers if present
                    if "headers" in result_data:
                        result["headers"] = result_data["headers"]

                    results.append(result)

                elif "config" in data:
                    # Summary stats at end
                    stats = {
                        "total_requests": data.get("config", {}).get("total_requests", 0),
                    }

            except json.JSONDecodeError:
                continue

        return {
            "results": results,
            "stats": stats,
            "total_found": len(results),
        }

    def extract_findings(self, parsed_data: dict) -> list[Finding]:
        """Extract findings from ffuf results."""
        findings = []

        for result in parsed_data.get("results", []):
            url = result.get("url", "")
            status = result.get("status", 0)

            # Categorize findings based on status code
            if status == 200:
                findings.append(self._generate_finding(
                    vuln_class="discovered_endpoint",
                    target_url=url,
                    severity=Severity.INFO,
                    evidence=f"Discovered endpoint: {url} (Status: {status}, Size: {result.get('length')})",
                ))

            elif status in [301, 302, 307, 308]:
                findings.append(self._generate_finding(
                    vuln_class="interesting_redirect",
                    target_url=url,
                    severity=Severity.INFO,
                    evidence=f"Redirect found: {url} → {result.get('headers', {}).get('Location', 'unknown')}",
                ))

            elif status == 401:
                findings.append(self._generate_finding(
                    vuln_class="authenticated_endpoint",
                    target_url=url,
                    severity=Severity.INFO,
                    evidence=f"Protected endpoint discovered: {url}",
                    poc_steps=[
                        f"1. Discovered protected endpoint at: {url}",
                        "2. Test for authentication bypass",
                        "3. Try common credentials",
                        "4. Test for IDOR vulnerabilities",
                    ],
                ))

            elif status == 403:
                findings.append(self._generate_finding(
                    vuln_class="forbidden_endpoint",
                    target_url=url,
                    severity=Severity.LOW,
                    evidence=f"Forbidden endpoint: {url}",
                    poc_steps=[
                        f"1. Discovered forbidden endpoint at: {url}",
                        "2. Test for access control bypass",
                        "3. Try different HTTP methods",
                        "4. Test header manipulation",
                    ],
                ))

            # Check for interesting files
            path = result.get("file", "")
            interesting_extensions = [".bak", ".backup", ".old", ".tmp", ".log",
                                     ".conf", ".config", ".env", ".git", ".sql",
                                     ".db", ".xml", ".json", ".yml", ".yaml"]

            if any(path.endswith(ext) for ext in interesting_extensions):
                findings.append(self._generate_finding(
                    vuln_class="interesting_file",
                    target_url=url,
                    severity=Severity.MEDIUM,
                    evidence=f"Interesting file discovered: {url}",
                    poc_steps=[
                        f"1. Interesting file found: {url}",
                        "2. Check for sensitive information disclosure",
                        "3. Attempt to download file",
                    ],
                ))

        return findings
