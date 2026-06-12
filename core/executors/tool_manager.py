"""
core/executors/tool_manager.py — Tool Manager

Centralized management of all security tools with:
- Tool availability checking
- Unified execution interface
- Result aggregation
- Intelligent tool selection
"""

from __future__ import annotations

from typing import Any, Type
from pathlib import Path

from .base import ToolBase, ToolResult
from .httpx_executor import HttpxExecutor
from .nuclei_executor import NucleiExecutor
from .ffuf_executor import FfufExecutor
from shared.types import HuntState


class ToolManager:
    """
    Central manager for all security tools.

    Provides:
    - Unified interface to all tools
    - Tool availability checking
    - Intelligent tool selection based on context
    - Result aggregation
    """

    # Registry of available tool executors
    _tool_classes = {
        "httpx": HttpxExecutor,
        "nuclei": NucleiExecutor,
        "ffuf": FfufExecutor,
    }

    def __init__(self, state: HuntState):
        """
        Initialize tool manager.

        Args:
            state: Current hunt state
        """
        self.state = state
        self._executors = {}
        self._availability_cache = {}

    def get_executor(self, tool_name: str) -> ToolBase | None:
        """
        Get an executor instance for the specified tool.

        Args:
            tool_name: Name of the tool (httpx, nuclei, ffuf)

        Returns:
            Tool executor instance or None if tool not available
        """
        if tool_name not in self._tool_classes:
            return None

        # Check cache
        if tool_name in self._executors:
            return self._executors[tool_name]

        # Check availability
        if not self.is_available(tool_name):
            return None

        # Create executor
        tool_class = self._tool_classes[tool_name]
        executor = tool_class(self.state)
        self._executors[tool_name] = executor
        return executor

    def is_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is installed and available
        """
        if tool_name in self._availability_cache:
            return self._availability_cache[tool_name]

        if tool_name not in self._tool_classes:
            self._availability_cache[tool_name] = False
            return False

        tool_class = self._tool_classes[tool_name]
        executor = tool_class(self.state)
        available = executor.is_available()
        self._availability_cache[tool_name] = available

        if available:
            self._executors[tool_name] = executor

        return available

    def get_available_tools(self) -> list[str]:
        """
        Get list of all available tools.

        Returns:
            List of tool names that are available
        """
        return [name for name in self._tool_classes if self.is_available(name)]

    def get_missing_tools(self) -> list[str]:
        """
        Get list of missing tools.

        Returns:
            List of tool names that are not available
        """
        return [name for name in self._tool_classes if not self.is_available(name)]

    def run_recon(self, targets: list[str] | None = None) -> dict[str, ToolResult]:
        """
        Run reconnaissance using available tools.

        Uses:
        - httpx for endpoint discovery
        - nuclei for vulnerability detection

        Args:
            targets: List of targets to scan

        Returns:
            Dictionary of tool results
        """
        results = {}

        # Run httpx
        if self.is_available("httpx"):
            httpx = self.get_executor("httpx")
            results["httpx"] = httpx.run(urls=targets or [self.state.target.url])

        # Run nuclei
        if self.is_available("nuclei"):
            nuclei = self.get_executor("nuclei")
            results["nuclei"] = nuclei.run(
                urls=targets or [self.state.target.url],
                severity=["critical", "high", "medium"],
            )

        return results

    def run_fuzzing(
        self,
        url: str,
        wordlist: str | Path | None = None
    ) -> ToolResult | None:
        """
        Run fuzzing against a target.

        Uses ffuf for directory fuzzing.

        Args:
            url: Target URL with FUZZ keyword
            wordlist: Optional wordlist path

        Returns:
            Tool result or None
        """
        if not self.is_available("ffuf"):
            return None

        ffuf = self.get_executor("ffuf")
        return ffuf.run(url=url, wordlist=wordlist)

    def run_vulnerability_scan(
        self,
        targets: list[str] | None = None,
        severity: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> ToolResult | None:
        """
        Run vulnerability scan using nuclei.

        Args:
            targets: List of targets
            severity: Severities to scan for
            tags: Template tags to use

        Returns:
            Tool result or None
        """
        if not self.is_available("nuclei"):
            return None

        nuclei = self.get_executor("nuclei")
        return nuclei.run(
            urls=targets or [self.state.target.url],
            severity=severity,
            tags=tags,
        )

    def get_status_report(self) -> dict[str, Any]:
        """
        Get status report of all tools.

        Returns:
            Dictionary with tool status information
        """
        report = {
            "available": [],
            "missing": [],
            "details": {},
        }

        for tool_name in self._tool_classes:
            if self.is_available(tool_name):
                report["available"].append(tool_name)
                executor = self.get_executor(tool_name)
                report["details"][tool_name] = {
                    "status": "available",
                    "version": executor.get_version(),
                }
            else:
                report["missing"].append(tool_name)
                report["details"][tool_name] = {
                    "status": "missing",
                    "version": None,
                }

        return report

    def suggest_installation(self) -> str:
        """
        Get installation commands for missing tools.

        Returns:
            String with installation commands
        """
        missing = self.get_missing_tools()
        if not missing:
            return "All tools are available!"

        commands = []

        if "httpx" in missing:
            commands.append("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")

        if "nuclei" in missing:
            commands.append("go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

        if "ffuf" in missing:
            commands.append("go install github.com/ffuf/ffuf/v2@latest")

        return "\n".join(commands)


# Convenience function for quick access
def get_tool_manager(state: HuntState) -> ToolManager:
    """Get a tool manager instance for the given state."""
    return ToolManager(state)
