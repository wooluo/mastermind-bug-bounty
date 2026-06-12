"""
core/executors/base.py — Base class for tool executors

Provides the foundation for all tool wrappers with common functionality.
"""

from __future__ import annotations

import subprocess
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from enum import Enum

from shared.types import HuntState, Finding, Severity
from core.agent_interface import SkillResult, AgentExecutionStatus


class ToolStatus(str, Enum):
    """Status of a tool execution."""
    SUCCESS = "success"
    FAILED = "failed"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ToolResult:
    """Standardized result from tool execution."""
    status: ToolStatus
    raw_output: str = ""
    parsed_data: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    execution_time: float = 0.0
    command: str = ""
    error_message: str = ""

    def to_skill_result(self) -> SkillResult:
        """Convert to SkillResult for agent consumption."""
        return SkillResult(
            status=AgentExecutionStatus.SUCCESS if self.status == ToolStatus.SUCCESS else AgentExecutionStatus.FAILED,
            data=self.parsed_data,
            findings=self.findings,
            metadata={
                "tool_status": self.status.value,
                "execution_time": self.execution_time,
                "command": self.command,
                "raw_output_length": len(self.raw_output),
            },
        )


class ToolBase(ABC):
    """
    Base class for all tool executors.

    Provides common functionality:
    - Tool availability checking
    - Command execution with timeout
    - Output parsing
    - Finding extraction
    """

    def __init__(self, hunt_state: HuntState):
        self.state = hunt_state
        self._available: bool | None = None
        self._version: str | None = None

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of the tool."""
        pass

    @property
    @abstractmethod
    def executable_name(self) -> str:
        """Name of the executable to check for."""
        pass

    def is_available(self) -> bool:
        """Check if the tool is available on the system."""
        if self._available is not None:
            return self._available

        try:
            result = subprocess.run(
                ["which", self.executable_name],
                capture_output=True,
                timeout=5,
            )
            self._available = result.returncode == 0
            return self._available
        except Exception:
            self._available = False
            return False

    def get_version(self) -> str | None:
        """Get the version of the installed tool."""
        if self._version is not None:
            return self._version

        if not self.is_available():
            return None

        try:
            result = subprocess.run(
                [self.executable_name, "--version"],
                capture_output=True,
                timeout=5,
                text=True,
            )
            self._version = result.stdout.strip().split("\n")[0]
            return self._version
        except Exception:
            return None

    def _execute_command(
        self,
        command: list[str],
        cwd: Path | None = None,
        timeout: int = 300,
        env: dict | None = None,
    ) -> ToolResult:
        """
        Execute a command and return standardized result.

        Args:
            command: Command and arguments as list
            cwd: Working directory
            timeout: Timeout in seconds
            env: Environment variables

        Returns:
            ToolResult with execution status and output
        """
        import time

        result = ToolResult(
            command=" ".join(command),
        )

        try:
            start_time = time.time()

            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=timeout,
                env=env or {},
            )

            result.execution_time = time.time() - start_time
            result.raw_output = process.stdout

            if process.stderr:
                result.raw_output += f"\nSTDERR:\n{process.stderr}"

            result.status = ToolStatus.SUCCESS

        except subprocess.TimeoutExpired:
            result.status = ToolStatus.TIMEOUT
            result.error_message = f"Command timed out after {timeout} seconds"

        except FileNotFoundError:
            result.status = ToolStatus.NOT_FOUND
            result.error_message = f"Executable '{command[0]}' not found"

        except Exception as e:
            result.status = ToolStatus.ERROR
            result.error_message = str(e)

        return result

    @abstractmethod
    def run(self, **kwargs) -> ToolResult:
        """
        Run the tool with given parameters.

        Args:
            **kwargs: Tool-specific parameters

        Returns:
            ToolResult with findings and data
        """
        pass

    @abstractmethod
    def parse_output(self, raw_output: str) -> dict:
        """
        Parse tool output into structured data.

        Args:
            raw_output: Raw output from tool

        Returns:
            Parsed data dictionary
        """
        pass

    def extract_findings(self, parsed_data: dict) -> list[Finding]:
        """
        Extract findings from parsed tool output.

        Args:
            parsed_data: Parsed tool output

        Returns:
            List of Finding objects
        """
        return []

    def _generate_finding(
        self,
        vuln_class: str,
        target_url: str,
        severity: Severity = Severity.MEDIUM,
        evidence: str = "",
        **kwargs
    ) -> Finding:
        """Helper to create a Finding object."""
        from shared.utils import finding_id, now_iso

        return Finding(
            id=finding_id(),
            vuln_class=vuln_class,
            target_url=target_url,
            severity=severity,
            evidence=evidence,
            timestamp=now_iso(),
            **kwargs
        )
