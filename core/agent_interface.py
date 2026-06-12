"""
core/agent_interface.py — Unified Agent Invocation Interface

Provides the standard interface for Hermes agents to interact with the
Mastermind system. Includes decorators, hooks, and standardized tool execution.

This module abstracts away the complexity of state management and provides
a clean, LLM-friendly API for agents to use.
"""

from __future__ import annotations

import functools
import inspect
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar, ParamSpec
from dataclasses import dataclass
from enum import Enum

from shared.types import (
    HuntState,
    Finding,
    FindingStatus,
    Severity,
    AgentState,
    WorklogEntry,
)
from shared.utils import now_iso, hunt_id
from shared.security import validate_target_url, sanitize_string


# ---------------------------------------------------------------------------
# Type variables for generic decorators
# ---------------------------------------------------------------------------

P = ParamSpec('P')
R = TypeVar('R')
T = TypeVar('T')


# ---------------------------------------------------------------------------
# Agent execution status
# ---------------------------------------------------------------------------

class AgentExecutionStatus(str, Enum):
    """Status of an agent skill execution."""
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    PARTIAL = "partial"


# ---------------------------------------------------------------------------
# Agent skill decorator
# ---------------------------------------------------------------------------

@dataclass
class SkillResult:
    """Result of an agent skill execution."""
    status: AgentExecutionStatus
    data: Any = None
    error: str = ""
    findings: list[Finding] = None
    metadata: dict = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "status": self.status.value,
            "data": self.data,
            "error": self.error,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "id": f.id,
                    "vuln_class": f.vuln_class,
                    "severity": f.severity.value,
                    "target_url": f.target_url,
                }
                for f in self.findings
            ],
            "metadata": self.metadata,
        }


def agent_skill(
    name: str | None = None,
    category: str = "general",
    capture_findings: bool = True,
    auto_state_update: bool = True,
):
    """
    Decorator to mark a function as an agent skill.

    This decorator automatically:
    - Tracks execution time
    - Logs to worklog
    - Captures findings returned by the function
    - Updates agent state
    - Handles errors gracefully

    Args:
        name: Skill name (defaults to function name)
        category: Skill category for organization
        capture_findings: Automatically capture Finding objects in return
        auto_state_update: Automatically update hunt state on completion

    Example:
        @agent_skill(name="scan_endpoint", category="recon")
        def scan_target(state: HuntState, target: str) -> SkillResult:
            # Do scanning
            return SkillResult(status=AgentExecutionStatus.SUCCESS, data={...})
    """
    def decorator(func: Callable[P, R]) -> Callable[P, SkillResult]:
        skill_name = name or func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> SkillResult:
            # Extract hunt_state from arguments
            state = None
            for arg in args:
                if isinstance(arg, HuntState):
                    state = arg
                    break
            if state is None:
                state = kwargs.get('hunt_state')

            if not state:
                return SkillResult(
                    status=AgentExecutionStatus.FAILED,
                    error="No HuntState provided to agent skill"
                )

            # Initialize result
            result = SkillResult(status=AgentExecutionStatus.SUCCESS)
            start_time = datetime.now(timezone.utc)

            try:
                # Call the actual function
                func_result = func(*args, **kwargs)

                # Handle different return types
                if isinstance(func_result, SkillResult):
                    result = func_result
                elif isinstance(func_result, dict):
                    result.data = func_result
                elif isinstance(func_result, list):
                    # Check if it's a list of findings
                    if func_result and isinstance(func_result[0], Finding):
                        result.findings = func_result
                    else:
                        result.data = func_result
                else:
                    result.data = func_result

                # Extract findings if capture enabled
                if capture_findings and isinstance(result.data, dict):
                    if 'findings' in result.data:
                        findings = result.data['findings']
                        if isinstance(findings, list):
                            result.findings.extend(findings)

                result.metadata.update({
                    'skill_name': skill_name,
                    'category': category,
                    'execution_time': (datetime.now(timezone.utc) - start_time).total_seconds(),
                })

                # Update state if enabled
                if auto_state_update:
                    _update_state_from_result(state, result, skill_name)

            except Exception as e:
                result.status = AgentExecutionStatus.FAILED
                result.error = str(e)
                result.metadata['traceback'] = traceback.format_exc()

            return result

        return wrapper
    return decorator


def _update_state_from_result(state: HuntState, result: SkillResult, skill_name: str):
    """Update hunt state from skill result."""
    # Add findings to state
    for finding in result.findings:
        if finding not in state.findings:
            state.findings.append(finding)

    # Update worklog
    state.touch()


# ---------------------------------------------------------------------------
# Agent hooks system
# ---------------------------------------------------------------------------

@dataclass
class AgentHookPoint:
    """A point in the workflow where agents can intervene."""
    name: str
    description: str
    phase: str
    callback: Callable | None = None


class AgentHooks:
    """
    Manages hook points for agent intervention during workflow execution.

    Agents can register callbacks at specific points to:
    - Make decisions about phase transitions
    - Modify data before processing
    - Add custom validation
    - Inject custom logic
    """

    def __init__(self):
        self._hooks: dict[str, list[Callable]] = {
            'pre_phase': [],
            'post_phase': [],
            'pre_finding': [],
            'post_finding': [],
            'on_blocked': [],
            'on_error': [],
            'decision_point': [],
        }

    def register(self, hook_type: str, callback: Callable):
        """Register a callback for a hook type."""
        if hook_type in self._hooks:
            self._hooks[hook_type].append(callback)
        else:
            raise ValueError(f"Unknown hook type: {hook_type}")

    def trigger(self, hook_type: str, *args: Any, **kwargs: Any) -> list[Any]:
        """Trigger all callbacks for a hook type."""
        results = []
        for callback in self._hooks.get(hook_type, []):
            try:
                result = callback(*args, **kwargs)
                results.append(result)
            except Exception:
                pass  # Hook failures should not stop execution
        return results

    def pre_phase(self, phase: str, state: HuntState) -> bool:
        """Trigger pre-phase hooks. Returns False to block phase."""
        results = self.trigger('pre_phase', phase, state)
        return all(r is not False for r in results)

    def post_phase(self, phase: str, state: HuntState):
        """Trigger post-phase hooks."""
        self.trigger('post_phase', phase, state)

    def on_finding(self, finding: Finding, state: HuntState) -> Finding | None:
        """Trigger finding hooks. Can modify or reject finding."""
        results = self.trigger('pre_finding', finding, state)
        if any(r is False for r in results):
            return None  # Finding rejected
        return finding

    def on_blocked(self, reason: str, state: HuntState):
        """Trigger when agent is blocked (WAF, rate limit, etc)."""
        self.trigger('on_blocked', reason, state)

    def on_error(self, error: Exception, state: HuntState):
        """Trigger on error."""
        self.trigger('on_error', error, state)

    def should_proceed(self, state: HuntState) -> bool:
        """Decision point hook - agents can vote on proceeding."""
        results = self.trigger('decision_point', state)
        return all(r is not False for r in results)


# ---------------------------------------------------------------------------
# Standardized tool executor
# ---------------------------------------------------------------------------

class ToolExecutor:
    """
    Standardized interface for executing security tools.

    All tool calls should go through this executor for:
    - Consistent error handling
    - Automatic state tracking
    - Result normalization
    - Security validation
    """

    def __init__(self, hunt_state: HuntState):
        self.state = hunt_state
        self._tools_executed: list[dict] = []

    @agent_skill(name="execute_http_request", category="network")
    def http_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        body: Any = None,
        follow_redirects: bool = True,
    ) -> SkillResult:
        """
        Execute an HTTP request with security validation.

        Args:
            url: Target URL (validated for SSRF)
            method: HTTP method
            headers: Request headers
            body: Request body
            follow_redirects: Whether to follow redirects

        Returns:
            SkillResult with response data
        """
        try:
            # Validate URL for SSRF protection
            validated_url = validate_target_url(url)

            # Import here to avoid hard dependency
            try:
                import requests
            except ImportError:
                return SkillResult(
                    status=AgentExecutionStatus.FAILED,
                    error="requests library not available"
                )

            # Execute request
            response = requests.request(
                method=method,
                url=validated_url,
                headers=headers or {},
                json=body if isinstance(body, dict) else None,
                data=body if isinstance(body, str) else None,
                allow_redirects=follow_redirects,
                timeout=30,
            )

            result_data = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:10000],  # Limit body size
                "url": response.url,
                "elapsed": response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
            }

            # Check for common vulnerability indicators
            findings = self._check_response_for_vulns(validated_url, result_data)

            return SkillResult(
                status=AgentExecutionStatus.SUCCESS,
                data=result_data,
                findings=findings,
            )

        except Exception as e:
            return SkillResult(
                status=AgentExecutionStatus.FAILED,
                error=str(e)
            )

    def _check_response_for_vulns(self, url: str, response: dict) -> list[Finding]:
        """Quick scan of response for obvious vulnerabilities."""
        findings = []
        status = response.get("status_code", 0)
        body = response.get("body", "")

        # Check for information disclosure
        if status == 500 and "stack trace" in body.lower():
            findings.append(Finding(
                id=hunt_id()[:8],
                vuln_class="information_disclosure",
                target_url=url,
                severity=Severity.MEDIUM,
                evidence="Stack trace in error response",
            ))

        # Check for missing security headers
        headers = response.get("headers", {})
        missing_headers = []
        for header in ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"]:
            if header not in headers:
                missing_headers.append(header)

        if missing_headers:
            findings.append(Finding(
                id=hunt_id()[:8],
                vuln_class="missing_security_headers",
                target_url=url,
                severity=Severity.LOW,
                evidence=f"Missing headers: {', '.join(missing_headers)}",
            ))

        return findings

    def get_execution_history(self) -> list[dict]:
        """Get history of tool executions."""
        return self._tools_executed.copy()


# ---------------------------------------------------------------------------
# Agent context manager
# ---------------------------------------------------------------------------

class AgentContext:
    """
    Context manager for agent operations.

    Provides agents with relevant context and handles cleanup.
    """

    def __init__(self, state: HuntState, agent_id: str = ""):
        self.state = state
        self.agent_id = agent_id or hunt_id()[:8]
        self._executor = ToolExecutor(state)

    @property
    def executor(self) -> ToolExecutor:
        """Get tool executor for this context."""
        return self._executor

    def get_relevant_findings(self, vuln_class: str | None = None) -> list[Finding]:
        """Get findings relevant to current context."""
        findings = self.state.findings
        if vuln_class:
            findings = [f for f in findings if f.vuln_class == vuln_class]
        return findings

    def get_endpoints(self) -> list[str]:
        """Get discovered endpoints."""
        return self.state.target.endpoints_discovered

    def get_js_files(self) -> list[str]:
        """Get discovered JavaScript files."""
        return self.state.target.js_files

    def log(self, message: str, level: str = "info"):
        """Log a message to the worklog."""
        from workflow.state import log_event
        log_event(
            self.state.hunt_dir,
            f"agent_log_{level}",
            self.agent_id,
            {"message": message}
        )


# ---------------------------------------------------------------------------
# Utility decorators
# ---------------------------------------------------------------------------

def validate_agent_input(**validators):
    """
    Decorator to validate agent function inputs.

    Example:
        @validate_agent_input(url=validate_target_url, count=lambda x: x > 0)
        def my_function(url: str, count: int):
            ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Apply validators
            for param_name, validator in validators.items():
                if param_name in kwargs:
                    try:
                        kwargs[param_name] = validator(kwargs[param_name])
                    except Exception as e:
                        return SkillResult(
                            status=AgentExecutionStatus.FAILED,
                            error=f"Validation failed for {param_name}: {e}"
                        )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def retry_on_failure(max_retries: int = 3, backoff: float = 1.0):
    """
    Decorator to retry agent skills on failure.

    Args:
        max_retries: Maximum number of retry attempts
        backoff: Exponential backoff multiplier
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        import time
                        time.sleep(backoff * (2 ** attempt))
            return SkillResult(
                status=AgentExecutionStatus.FAILED,
                error=f"Failed after {max_retries} attempts: {last_error}"
            )
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

__all__ = [
    'AgentExecutionStatus',
    'SkillResult',
    'agent_skill',
    'AgentHooks',
    'ToolExecutor',
    'AgentContext',
    'validate_agent_input',
    'retry_on_failure',
]
