"""
shared/types.py — Core data types for Mastermind Bug Bounty (Security Hardened).

All state, findings, and configuration flow through these types.
Zero external dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HuntStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"


class PhaseName(str, Enum):
    RECON = "recon"
    DEPENDENCY_SCAN = "dependency_scan"
    API_FUZZ = "api_fuzz"
    CRYPTO_ATTACK = "crypto_attack"
    BYPASS = "bypass"
    EXPLOIT = "exploit"
    AI_SECURITY = "ai_security"


class FindingStatus(str, Enum):
    DETECTED = "detected"
    TRIAGE_PENDING = "triage_pending"
    TRIAGE_APPROVED = "triage_approved"
    TRIAGE_REJECTED = "triage_rejected"
    POC_GENERATED = "poc_generated"
    REPORTED = "reported"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Target:
    """A single target under test."""
    url: str
    scope: list[str] = field(default_factory=list)
    tech_stack: dict[str, str] = field(default_factory=dict)
    waf_cdn: str = ""
    endpoints_discovered: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A vulnerability finding tracked through the triage pipeline."""
    id: str
    vuln_class: str
    target_url: str
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.0
    evidence: str = ""
    impact: str = ""
    poc_steps: list[str] = field(default_factory=list)
    status: FindingStatus = FindingStatus.DETECTED
    agent_id: str = ""
    timestamp: str = ""


@dataclass
class AgentState:
    """Tracked state of a specialist agent."""
    agent_id: str
    agent_type: str
    task: str = ""
    status: str = "idle"
    retry_count: int = 0
    max_retries: int = 3
    last_output: str = ""
    spawned_at: str = ""
    concluded_at: str = ""


@dataclass
class WorklogEntry:
    """A single entry in the hunt worklog."""
    timestamp: str
    session_id: str
    agent_id: str
    entry_type: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class HuntState:
    """Complete hunt session state — serialized across sessions."""
    hunt_id: str
    target: Target
    status: HuntStatus = HuntStatus.ACTIVE
    current_phase: PhaseName = PhaseName.RECON
    findings: list[Finding] = field(default_factory=list)
    completed_phases: list[PhaseName] = field(default_factory=list)
    agents: dict[str, AgentState] = field(default_factory=dict)
    worklog: list[WorklogEntry] = field(default_factory=list)
    custom_instructions: str = ""
    created_at: str = ""
    updated_at: str = ""
    # Agent-friendly helper properties
    hunt_dir: str = "./hunt-data"
    js_analysis_meta: JSAnalysisMeta | None = None
    linkage_pairs: list[UnconsumedPair] = field(default_factory=list)

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # -----------------------------------------------------------------------
    # Agent-friendly query methods
    # -----------------------------------------------------------------------

    def get_unconsumed_critical_pairs(self) -> list[UnconsumedPair]:
        """Get unconsumed value-endpoint pairs with CRITICAL priority."""
        return [p for p in self.linkage_pairs
                if p.priority == "CRITICAL" and
                (p.value_entry is None or p.value_entry.status != "consumed")]

    def get_pending_fuzzing_targets(self) -> list[EndpointParamRequirement]:
        """Get endpoints that still need fuzzing/testing."""
        # Return endpoints that haven't been fully tested
        from core.linkage import ValueLinkageEngine
        engine = ValueLinkageEngine()
        result = engine.process_state(self)
        if result.unconsumed_pairs > 0:
            pairs = engine.get_unconsumed_pairs(self, limit=50)
            # Convert pairs to endpoint requirements
            endpoints = {}
            for pair in pairs:
                if pair.endpoint not in endpoints:
                    endpoints[pair.endpoint] = EndpointParamRequirement(
                        endpoint=pair.endpoint,
                        method=pair.method,
                        params_optional=[pair.param_name],
                    )
                else:
                    if pair.param_name not in endpoints[pair.endpoint].params_optional:
                        endpoints[pair.endpoint].params_optional.append(pair.param_name)
            return list(endpoints.values())
        return []

    def should_transition(self, next_phase: PhaseName) -> bool:
        """Determine if the hunt can transition to the next phase."""
        from workflow.pipeline import get_phase

        # Check if current phase dependencies are met
        phase = get_phase(next_phase.value if isinstance(next_phase, str) else next_phase.value)
        if not phase:
            return False

        # Check if all dependencies are completed
        for dep in phase.depends_on:
            dep_phase = PhaseName(dep) if isinstance(dep, str) else dep
            if dep_phase not in self.completed_phases:
                return False

        # Phase-specific checks
        if next_phase == PhaseName.API_FUZZ:
            # Need endpoints and value linkage
            return len(self.target.endpoints_discovered) > 0
        elif next_phase == PhaseName.EXPLOIT:
            # Need approved findings
            return any(f.status == FindingStatus.TRIAGE_APPROVED for f in self.findings)

        return True

    def get_relevant_context(self, task: str) -> dict[str, Any]:
        """Get context relevant to a specific task."""
        context = {
            "hunt_id": self.hunt_id,
            "target": self.target.url,
            "current_phase": self.current_phase.value,
            "status": self.status.value,
        }

        # Task-specific context
        task_lower = task.lower()
        if "fuzz" in task_lower or "api" in task_lower:
            context["endpoints"] = self.target.endpoints_discovered[:50]
            context["tech_stack"] = self.target.tech_stack
        elif "crypto" in task_lower or "jwt" in task_lower:
            context["findings"] = [f for f in self.findings if "crypto" in f.vuln_class.lower() or "jwt" in f.vuln_class.lower()]
        elif "bypass" in task_lower or "auth" in task_lower:
            context["endpoints"] = [e for e in self.target.endpoints_discovered if "auth" in e.lower() or "login" in e.lower()]
            context["findings"] = [f for f in self.findings if "auth" in f.vuln_class.lower()]

        return context

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_pending_findings(self) -> list[Finding]:
        """Get findings that need triage."""
        return [f for f in self.findings
                if f.status in (FindingStatus.DETECTED, FindingStatus.TRIAGE_PENDING)]

    def get_approved_findings(self) -> list[Finding]:
        """Get findings that passed triage."""
        return [f for f in self.findings
                if f.status in (FindingStatus.TRIAGE_APPROVED, FindingStatus.POC_GENERATED)]

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the state."""
        self.findings.append(finding)
        self.touch()

    def complete_phase(self, phase: PhaseName) -> None:
        """Mark a phase as completed."""
        if phase not in self.completed_phases:
            self.completed_phases.append(phase)
        self.current_phase = phase
        self.touch()

    def get_summary(self) -> str:
        """Get a concise summary of the hunt state."""
        parts = [
            f"Hunt: {self.hunt_id}",
            f"Target: {self.target.url}",
            f"Phase: {self.current_phase.value}",
            f"Status: {self.status.value}",
            f"Findings: {len(self.findings)} ({sum(1 for f in self.findings if f.status == FindingStatus.TRIAGE_APPROVED)} approved)",
            f"Endpoints: {len(self.target.endpoints_discovered)}",
        ]
        return " | ".join(parts)


# ---------------------------------------------------------------------------
# Data linkage types (used by shared/linkage.py)
# ---------------------------------------------------------------------------

@dataclass
class ValueEntry:
    """"""
    value: str
    status: str = "pending"
    discovered_at: str = ""
    source_endpoint: str = ""
    source_param: str = ""
    priority: str = "NORMAL"
    unconsumed_endpoints: list[str] = field(default_factory=list)
    consumed_endpoints: list[str] = field(default_factory=list)


class ValueStatus(str, Enum):
    PENDING = "pending"
    CONSUMING = "consuming"
    CONSUMED = "consumed"
    SKIPPED = "skipped"


@dataclass
class UnconsumedPair:
    param_name: str
    value: str = ""
    endpoint: str = ""
    method: str = "GET"
    fallback_methods: list[str] = field(default_factory=list)
    priority: str = "NORMAL"
    reason: str = ""
    value_entry: ValueEntry | None = None


@dataclass
class EndpointParamRequirement:
    endpoint: str
    method: str
    params_required: list[str] = field(default_factory=list)
    params_optional: list[str] = field(default_factory=list)
    content_type: str = "application/json"
    auth: str = "none"
    source_files: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class MethodFallback:
    method: str
    content_type: str
    body_variant: str = ""


@dataclass
class LinkageCheckResult:
    passed: bool = False
    complete: bool = False
    block_transition: bool = False
    total_values: int = 0
    total_pairs: int = 0
    unconsumed: int = 0
    unconsumed_pairs: int = 0
    consumed_pairs: int = 0
    pairs_made: int = 0
    critical_unconsumed: int = 0
    summary: str = ""
    details: str = ""


@dataclass
class JSAnalysisMeta:
    total_js_files: int = 0
    js_files_collected: int = 0
    js_files_analyzed: int = 0
    js_files_skipped: list[str] = field(default_factory=list)
    skipped_reason: str = ""
    analysis_completeness: float = 0.0
    total_endpoints_extracted: int = 0
    total_secrets_found: int = 0
    total_routes_found: int = 0
    files_detail: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    generated_at: str = ""
    last_analysis: str = ""


@dataclass
class JSAnalysisCheckResult:
    passed: bool = False
    summary: str = ""
    meta: JSAnalysisMeta | None = None
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    all_files_downloaded: bool = False
    all_files_read: bool = False
    endpoint_params_created: bool = False
    has_endpoints: bool = False
    completeness_valid: bool = False
