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

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
