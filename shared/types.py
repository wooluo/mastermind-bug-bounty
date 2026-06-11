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
