"""
workflow/state.py — Hunt state persistence layer (Security Hardened)

Manages the full lifecycle of a hunt with security enhancements:
    - HMAC signature verification for integrity
    - Optional encryption for sensitive data
    - Secure file permissions
    - Input validation

Author: Security Enhancement
Date: 2026-06-11
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.types import (
    AgentState,
    Finding,
    FindingStatus,
    HuntState,
    HuntStatus,
    PhaseName,
    Target,
    WorklogEntry,
)
from shared.utils import (
    append_jsonl,
    now_iso,
    read_json,
    read_jsonl,
    write_json,
)
from shared.security import (
    SecureFileHandler,
    get_secure_hmac_key,
    ValidationError,
    validate_json_size,
)


# ---------------------------------------------------------------------------
# Hunt directory structure (with security)
# ---------------------------------------------------------------------------
# hunt-data/
#   state.json.signed          # Full hunt state (HMAC signed)
#   state.json.enc             # Encrypted backup (optional)
#   worklog.jsonl              # Append-only action log
#   vault/
#     handoff_latest.md        # Most recent handoff
#   .audit/                    # Security audit logs
#   .rate_limit                # Rate limit data


def _default_hunt_dir() -> Path:
    return Path.cwd() / "hunt-data"


def _ensure_hunt_dir(hunt_dir: str | Path) -> Path:
    """Ensure hunt directory exists with secure permissions."""
    from shared.security import validate_hunt_dir
    return validate_hunt_dir(hunt_dir)


def _get_secure_handler(hunt_dir: Path) -> SecureFileHandler:
    """Get a secure file handler for the hunt directory."""
    hmac_key = get_secure_hmac_key()
    return SecureFileHandler(hunt_dir, hmac_key=hmac_key)


# ---------------------------------------------------------------------------
# State file paths
# ---------------------------------------------------------------------------

def _state_path(hunt_dir: Path) -> Path:
    return hunt_dir / "state.json.signed"


def _worklog_path(hunt_dir: Path) -> Path:
    return hunt_dir / "worklog.jsonl"


def _encrypted_state_path(hunt_dir: Path) -> Path:
    return hunt_dir / "state.json.enc"


# ---------------------------------------------------------------------------
# Create / Load / Save
# ---------------------------------------------------------------------------

def create_hunt(target_url: str, scope: list[str] | None = None,
                hunt_dir: str | Path | None = None) -> HuntState:
    """Initialize a brand-new hunt for the given target."""
    from shared.utils import hunt_id as gen_hunt_id
    from shared.security import validate_target_url

    # Validate target URL
    validated_url = validate_target_url(target_url)

    base = _ensure_hunt_dir(hunt_dir or _default_hunt_dir())

    state = HuntState(
        hunt_id=gen_hunt_id(),
        target=Target(url=validated_url, scope=scope or [validated_url]),
        created_at=now_iso(),
        updated_at=now_iso(),
    )

    # Ensure audit directory exists
    (base / '.audit').mkdir(exist_ok=True)
    (base / '.audit').chmod(0o700)

    if hunt_dir:
        _persist_state(base, state)

    return state


def load_hunt(hunt_dir: str | Path) -> HuntState | None:
    """Load an existing hunt state from disk with verification."""
    base = _ensure_hunt_dir(hunt_dir)
    sp = _state_path(base)

    if not sp.exists():
        return None

    try:
        # Use secure handler to read with HMAC verification
        handler = _get_secure_handler(base)
        data = handler.read_secure(sp)

        if not isinstance(data, dict):
            return None

        return _deserialize_state(data)

    except (ValueError, json.JSONDecodeError, KeyError) as e:
        # HMAC verification failed or data corrupted
        print(f"[Security] Warning: State file verification failed: {e}")
        return None
    except Exception:
        return None


def save_hunt(state: HuntState, hunt_dir: str | Path) -> bool:
    """Persist the hunt state to disk with security features."""
    state.touch()
    base = _ensure_hunt_dir(hunt_dir)
    return _persist_state(base, state)


def _persist_state(hunt_dir: Path, state: HuntState) -> bool:
    """Persist state with HMAC signature and secure permissions."""
    try:
        handler = _get_secure_handler(hunt_dir)

        # Serialize state
        data = _serialize_state(state)

        # Validate size
        validate_json_size(data, max_size=100 * 1024 * 1024)  # 100MB

        # Write with HMAC signature
        handler.write_secure(_state_path(hunt_dir), data)

        return True

    except ValidationError as e:
        print(f"[Security] State validation failed: {e.message}")
        return False
    except Exception:
        return False


def backup_encrypted(state: HuntState, hunt_dir: Path, enc_key: bytes) -> bool:
    """Create encrypted backup of state file."""
    try:
        handler = _get_secure_handler(hunt_dir)
        data = _serialize_state(state)

        handler.write_secure(
            _encrypted_state_path(hunt_dir),
            data,
            encrypt=True,
            enc_key=enc_key
        )

        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Internal serialization
# ---------------------------------------------------------------------------

def _serialize_state(state: HuntState) -> dict:
    """Serialize state to dict with size limits."""
    findings_list = []

    for f in state.findings:
        # Limit size of each finding
        finding_dict = {
            "id": f.id,
            "vuln_class": f.vuln_class,
            "target_url": f.target_url,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "evidence": (f.evidence or "")[:10000],  # Limit evidence size
            "impact": (f.impact or "")[:5000],       # Limit impact size
            "poc_steps": (f.poc_steps or [])[:100],  # Limit POC steps
            "status": f.status.value,
            "agent_id": f.agent_id,
            "timestamp": f.timestamp,
        }
        findings_list.append(finding_dict)

    return {
        "hunt_id": state.hunt_id,
        "target": {
            "url": state.target.url,
            "scope": state.target.scope[:100],  # Limit scope entries
            "tech_stack": state.target.tech_stack,
            "waf_cdn": state.target.waf_cdn,
            "endpoints_discovered": state.target.endpoints_discovered[:1000],  # Limit endpoints
            "js_files": state.target.js_files[:500],  # Limit JS files
        },
        "status": state.status.value,
        "current_phase": state.current_phase.value,
        "findings": findings_list,
        "completed_phases": [p.value for p in state.completed_phases],
        "agents": {
            aid: {
                "agent_id": a.agent_id,
                "agent_type": a.agent_type,
                "task": (a.task or "")[:1000],  # Limit task size
                "status": a.status,
                "retry_count": a.retry_count,
                "max_retries": a.max_retries,
                "last_output": (a.last_output or "")[:5000],  # Limit output size
                "spawned_at": a.spawned_at,
                "concluded_at": a.concluded_at,
            }
            for aid, a in state.agents.items()
        },
        "custom_instructions": (state.custom_instructions or "")[:5000],
        "created_at": state.created_at,
        "updated_at": state.updated_at,
    }


def _deserialize_state(raw: dict) -> HuntState:
    """Deserialize state from dict with validation."""
    try:
        target_raw = raw.get("target", {})

        # Validate target URL
        from shared.security import validate_target_url
        target_url = target_raw.get("url", "")
        if target_url:
            target_url = validate_target_url(target_url)

        target = Target(
            url=target_url,
            scope=target_raw.get("scope", []),
            tech_stack=target_raw.get("tech_stack", {}),
            waf_cdn=target_raw.get("waf_cdn", ""),
            endpoints_discovered=target_raw.get("endpoints_discovered", []),
            js_files=target_raw.get("js_files", []),
        )

        findings = [
            Finding(
                id=f["id"],
                vuln_class=f["vuln_class"],
                target_url=f["target_url"],
                severity=f["severity"],
                confidence=f.get("confidence", 0.0),
                evidence=f.get("evidence", ""),
                impact=f.get("impact", ""),
                poc_steps=f.get("poc_steps", []),
                status=FindingStatus(f.get("status", "detected")),
                agent_id=f.get("agent_id", ""),
                timestamp=f.get("timestamp", ""),
            )
            for f in raw.get("findings", [])
        ]

        agents = {
            aid: AgentState(
                agent_id=a["agent_id"],
                agent_type=a["agent_type"],
                task=a.get("task", ""),
                status=a.get("status", "idle"),
                retry_count=a.get("retry_count", 0),
                max_retries=a.get("max_retries", 3),
                last_output=a.get("last_output", ""),
                spawned_at=a.get("spawned_at", ""),
                concluded_at=a.get("concluded_at", ""),
            )
            for aid, a in raw.get("agents", {}).items()
        }

        return HuntState(
            hunt_id=raw["hunt_id"],
            target=target,
            status=HuntStatus(raw.get("status", "active")),
            current_phase=PhaseName(raw.get("current_phase", "recon")),
            findings=findings,
            completed_phases=[PhaseName(p) for p in raw.get("completed_phases", [])],
            agents=agents,
            custom_instructions=raw.get("custom_instructions", ""),
            created_at=raw.get("created_at", ""),
            updated_at=raw.get("updated_at", ""),
        )

    except (KeyError, ValueError, TypeError) as e:
        raise ValueError(f"Invalid state data: {e}")


# ---------------------------------------------------------------------------
# Worklog (with security)
# ---------------------------------------------------------------------------

def log_event(hunt_dir: str | Path, entry_type: str,
              agent_id: str, data: dict | None = None) -> WorklogEntry:
    """Record a worklog event with size limits."""
    from shared.security import sanitize_string

    entry = WorklogEntry(
        timestamp=now_iso(),
        session_id="",
        agent_id=sanitize_string(agent_id, 100),  # Limit agent ID size
        entry_type=sanitize_string(entry_type, 50),  # Limit entry type size
        data=(data or {})[:100],  # Limit data size
    )

    base = _ensure_hunt_dir(hunt_dir)

    # Sanitize and size limit data
    sanitized_data = {
        k: sanitize_string(str(v)[:500], 500) if isinstance(v, str) else v
        for k, v in entry.data.items()
    }

    append_jsonl(_worklog_path(base), {
        "timestamp": entry.timestamp,
        "agent_id": entry.agent_id,
        "entry_type": entry.entry_type,
        "data": sanitized_data,
    })

    return entry


def load_recent_worklog(hunt_dir: str | Path, minutes: int = 30) -> list[dict]:
    """Load worklog entries from the last N minutes with validation."""
    from datetime import timedelta

    base = _ensure_hunt_dir(hunt_dir)

    # Check file size before loading
    worklog_path = _worklog_path(base)
    if worklog_path.exists():
        file_size = worklog_path.stat().st_size
        max_size = 500 * 1024 * 1024  # 500MB
        if file_size > max_size:
            print(f"[Security] Warning: Worklog file too large ({file_size} bytes)")
            return []

    entries = read_jsonl(worklog_path)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    recent: list[dict] = []
    for e in entries:
        ts_raw = e.get("timestamp", "")
        if not ts_raw:
            continue
        try:
            ts_raw_clean = ts_raw.replace("Z", "+00:00")
            ts = datetime.fromisoformat(ts_raw_clean)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                recent.append(e)
        except (ValueError, TypeError):
            continue

    recent.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return recent[:100]  # Limit to 100 recent entries


# ---------------------------------------------------------------------------
# Finding helpers (with validation)
# ---------------------------------------------------------------------------

def add_finding(state: HuntState, vuln_class: str, target_url: str,
                severity: str = "medium", confidence: float = 0.0,
                evidence: str = "", agent_id: str = "") -> Finding:
    """Create a new finding with validation and size limits."""
    from shared.utils import finding_id as gen_finding_id
    from shared.security import sanitize_string, validate_json_size

    # Sanitize inputs
    vuln_class = sanitize_string(vuln_class, 100)
    target_url = sanitize_string(target_url, 500)
    evidence = sanitize_string(evidence, 10000)

    # Validate target URL
    from shared.security import validate_target_url
    if target_url:
        target_url = validate_target_url(target_url)

    f = Finding(
        id=gen_finding_id(),
        vuln_class=vuln_class,
        target_url=target_url,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        agent_id=sanitize_string(agent_id, 100),
        timestamp=now_iso(),
    )

    # Check total findings limit
    if len(state.findings) >= 10000:
        raise ValueError("Maximum number of findings (10000) reached")

    state.findings.append(f)
    return f


def get_pending_findings(state: HuntState) -> list[Finding]:
    """Findings that need triage."""
    return [f for f in state.findings
            if f.status in (FindingStatus.DETECTED, FindingStatus.TRIAGE_PENDING)][:1000]


def get_approved_findings(state: HuntState) -> list[Finding]:
    """Findings that passed triage."""
    return [f for f in state.findings
            if f.status in (FindingStatus.TRIAGE_APPROVED, FindingStatus.POC_GENERATED)][:1000]


# ---------------------------------------------------------------------------
# Cleanup utilities
# ---------------------------------------------------------------------------

def cleanup_old_data(hunt_dir: Path, days: int = 30) -> dict:
    """Clean up old audit logs and temporary files.

    Args:
        hunt_dir: The hunt directory
        days: Keep data newer than this many days

    Returns:
        Summary of cleanup actions
    """
    import time

    summary = {
        'files_deleted': 0,
        'space_freed': 0,
        'errors': []
    }

    cutoff_time = time.time() - (days * 24 * 60 * 60)

    try:
        # Clean up old audit logs
        audit_dir = hunt_dir / '.audit'
        if audit_dir.exists():
            for file in audit_dir.glob('*.log*'):
                if file.stat().st_mtime < cutoff_time:
                    try:
                        size = file.stat().st_size
                        file.unlink()
                        summary['files_deleted'] += 1
                        summary['space_freed'] += size
                    except Exception as e:
                        summary['errors'].append(str(e))

    except Exception as e:
        summary['errors'].append(str(e))

    return summary
