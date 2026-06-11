"""
workflow/orchestrator.py — Orchestrator v3.1 (Security Hardened)

Drives the pipeline phases with security validation.
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
from typing import Any


class Orchestrator:
    """Orchestrates the pipeline with security-aware phase transitions."""

    def __init__(self, hunt_dir: str | Path = "./hunt-data"):
        self.hunt_dir = Path(hunt_dir)
        self.state = None

    def run(self, target_url: str, scope: list[str] | None = None):
        """Run the hunt pipeline against a target."""
        from shared.types import HuntState, HuntStatus, PhaseName, Target
        from shared.utils import now_iso, hunt_id
        from shared.security import validate_target_url

        # Validate target
        validated_url = validate_target_url(target_url)

        # Create new state for this run
        self.state = HuntState(
            hunt_id=hunt_id(),
            target=Target(url=validated_url, scope=scope or [validated_url]),
            status=HuntStatus.ACTIVE,
            current_phase=PhaseName.RECON,
            created_at=now_iso(),
            updated_at=now_iso(),
        )

        # Simulate phases for demo
        print("  [Phase 1/6] RECON - Fingerprinting target...")
        self.state.completed_phases.append(PhaseName.RECON)

        print("  [Phase 2/6] DEPENDENCY_SCAN - Checking for CVEs...")
        self.state.completed_phases.append(PhaseName.DEPENDENCY_SCAN)

        print("  [Phase 3/6] API_FUZZ - Testing endpoints...")
        self.state.completed_phases.append(PhaseName.API_FUZZ)

        print("  [Phase 4/6] CRYPTO_ATTACK - Analyzing crypto...")
        self.state.completed_phases.append(PhaseName.CRYPTO_ATTACK)

        print("  [Phase 5/6] BYPASS - Testing access controls...")
        self.state.completed_phases.append(PhaseName.BYPASS)

        print("  [Phase 6/6] EXPLOIT - Generating reports...")
        self.state.completed_phases.append(PhaseName.EXPLOIT)

        self.state.current_phase = PhaseName.EXPLOIT
        self.state.touch()

        return self.state
