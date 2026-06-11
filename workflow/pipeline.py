"""
workflow/pipeline.py — 6-Phase Pipeline (v3.1)

Phase definitions for the bug bounty pipeline.
"""

from __future__ import annotations

from shared.types import PhaseName
from dataclasses import dataclass, field


@dataclass
class Phase:
    name: str
    agent: str
    description: str = ""
    skills: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    optional: bool = False


PIPELINE: list[Phase] = [
    Phase(
        name="recon", agent="recon",
        description="RECON: chrome-devtools navigate + snow_eyes + download JS + fingerprint",
        skills=["js_analysis", "source_leak", "passive_recon"],
    ),
    Phase(
        name="dependency_scan", agent="recon",
        description="DEPENDENCY_SCAN: extract versions → match CVE → OOB verify",
        skills=["dependency_cve"],
        depends_on=["recon"],
    ),
    Phase(
        name="api_fuzz", agent="api_fuzz",
        description="API_FUZZ: blind probe endpoints → value pool linkage",
        skills=["api_fuzz", "data_linkage", "graphql_test"],
        depends_on=["recon"],
    ),
    Phase(
        name="crypto_attack", agent="crypto_attack",
        description="CRYPTO_ATTACK: JWT/AES/RSA attacks",
        skills=["crypto_attack", "jwt_attack"],
        depends_on=["api_fuzz"],
    ),
    Phase(
        name="bypass", agent="bypass",
        description="BYPASS: 401/403 bypass + OAuth/SSO attack",
        skills=["auth_bypass", "oauth_sso"],
        depends_on=["api_fuzz"],
    ),
    Phase(
        name="exploit", agent="exploit",
        description="EXPLOIT: P0 CVE/JWT → P1 SQLi/RCE → P2 XSS",
        skills=["vuln_classes", "race_condition"],
        depends_on=["crypto_attack", "bypass"],
    ),
    Phase(
        name="ai_security", agent="ai_security",
        description="AI_SECURITY: prompt injection, jailbreak",
        skills=["ai_security"],
        depends_on=["recon"],
        optional=True,
    ),
]


def get_phase(name: str) -> Phase | None:
    for p in PIPELINE:
        if p.name == name:
            return p
    return None


def get_next_phase(current: str) -> Phase | None:
    names = [p.name for p in PIPELINE]
    try:
        idx = names.index(current)
        return PIPELINE[idx + 1] if idx + 1 < len(PIPELINE) else None
    except ValueError:
        return None
