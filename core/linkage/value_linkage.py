"""
core/linkage/value_linkage.py — Value Linkage Engine for Agent-Driven Testing

Automatically links discovered values (from JS analysis, responses, etc.)
to unconsumed endpoint parameters for intelligent fuzzing.

This is the core data correlation engine that enables Hermes agents to
make informed decisions about which values to test against which endpoints.
"""

from __future__ import annotations

import re
import json
from datetime import datetime, timezone
from typing import Any
from collections import defaultdict
from dataclasses import dataclass

from shared.types import (
    ValueEntry,
    ValueStatus,
    UnconsumedPair,
    EndpointParamRequirement,
    LinkageCheckResult,
    JSAnalysisMeta,
    JSAnalysisCheckResult,
    HuntState,
    PhaseName,
)
from shared.utils import now_iso


# ---------------------------------------------------------------------------
# Value extraction patterns
# ---------------------------------------------------------------------------

# Common patterns for extracting values from JS and responses
VALUE_PATTERNS = {
    # JWT Tokens
    'jwt': [
        r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        r'["\']jwt["\']\s*[:=]\s*["\']([A-Za-z0-9_.-]{20,})["\']',
    ],
    # API Keys (general)
    'api_key': [
        r'["\']api[_-]?key["\']\s*[:=]\s*["\']([A-Za-z0-9\-._~+/]{16,})["\']',
        r'apiKey["\']?\s*[:=]\s*["\']([A-Za-z0-9\-._~+/]{16,})["\']',
        r'["\']key["\']\s*[:=]\s*["\']([A-Za-z0-9\-._~+/]{16,})["\']',
    ],
    # Service-specific API keys
    'aws_key': [
        r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
        r'["\']aws[_-]?key["\']\s*[:=]\s*["\']([A-Za-z0-9/+=]{20,})["\']',
    ],
    'google_api_key': [
        r'AIza[0-9A-Za-z_-]{35}',  # Google API key
        r'["\']google[_-]?api[_-]?key["\']\s*[:=]\s*["\']([A-Za-z0-9\-._~+/]{20,})["\']',
    ],
    'github_token': [
        r'gh[pousr]_[A-Za-z0-9]{20,}',  # GitHub tokens (more flexible)
    ],
    'slack_token': [
        r'xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9A-Za-z]{24}',  # Slack tokens
    ],
    'stripe_key': [
        r'sk_[a-zA-Z0-9]{24,}',  # Stripe secret key
        r'pk_[a-zA-Z0-9]{24,}',  # Stripe publishable key
    ],
    # Authentication tokens
    'bearer_token': [
        r'Bearer\s+([A-Za-z0-9\-._~+/]{20,})',
        r'["\']bearer[_-]?token["\']\s*[:=]\s*["\']([A-Za-z0-9\-._~+/]{20,})["\']',
    ],
    'auth_token': [
        r'["\']auth[_-]?token["\']\s*[:=]\s*["\']([A-Za-z0-9\-._~+/]{20,})["\']',
        r'["\']token["\']\s*[:=]\s*["\']([A-Za-z0-9\-._~+/]{20,})["\']',
        r'["\']access[_-]?token["\']\s*[:=]\s*["\']([A-Za-z0-9\-._~+/]{20,})["\']',
    ],
    'refresh_token': [
        r'["\']refresh[_-]?token["\']\s*[:=]\s*["\']([A-Za-z0-9\-._~+/]{20,})["\']',
    ],
    # User identifiers
    'user_id': [
        r'["\']user[_-]?id["\']\s*[:=]\s*["\']?([A-Za-z0-9\-]{8,})["\']?',
        r'userId["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-]{8,})["\']?',
        r'["\']uid["\']\s*[:=]\s*["\']?([A-Za-z0-9\-]{8,})["\']?',
    ],
    'session_id': [
        r'["\']session[_-]?id["\']\s*[:=]\s*["\']?([A-Za-z0-9\-]{20,})["\']?',
        r'sessionId["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-]{20,})["\']?',
        r'["\']sid["\']\s*[:=]\s*["\']?([A-Za-z0-9\-]{20,})["\']?',
    ],
    'csrf_token': [
        r'["\']csrf[_-]?token["\']\s*[:=]\s*["\']([A-Za-z0-9\-]{20,})["\']',
        r'["\']_token["\']\s*[:=]\s*["\']([A-Za-z0-9\-]{20,})["\']',
        r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([A-Za-z0-9\-]+)["\']',
    ],
    # Common identifiers
    'email': [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    ],
    'uuid': [
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',  # uppercase
    ],
    'guid': [
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    ],
    'numeric_id': [
        r'["\']id["\']\s*[:=]\s*(\d{4,})',
        r'["\']userId["\']\s*[:=]\s*(\d{4,})',
        r'["\']accountId["\']\s*[:=]\s*(\d{4,})',
    ],
    # Sensitive data
    'password': [
        r'["\']password["\']\s*[:=]\s*["\']([^"\']{6,})["\']',
        r'["\']passwd["\']\s*[:=]\s*["\']([^"\']{6,})["\']',
        r'["\']pwd["\']\s*[:=]\s*["\']([^"\']{6,})["\']',
    ],
    'secret': [
        r'["\']secret["\']\s*[:=]\s*["\']([^"\']{10,})["\']',
        r'["\']api[_-]?secret["\']\s*[:=]\s*["\']([^"\']{10,})["\']',
    ],
    # URLs and endpoints
    'internal_url': [
        r'["\']url["\']\s*[:=]\s*["\'](https?://[^"\']+)["\']',
        r'["\']endpoint["\']\s*[:=]\s*["\'](https?://[^"\']+)["\']',
        r'["\']api[_-]?url["\']\s*[:=]\s*["\'](https?://[^"\']+)["\']',
    ],
    # Database related
    'database_url': [
        r'(postgres|mysql|mongodb|redis)://[^"\s]+\.[^"\s]+',
        r'["\']database[_-]?url["\']\s*[:=]\s*["\']([^"\']{10,})["\']',
        r'["\']db[_-]?url["\']\s*[:=]\s*["\']([^"\']{10,})["\']',
    ],
    # Cloud services
    's3_bucket': [
        r'["\']s3[_-]?bucket["\']\s*[:=]\s*["\']([A-Za-z0-9.\-]{3,63})["\']',
        r'https?://s3[.\-]amazonaws\.com/["\']?([A-Za-z0-9.\-]{3,63})["\']?',
        r'([A-Za-z0-9.\-]{3,63})\.s3[.\-]amazonaws\.com',
    ],
    # Configuration files
    'config_path': [
        r'["\']config[_-]?file["\']\s*[:=]\s*["\']([^"\']+\.(json|yaml|yml|xml|conf|ini))["\']',
        r'["\']env[_-]?file["\']\s*[:=]\s*["\']([^"\']+\.env)["\']',
    ],
    # GraphQL
    'graphql_operation': [
        r'["\']query["\']\s*[:=]\s*["\']([A-Za-z][A-Za-z0-9_]{3,})["\']',
        r'["\']mutation["\']\s*[:=]\s*["\']([A-Za-z][A-Za-z0-9_]{3,})["\']',
        r'query\s+([A-Za-z][A-Za-z0-9_]{3,})\s*\(',
        r'mutation\s+([A-Za-z][A-Za-z0-9_]{3,})\s*\(',
    ],
    # IP addresses (internal)
    'internal_ip': [
        r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        r'\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b',
        r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
        r'\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    ],
    # Phone numbers
    'phone': [
        r'\b\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
        r'\b\+?[\d\s\-()]{10,}\b',
    ],
    # Base64 encoded data (potential secrets)
    'base64_secret': [
        r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']',
    ],
}


# ---------------------------------------------------------------------------
# Priority levels for value-endpoint pairs
# ---------------------------------------------------------------------------

class LinkagePriority:
    """Priority levels for unconsumed pairs."""
    CRITICAL = "CRITICAL"    # Auth tokens, API keys, sensitive data
    HIGH = "HIGH"           # User IDs, session IDs
    NORMAL = "NORMAL"       # Regular parameters
    LOW = "LOW"             # Optional parameters


# ---------------------------------------------------------------------------
# Main linkage engine
# ---------------------------------------------------------------------------

class ValueLinkageEngine:
    """
    Engine for automatically linking discovered values to unconsumed endpoints.

    Usage:
        engine = ValueLinkageEngine()
        result = engine.process_state(state)
        pairs = engine.get_unconsumed_pairs(state)
    """

    def __init__(self):
        self._value_cache: dict[str, ValueEntry] = {}
        self._endpoint_cache: dict[str, EndpointParamRequirement] = {}
        self._pair_cache: list[UnconsumedPair] = []

    # -----------------------------------------------------------------------
    # Main processing methods
    # -----------------------------------------------------------------------

    def process_state(self, state: HuntState) -> LinkageCheckResult:
        """
        Process a hunt state and extract/link all values to endpoints.

        Args:
            state: Current hunt state

        Returns:
            LinkageCheckResult with statistics and generated pairs
        """
        result = LinkageCheckResult()

        # Extract values from JS files
        js_values = self._extract_from_js_analysis(state)
        self._register_values(js_values, state)

        # Extract values from discovered endpoints
        endpoint_values = self._extract_from_endpoints(state)
        self._register_values(endpoint_values, state)

        # Build endpoint parameter requirements
        self._build_endpoint_requirements(state)

        # Generate unconsumed pairs
        self._generate_unconsumed_pairs(state)

        # Calculate statistics
        result.total_values = len(self._value_cache)
        result.total_pairs = len(self._pair_cache)
        result.unconsumed = len([p for p in self._pair_cache if p.value_entry.status != ValueStatus.CONSUMED])
        result.unconsumed_pairs = result.unconsumed
        result.consumed_pairs = result.total_pairs - result.unconsumed
        result.pairs_made = result.total_pairs
        result.critical_unconsumed = len([
            p for p in self._pair_cache
            if p.priority == LinkagePriority.CRITICAL and p.value_entry.status != ValueStatus.CONSUMED
        ])

        # Generate summary
        result.summary = self._generate_summary(result)
        result.details = self._generate_details(result)

        # Check if linkage is complete
        result.passed = result.unconsumed == 0
        result.complete = result.unconsumed == 0
        result.block_transition = result.critical_unconsumed > 0

        return result

    def get_unconsumed_pairs(
        self,
        state: HuntState,
        priority: str | None = None,
        limit: int = 100
    ) -> list[UnconsumedPair]:
        """
        Get unconsumed value-endpoint pairs for agent processing.

        Args:
            state: Current hunt state
            priority: Filter by priority (CRITICAL, HIGH, NORMAL, LOW)
            limit: Maximum number of pairs to return

        Returns:
            List of UnconsumedPair sorted by priority
        """
        pairs = [p for p in self._pair_cache if p.value_entry.status != ValueStatus.CONSUMED]

        if priority:
            pairs = [p for p in pairs if p.priority == priority]

        # Sort by priority (CRITICAL > HIGH > NORMAL > LOW)
        priority_order = {LinkagePriority.CRITICAL: 0, LinkagePriority.HIGH: 1,
                         LinkagePriority.NORMAL: 2, LinkagePriority.LOW: 3}
        pairs.sort(key=lambda p: priority_order.get(p.priority, 99))

        return pairs[:limit]

    # -----------------------------------------------------------------------
    # Value extraction methods
    # -----------------------------------------------------------------------

    def _extract_from_js_analysis(self, state: HuntState) -> list[ValueEntry]:
        """Extract values from analyzed JavaScript files."""
        values = []

        for js_file in state.target.js_files:
            try:
                js_path = state.hunt_dir / "vault" / "js" / js_file
                if js_path.exists():
                    content = js_path.read_text()
                    values.extend(self._extract_values_from_content(content, js_file))
            except Exception:
                pass

        return values

    def _extract_from_endpoints(self, state: HuntState) -> list[ValueEntry]:
        """Extract values from discovered endpoints and responses."""
        values = []

        # Extract from endpoint patterns
        for endpoint in state.target.endpoints_discovered:
            # Extract IDs from URL paths
            id_match = re.search(r'/([A-Za-z0-9\-]{8,})', endpoint)
            if id_match:
                values.append(ValueEntry(
                    value=id_match.group(1),
                    status=ValueStatus.PENDING,
                    discovered_at=now_iso(),
                    source_endpoint=endpoint,
                    source_param="path",
                    priority=LinkagePriority.NORMAL,
                ))

        return values

    def _extract_values_from_content(self, content: str, source: str) -> list[ValueEntry]:
        """Extract values from content using regex patterns."""
        values = []
        seen = set()

        for value_type, patterns in VALUE_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Try to get captured group, fallback to full match
                    try:
                        value = match.group(1)
                    except IndexError:
                        value = match.group(0) if match.group(0) else None

                    if value and value not in seen and len(value) >= 4:
                        seen.add(value)
                        priority = self._determine_value_priority(value_type, value)
                        values.append(ValueEntry(
                            value=value,
                            status=ValueStatus.PENDING,
                            discovered_at=now_iso(),
                            source_endpoint=source,
                            source_param=value_type,
                            priority=priority,
                        ))

        return values

    def _determine_value_priority(self, value_type: str, value: str) -> str:
        """Determine priority level for a discovered value."""
        # CRITICAL - Authentication credentials, API keys, secrets
        if value_type in (
            'jwt', 'api_key', 'aws_key', 'google_api_key', 'github_token',
            'slack_token', 'stripe_key', 'bearer_token', 'auth_token',
            'refresh_token', 'csrf_token', 'secret', 'database_url',
        ):
            return LinkagePriority.CRITICAL

        # HIGH - User identifiers, session data
        if value_type in (
            'user_id', 'session_id', 'password', 'email', 's3_bucket',
        ):
            return LinkagePriority.HIGH

        # NORMAL - General identifiers, URLs, phone numbers
        if value_type in (
            'uuid', 'guid', 'numeric_id', 'internal_url',
            'graphql_operation', 'phone', 'config_path',
        ):
            return LinkagePriority.NORMAL

        # LOW - Optional parameters, less critical data
        if value_type in (
            'base64_secret', 'internal_ip',
        ):
            return LinkagePriority.LOW

        return LinkagePriority.LOW

    # -----------------------------------------------------------------------
    # Value registration
    # -----------------------------------------------------------------------

    def _register_values(self, values: list[ValueEntry], state: HuntState):
        """Register discovered values in the cache."""
        for value in values:
            key = f"{value.value}:{value.source_endpoint}"
            if key not in self._value_cache:
                self._value_cache[key] = value

    # -----------------------------------------------------------------------
    # Endpoint requirement building
    # -----------------------------------------------------------------------

    def _build_endpoint_requirements(self, state: HuntState):
        """Build endpoint parameter requirements from discovered endpoints."""
        for endpoint in state.target.endpoints_discovered:
            # Parse endpoint to extract parameters
            try:
                parts = endpoint.split('/')
                method = "GET" if not any(x in endpoint.upper() for x in ['POST', 'PUT', 'DELETE']) else "POST"

                # Extract path parameters
                path_params = [p.strip('{}') for p in parts if p.startswith('{') and p.endswith('}')]

                # Extract query parameters from common patterns
                query_params = self._extract_query_params(endpoint)

                requirement = EndpointParamRequirement(
                    endpoint=endpoint,
                    method=method,
                    params_required=path_params,
                    params_optional=query_params,
                    content_type="application/json",
                    auth="unknown",
                    source_files=[],
                    notes=f"Discovered during recon phase",
                )

                self._endpoint_cache[endpoint] = requirement

            except Exception:
                pass

    def _extract_query_params(self, endpoint: str) -> list[str]:
        """Extract common query parameter names from endpoint."""
        common_params = ['id', 'user_id', 'session_id', 'token', 'api_key', 'email',
                        'page', 'limit', 'offset', 'sort', 'order', 'search', 'q']
        # For now, return common params that might be relevant
        return common_params

    # -----------------------------------------------------------------------
    # Unconsumed pair generation
    # -----------------------------------------------------------------------

    def _generate_unconsumed_pairs(self, state: HuntState):
        """Generate unconsumed value-endpoint pairs."""
        self._pair_cache.clear()

        for endpoint, requirement in self._endpoint_cache.items():
            for value_key, value_entry in self._value_cache.items():
                # Check if value matches endpoint parameters
                if self._should_link(value_entry, requirement):
                    pair = UnconsumedPair(
                        param_name=value_entry.source_param or "value",
                        value=value_entry.value,
                        endpoint=endpoint,
                        method=requirement.method,
                        priority=value_entry.priority,
                        reason=f"Value '{value_entry.value[:20]}...' matches endpoint parameters",
                        value_entry=value_entry,
                    )
                    self._pair_cache.append(pair)

                    # Add to value entry's unconsumed endpoints
                    if endpoint not in value_entry.unconsumed_endpoints:
                        value_entry.unconsumed_endpoints.append(endpoint)

    def _should_link(self, value: ValueEntry, endpoint: EndpointParamRequirement) -> bool:
        """Determine if a value should be linked to an endpoint."""
        # Link if:
        # 1. Value type matches endpoint params
        # 2. Endpoint requires authentication (critical values)
        # 3. Value is from same domain/file

        value_type = value.source_param.lower()

        # Critical values always link to authenticated endpoints
        if value.priority == LinkagePriority.CRITICAL:
            return True

        # Check if value type matches required params
        if any(value_type in p.lower() for p in endpoint.params_required):
            return True

        # Check if value type matches optional params
        if any(value_type in p.lower() for p in endpoint.params_optional):
            return True

        return False

    # -----------------------------------------------------------------------
    # Summary generation
    # -----------------------------------------------------------------------

    def _generate_summary(self, result: LinkageCheckResult) -> str:
        """Generate human-readable summary."""
        parts = []
        parts.append(f"Total values discovered: {result.total_values}")
        parts.append(f"Total pairs generated: {result.total_pairs}")
        parts.append(f"Unconsumed pairs: {result.unconsumed}")
        parts.append(f"Critical unconsumed: {result.critical_unconsumed}")
        return ". ".join(parts)

    def _generate_details(self, result: LinkageCheckResult) -> str:
        """Generate detailed breakdown."""
        details = []
        details.append("## Value Linkage Details")
        details.append(f"**Status:** {'PASS' if result.passed else 'INCOMPLETE'}")
        details.append(f"**Critical Unconsumed:** {result.critical_unconsumed}")
        details.append(f"**Total Pairs:** {result.total_pairs}")
        details.append(f"**Consumed:** {result.consumed_pairs}")
        details.append(f"**Block Transition:** {result.block_transition}")
        return "\n".join(details)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def check_linkage_completeness(state: HuntState) -> JSAnalysisCheckResult:
    """
    Check if JS analysis and value linkage is complete for phase transition.

    This is called by agents to determine if they can proceed to the next phase.

    Args:
        state: Current hunt state

    Returns:
        JSAnalysisCheckResult with pass/fail status
    """
    result = JSAnalysisCheckResult()

    # Check JS analysis completeness
    js_meta = state.js_analysis_meta if hasattr(state, 'js_analysis_meta') else None

    if js_meta:
        result.meta = js_meta
        result.has_endpoints = js_meta.total_endpoints_extracted > 0
        result.all_files_downloaded = js_meta.js_files_collected == js_meta.total_js_files
        result.all_files_read = js_meta.js_files_analyzed == js_meta.js_files_collected
        result.endpoint_params_created = len(state.target.endpoints_discovered) > 0
        result.completeness_valid = js_meta.analysis_completeness >= 0.8
    else:
        # Fallback check if meta not available
        result.has_endpoints = len(state.target.endpoints_discovered) > 0
        result.all_files_downloaded = len(state.target.js_files) > 0
        result.all_files_read = True  # Assume read if files exist
        result.endpoint_params_created = True
        result.completeness_valid = True

    # Check value linkage
    engine = ValueLinkageEngine()
    linkage_result = engine.process_state(state)

    result.passed = (
        result.has_endpoints and
        result.endpoint_params_created and
        linkage_result.critical_unconsumed == 0
    )

    # Generate summary
    if result.passed:
        result.summary = "JS analysis and value linkage complete"
    else:
        failures = []
        if not result.has_endpoints:
            failures.append("No endpoints extracted")
        if linkage_result.critical_unconsumed > 0:
            failures.append(f"{linkage_result.critical_unconsumed} critical unconsumed pairs")
        result.summary = f"Incomplete: {', '.join(failures)}"
        result.failures = failures

    return result


def get_next_unconsumed_pair(state: HuntState, agent_id: str = "") -> UnconsumedPair | None:
    """
    Get the next unconsumed pair for an agent to process.

    Args:
        state: Current hunt state
        agent_id: Agent requesting the pair

    Returns:
        Next UnconsumedPair or None if no pairs available
    """
    engine = ValueLinkageEngine()
    engine.process_state(state)

    pairs = engine.get_unconsumed_pairs(state, limit=1)
    if pairs:
        return pairs[0]
    return None


def mark_pair_consumed(state: HuntState, pair: UnconsumedPair, agent_id: str = ""):
    """
    Mark a value-endpoint pair as consumed by an agent.

    Args:
        state: Current hunt state
        pair: The pair that was consumed
        agent_id: Agent that consumed it
    """
    if pair.value_entry:
        pair.value_entry.status = ValueStatus.CONSUMED
        if pair.endpoint not in pair.value_entry.consumed_endpoints:
            pair.value_entry.consumed_endpoints.append(pair.endpoint)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

__all__ = [
    'ValueLinkageEngine',
    'LinkagePriority',
    'check_linkage_completeness',
    'get_next_unconsumed_pair',
    'mark_pair_consumed',
]
