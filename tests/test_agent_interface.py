"""
tests/test_agent_interface.py — Tests for agent interface modules

Tests the new agent-friendly interfaces for Hermes integration.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.types import (
    HuntState, Target, HuntStatus, PhaseName, Finding, FindingStatus, Severity,
    UnconsumedPair, ValueEntry, ValueStatus,
)
from core.agent_interface import (
    AgentExecutionStatus, SkillResult, agent_skill, AgentHooks, ToolExecutor,
)
from core.linkage import (
    ValueLinkageEngine, LinkagePriority,
    check_linkage_completeness, get_next_unconsumed_pair, mark_pair_consumed,
)


def test_skill_decorator():
    """Test the @agent_skill decorator."""
    print("Testing @agent_skill decorator...")

    # Create a test state
    state = HuntState(
        hunt_id="test-001",
        target=Target(url="https://example.com"),
    )

    @agent_skill(name="test_scan", category="test")
    def test_skill(state: HuntState) -> SkillResult:
        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            data={"scanned": True},
        )

    result = test_skill(state)

    assert result.status == AgentExecutionStatus.SUCCESS
    assert result.data["scanned"] == True
    print("  ✓ @agent_skill works")


def test_agent_hooks():
    """Test the AgentHooks system."""
    print("Testing AgentHooks...")

    hooks = AgentHooks()

    # Register a pre-phase hook
    hooks.register('pre_phase', lambda phase, state: phase != "blocked_phase")

    # Register a decision point hook
    hooks.register('decision_point', lambda state: True)

    assert hooks.pre_phase("recon", None) == True
    assert hooks.pre_phase("blocked_phase", None) == False
    assert hooks.should_proceed(None) == True

    print("  ✓ AgentHooks work")


def test_hunt_state_queries():
    """Test HuntState agent-friendly query methods."""
    print("Testing HuntState query methods...")

    state = HuntState(
        hunt_id="test-002",
        target=Target(url="https://example.com",
                     endpoints_discovered=["/api/users", "/api/auth"]),
        status=HuntStatus.ACTIVE,
        current_phase=PhaseName.RECON,
        completed_phases=[PhaseName.RECON],  # RECON is completed
    )

    # Test should_transition - DEPENDENCY_SCAN depends on RECON
    assert state.should_transition(PhaseName.DEPENDENCY_SCAN) == True

    # Test get_pending_fuzzing_targets
    state.target.endpoints_discovered = ["/api/users", "/api/auth/login"]
    targets = state.get_pending_fuzzing_targets()
    assert isinstance(targets, list)

    # Test get_relevant_context
    context = state.get_relevant_context("fuzz api")
    assert "endpoints" in context
    assert context["current_phase"] == "recon"

    # Test get_summary
    summary = state.get_summary()
    assert "test-002" in summary
    assert "example.com" in summary

    print("  ✓ HuntState query methods work")


def test_value_linkage():
    """Test ValueLinkageEngine."""
    print("Testing ValueLinkageEngine...")

    state = HuntState(
        hunt_id="test-003",
        target=Target(
            url="https://example.com",
            endpoints_discovered=[
                "/api/users/{user_id}",
                "/api/sessions",
                "/api/auth/token",
            ],
            js_files=["app.js", "auth.js"],
        ),
        hunt_dir="./test-data",
    )

    # Simulate some discovered values
    state.linkage_pairs = [
        UnconsumedPair(
            param_name="user_id",
            value="12345",
            endpoint="/api/users/{user_id}",
            method="GET",
            priority="HIGH",
            value_entry=ValueEntry(
                value="12345",
                status="pending",
                priority="HIGH",
            ),
        ),
        UnconsumedPair(
            param_name="token",
            value="abc123def456",
            endpoint="/api/auth/token",
            method="POST",
            priority="CRITICAL",
            value_entry=ValueEntry(
                value="abc123def456",
                status="pending",
                priority="CRITICAL",
            ),
        ),
    ]

    # Test critical pair retrieval
    critical = state.get_unconsumed_critical_pairs()
    assert len(critical) == 1
    assert critical[0].priority == "CRITICAL"

    # Test linkage engine
    engine = ValueLinkageEngine()
    result = engine.process_state(state)

    assert result.total_pairs >= 0
    assert isinstance(result.summary, str)

    print("  ✓ ValueLinkageEngine works")


def test_findings_management():
    """Test finding management methods."""
    print("Testing findings management...")

    state = HuntState(
        hunt_id="test-004",
        target=Target(url="https://example.com"),
    )

    # Add findings
    finding1 = Finding(
        id="F001",
        vuln_class="sql_injection",
        target_url="https://example.com/api/users",
        severity=Severity.HIGH,
        status=FindingStatus.DETECTED,
    )
    finding2 = Finding(
        id="F002",
        vuln_class="xss",
        target_url="https://example.com/search",
        severity=Severity.MEDIUM,
        status=FindingStatus.TRIAGE_APPROVED,
    )

    state.add_finding(finding1)
    state.add_finding(finding2)

    # Test get_pending_findings
    pending = state.get_pending_findings()
    assert len(pending) == 1
    assert pending[0].id == "F001"

    # Test get_approved_findings
    approved = state.get_approved_findings()
    assert len(approved) == 1
    assert approved[0].id == "F002"

    # Test get_findings_by_severity
    high = state.get_findings_by_severity(Severity.HIGH)
    assert len(high) == 1
    assert high[0].vuln_class == "sql_injection"

    print("  ✓ Findings management works")


def test_skill_result():
    """Test SkillResult serialization."""
    print("Testing SkillResult...")

    from shared.types import Finding

    result = SkillResult(
        status=AgentExecutionStatus.SUCCESS,
        data={"key": "value"},
        findings=[
            Finding(
                id="F001",
                vuln_class="test",
                target_url="https://example.com",
            )
        ],
    )

    serialized = result.to_dict()
    assert serialized["status"] == "success"
    assert serialized["findings_count"] == 1
    assert serialized["data"]["key"] == "value"

    print("  ✓ SkillResult serialization works")


def run_all_tests():
    """Run all agent interface tests."""
    print("\n" + "="*60)
    print("AGENT INTERFACE TESTS")
    print("="*60 + "\n")

    tests = [
        test_skill_decorator,
        test_agent_hooks,
        test_hunt_state_queries,
        test_value_linkage,
        test_findings_management,
        test_skill_result,
    ]

    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"  ✗ {test.__name__} failed: {e}")
            return False
        except Exception as e:
            print(f"  ✗ {test.__name__} error: {e}")
            return False

    print("\n" + "="*60)
    print("ALL TESTS PASSED ✓")
    print("="*60 + "\n")
    return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
