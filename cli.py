#!/usr/bin/env python3
"""
cli.py — Mastermind Bug Bounty unified CLI (Security Hardened)

One-command full-auto bug bounty pipeline with comprehensive security validation.

Security Enhancements v1.0:
    - Input validation to prevent SSRF and path traversal
    - Secure file handling with HMAC verification
    - Rate limiting with persistent storage
    - Audit logging for all operations
    - Error message sanitization

Zero external dependencies. Pure Python stdlib.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
import time

# Ensure the package root is on sys.path
_PKG_ROOT = Path(__file__).resolve().parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Import security module
from shared.security import (
    validate_target_url,
    validate_hunt_dir,
    ValidationError,
    secure_headers,
    redact_sensitive,
    PersistentRateLimiter,
)


class SecurityAuditor:
    """Audit logger for security-relevant operations."""

    def __init__(self, log_file: Path = None):
        self.log_file = log_file or Path('./audit.log')

    def log(self, event: str, details: dict, success: bool = True):
        """Log security event."""
        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'event': event,
            'details': redact_sensitive(str(details)),
            'success': success,
            'pid': os.getpid() if 'os' in dir() else None,
        }
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            pass  # Fail silently on audit logging errors


def cmd_run(args: argparse.Namespace) -> int:
    """Execute the full bug bounty pipeline against a target."""
    from workflow.orchestrator import Orchestrator

    try:
        # Validate target URL (SSRF protection)
        print(f"[Security] Validating target URL...")
        validated_url = validate_target_url(args.target)
        print(f"[Security] ✓ Target validated: {redact_sensitive(validated_url)}")

        # Validate hunt directory (path traversal protection)
        print(f"[Security] Validating hunt directory...")
        validated_dir = validate_hunt_dir(args.hunt_dir)
        print(f"[Security] ✓ Directory validated: {validated_dir}")

    except ValidationError as e:
        print(f"[Security] ✗ Validation failed: {e.message}", file=sys.stderr)
        return 1

    # Initialize security auditor
    auditor = SecurityAuditor(validated_dir / 'audit.log')

    # Initialize rate limiter
    rate_limiter = PersistentRateLimiter(
        max_requests=10,
        window_seconds=60,
        store_path=validated_dir / '.rate_limit'
    )

    # Check rate limit
    allowed, info = rate_limiter.check_rate_limit(validated_url)
    if not allowed:
        print(f"[Security] ✗ Rate limit exceeded: {info['reason']}")
        print(f"[Security] Retry after {info.get('retry_after', 60)} seconds")
        auditor.log('rate_limit_exceeded', info, False)
        return 1

    print(f"\n{'='*60}")
    print(f"MASTERMIND BUG BOUNTY (SECURITY HARDENED)")
    print(f"Target: {redact_sensitive(validated_url)}")
    print(f"Hunt Dir: {validated_dir}")
    print(f"Depth: {args.depth}")
    print(f"{'='*60}\n")

    try:
        from workflow.orchestrator import Orchestrator
        orch = Orchestrator(hunt_dir=validated_dir)
        state = orch.run(validated_url, scope=args.scope)

        # Summary
        print(f"\n{'='*60}")
        print(f"HUNT SUMMARY")
        print(f"{'='*60}")
        print(f"Hunt ID: {state.hunt_id}")
        print(f"Target: {redact_sensitive(state.target.url)}")
        print(f"Status: {state.status.value}")
        print(f"Phases completed: {[p.value for p in state.completed_phases]}")
        print(f"Total findings: {len(state.findings)}")

        approved = [f for f in state.findings
                    if f.status.value == "triage_approved"]
        if approved:
            print(f"\nApproved Findings ({len(approved)}):")
            for f in approved:
                print(f"  [{f.severity.upper()}] {f.vuln_class} @ {redact_sensitive(f.target_url)}")

        pending = [f for f in state.findings
                   if f.status.value in ("detected", "triage_pending")]
        if pending:
            print(f"\nPending Findings ({len(pending)}):")
            for f in pending:
                print(f"  [{f.severity.upper()}] {f.vuln_class} @ {redact_sensitive(f.target_url)}")

        print(f"\nWorklog: {validated_dir}/worklog.jsonl")
        print(f"Handoff: {validated_dir}/vault/handoff_latest.md")

        auditor.log('hunt_completed', {
            'hunt_id': state.hunt_id,
            'findings_count': len(state.findings),
        }, True)

        return 0

    except Exception as e:
        print(f"[Error] Hunt failed: {str(e)}", file=sys.stderr)
        auditor.log('hunt_failed', {'error': str(e)[:200]}, False)
        return 1


def cmd_resume(args: argparse.Namespace) -> int:
    """Resume an existing hunt from its hunt directory."""
    from workflow.orchestrator import Orchestrator
    from workflow.state import load_hunt

    try:
        # Validate hunt directory
        validated_dir = validate_hunt_dir(args.hunt_dir)

        state = load_hunt(validated_dir)
        if state is None:
            print(f"[ERROR] No hunt found in {validated_dir}")
            print("Use 'python cli.py run --target <URL>' to start a new hunt.")
            return 1

        print(f"\nResuming hunt: {state.hunt_id}")
        print(f"Target: {redact_sensitive(state.target.url)}")
        print(f"Current phase: {state.current_phase.value}")
        print(f"Completed phases: {[p.value for p in state.completed_phases]}")

        orch = Orchestrator(hunt_dir=validated_dir)
        state = orch.run(state.target.url, scope=state.target.scope)
        return 0

    except ValidationError as e:
        print(f"[Security] ✗ Validation failed: {e.message}", file=sys.stderr)
        return 1


def cmd_status(args: argparse.Namespace) -> int:
    """Show the status of an existing hunt."""
    from workflow.state import load_hunt, load_recent_worklog

    try:
        validated_dir = validate_hunt_dir(args.hunt_dir)
        state = load_hunt(validated_dir)

        if state is None:
            print(f"[ERROR] No hunt found in {validated_dir}")
            return 1

        print(f"\n{'='*60}")
        print(f"HUNT STATUS: {state.hunt_id}")
        print(f"{'='*60}")
        print(f"Target:      {redact_sensitive(state.target.url)}")
        print(f"Scope:       {', '.join(state.target.scope)}")
        print(f"Status:      {state.status.value}")
        print(f"Phase:       {state.current_phase.value}")
        print(f"Completed:   {[p.value for p in state.completed_phases] or 'None'}")
        print(f"Findings:    {len(state.findings)} total")
        print(f"  Approved:  {sum(1 for f in state.findings if f.status.value == 'triage_approved')}")
        print(f"  Pending:   {sum(1 for f in state.findings if f.status.value in ('detected', 'triage_pending'))}")
        print(f"  Rejected:  {sum(1 for f in state.findings if f.status.value == 'triage_rejected')}")
        print(f"Agents:      {len(state.agents)}")
        for a in state.agents.values():
            print(f"  - {a.agent_id}: {a.status} ({a.agent_type})")
        print(f"Endpoints:   {len(state.target.endpoints_discovered)}")
        print(f"JS Files:    {len(state.target.js_files)}")
        print(f"Tech Stack:  {state.target.tech_stack or 'Not fingerprinted'}")
        print(f"WAF/CDN:     {state.target.waf_cdn or 'Unknown'}")
        print(f"Created:     {state.created_at[:19] if state.created_at else 'N/A'}")
        print(f"Updated:     {state.updated_at[:19] if state.updated_at else 'N/A'}")

        recent = load_recent_worklog(validated_dir, minutes=30)
        if recent:
            print(f"\nRecent Activity ({len(recent)} entries, last 30 min):")
            for e in recent[:5]:
                ts = e.get("timestamp", "")[:19]
                et = e.get("entry_type", "?")
                agent = e.get("agent_id", "?")
                print(f"  {ts} [{et}] {agent}")

        return 0

    except ValidationError as e:
        print(f"[Security] ✗ Validation failed: {e.message}", file=sys.stderr)
        return 1


def cmd_list_phases(_args: argparse.Namespace) -> int:
    """List all pipeline phases."""
    from workflow.pipeline import PIPELINE

    print(f"\n{'='*60}")
    print("PIPELINE PHASES")
    print(f"{'='*60}")
    for i, phase in enumerate(PIPELINE):
        marker = " (optional)" if phase.optional else ""
        print(f"\n{i+1}. {str(phase.name).upper()}{marker}")
        print(f"   Agent: {phase.agent}")
        print(f"   Skills: {phase.skills or 'none'}")
        print(f"   {phase.description}")
        if phase.depends_on:
            print(f"   Depends on: {[str(d) for d in phase.depends_on]}")
    return 0


def cmd_security_check(_args: argparse.Namespace) -> int:
    """Run security diagnostics."""
    print(f"\n{'='*60}")
    print("SECURITY DIAGNOSTICS")
    print(f"{'='*60}\n")

    checks = []

    # Check 1: HMAC key
    try:
        from shared.security import get_secure_hmac_key
        key = get_secure_hmac_key()
        checks.append(('HMAC Key', 'PASS', f'Key loaded ({len(key)} bytes)'))
    except Exception as e:
        checks.append(('HMAC Key', 'FAIL', str(e)[:100]))

    # Check 2: Directory permissions
    try:
        test_dir = Path('./hunt-data')
        if test_dir.exists():
            mode = test_dir.stat().st_mode & 0o777
            if mode <= 0o700:
                checks.append(('Directory Permissions', 'PASS', f'{oct(mode)}'))
            else:
                checks.append(('Directory Permissions', 'WARN', f'Too permissive: {oct(mode)}'))
        else:
            checks.append(('Directory Permissions', 'SKIP', 'No hunt directory'))
    except Exception as e:
        checks.append(('Directory Permissions', 'FAIL', str(e)[:100]))

    # Check 3: Python version
    checks.append(('Python Version', 'INFO' if sys.version_info >= (3, 9) else 'WARN',
                   f'{sys.version.split()[0]}'))

    # Print results
    for name, status, message in checks:
        icon = {'PASS': '✓', 'FAIL': '✗', 'WARN': '⚠', 'INFO': 'ℹ', 'SKIP': '○'}[status]
        color = {'PASS': 'green', 'FAIL': 'red', 'WARN': 'yellow', 'INFO': 'blue', 'SKIP': 'gray'}[status]
        print(f"  {icon} {name}: {message}")

    print(f"\n{'='*60}")
    return 0 if all(s[1] in ('PASS', 'INFO', 'SKIP') for s in checks) else 1


# ---------------------------------------------------------------------------
# CLI setup
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mastermind",
        description="Mastermind Bug Bounty — Autonomous Offensive Security Orchestration (Security Hardened)",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # run
    p_run = sub.add_parser("run", help="Start a new hunt against a target")
    p_run.add_argument("--target", "-t", required=True,
                       help="Target URL to test (http/https only)")
    p_run.add_argument("--scope", "-s", nargs="*",
                       help="Scope URLs/domains (default: derived from target)")
    p_run.add_argument("--hunt-dir", "-d", default="./hunt-data",
                       help="Hunt data directory (default: ./hunt-data)")
    p_run.add_argument("--depth", choices=["standard", "aggressive", "stealth"],
                       default="standard", help="Hunt depth (default: standard)")

    # resume
    p_resume = sub.add_parser("resume", help="Resume an existing hunt")
    p_resume.add_argument("--hunt-dir", "-d", default="./hunt-data",
                          help="Hunt data directory (default: ./hunt-data)")

    # status
    p_status = sub.add_parser("status", help="Show hunt status")
    p_status.add_argument("--hunt-dir", "-d", default="./hunt-data",
                        help="Hunt data directory (default: ./hunt-data)")

    # phases
    sub.add_parser("phases", help="List all pipeline phases")

    # security-check
    sub.add_parser("security-check", help="Run security diagnostics")

    return parser


def main() -> int:
    import os
    import json

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "run":
        return cmd_run(args)
    elif args.command == "resume":
        return cmd_resume(args)
    elif args.command == "status":
        return cmd_status(args)
    elif args.command == "phases":
        return cmd_list_phases(args)
    elif args.command == "security-check":
        return cmd_security_check(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
