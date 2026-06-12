"""
core/batch.py — Batch Processing Module

Provides functionality for processing multiple targets efficiently:
- Target file parsing
- CIDR expansion
- Concurrent execution
- Progress tracking
"""

from __future__ import annotations

import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import threading

from shared.types import HuntState, Target
from shared.utils import hunt_id, now_iso
from shared.security import validate_target_url


@dataclass
class BatchConfig:
    """Configuration for batch processing."""
    targets: list[str] = field(default_factory=list)
    target_file: Path | None = None
    cidr_ranges: list[str] = field(default_factory=list)
    exclude_ranges: list[str] = field(default_factory=list)
    parallel_jobs: int = 3
    base_hunt_dir: str = "./hunt-data"
    depth: str = "standard"
    timeout: int = 3600


@dataclass
class BatchResult:
    """Result from a single target in batch."""
    target: str
    hunt_id: str
    status: str = "pending"
    findings_count: int = 0
    error: str = ""
    duration: float = 0.0
    started_at: str = ""
    completed_at: str = ""


@dataclass
class BatchSummary:
    """Summary of batch processing results."""
    total_targets: int = 0
    completed: int = 0
    failed: int = 0
    total_findings: int = 0
    started_at: str = ""
    completed_at: str = ""
    results: list[BatchResult] = field(default_factory=list)


class BatchProcessor:
    """
    Process multiple targets in parallel.

    Usage:
        processor = BatchProcessor(config)
        summary = processor.run()
    """

    def __init__(self, config: BatchConfig):
        """Initialize batch processor."""
        self.config = config
        self._lock = threading.Lock()
        self._summary = BatchSummary()
        self._progress_callback = None

    def set_progress_callback(self, callback):
        """Set callback for progress updates."""
        self._progress_callback = callback

    def run(self) -> BatchSummary:
        """
        Run batch processing.

        Returns:
            BatchSummary with all results
        """
        self._summary.started_at = now_iso()

        # Collect all targets
        targets = self._collect_targets()

        if not targets:
            self._summary.completed_at = now_iso()
            return self._summary

        self._summary.total_targets = len(targets)

        # Process targets in parallel
        with ThreadPoolExecutor(max_workers=self.config.parallel_jobs) as executor:
            futures = {
                executor.submit(self._process_target, target): target
                for target in targets
            }

            for future in as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    with self._lock:
                        self._summary.results.append(result)
                        self._summary.total_findings += result.findings_count
                        if result.status == "completed":
                            self._summary.completed += 1
                        else:
                            self._summary.failed += 1

                    # Report progress
                    if self._progress_callback:
                        progress = len(self._summary.results) / len(targets) * 100
                        self._progress_callback(progress, result)

                except Exception as e:
                    with self._lock:
                        self._summary.failed += 1
                        result = BatchResult(
                            target=target,
                            hunt_id="",
                            status="failed",
                            error=str(e),
                        )
                        self._summary.results.append(result)

        self._summary.completed_at = now_iso()
        return self._summary

    def _collect_targets(self) -> list[str]:
        """Collect all targets from various sources."""
        targets = []

        # From explicit targets
        targets.extend(self.config.targets)

        # From target file
        if self.config.target_file and self.config.target_file.exists():
            targets.extend(self._parse_target_file(self.config.target_file))

        # From CIDR ranges
        for cidr in self.config.cidr_ranges:
            targets.extend(self._expand_cidr(cidr))

        # Remove excluded targets
        if self.config.exclude_ranges:
            targets = self._filter_excluded(targets)

        # Validate and deduplicate
        validated = []
        seen = set()
        for target in targets:
            if target not in seen:
                try:
                    validated_url = validate_target_url(target)
                    validated.append(validated_url)
                    seen.add(target)
                except Exception:
                    pass  # Skip invalid targets

        return validated

    def _parse_target_file(self, file_path: Path) -> list[str]:
        """Parse targets from file."""
        targets = []

        # Try different formats
        content = file_path.read_text()

        # Try JSON
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "targets" in data:
                return data["targets"]
        except json.JSONDecodeError:
            pass

        # Try plain text (one target per line)
        for line in content.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)

        return targets

    def _expand_cidr(self, cidr: str) -> list[str]:
        """Expand CIDR range to individual hosts."""
        targets = []

        try:
            network = ipaddress.ip_network(cidr, strict=False)

            # Limit to /24 or smaller for safety
            if network.prefixlen <= 24:
                for ip in network.hosts():
                    targets.append(f"http://{ip}")

        except ValueError:
            pass  # Invalid CIDR, skip

        return targets

    def _filter_excluded(self, targets: list[str]) -> list[str]:
        """Filter out excluded targets."""
        filtered = []

        for target in targets:
            excluded = False
            for exclude_range in self.config.exclude_ranges:
                if exclude_range in target:
                    excluded = True
                    break
            if not excluded:
                filtered.append(target)

        return filtered

    def _process_target(self, target: str) -> BatchResult:
        """Process a single target."""
        result = BatchResult(target=target, hunt_id=hunt_id())
        result.started_at = now_iso()

        try:
            # Create hunt directory for this target
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.netloc or parsed.path
            hunt_dir = Path(self.config.base_hunt_dir) / host.replace(".", "_")

            # Run the hunt
            from workflow.orchestrator import Orchestrator
            orch = Orchestrator(hunt_dir=str(hunt_dir))
            state = orch.run(target)

            result.status = "completed"
            result.findings_count = len(state.findings)
            result.completed_at = now_iso()
            result.duration = (
                datetime.fromisoformat(result.completed_at) -
                datetime.fromisoformat(result.started_at)
            ).total_seconds()

        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            result.completed_at = now_iso()

        return result

    def save_summary(self, output_file: Path):
        """Save batch summary to file."""
        summary_data = {
            "started_at": self._summary.started_at,
            "completed_at": self._summary.completed_at,
            "total_targets": self._summary.total_targets,
            "completed": self._summary.completed,
            "failed": self._summary.failed,
            "total_findings": self._summary.total_findings,
            "results": [
                {
                    "target": r.target,
                    "hunt_id": r.hunt_id,
                    "status": r.status,
                    "findings_count": r.findings_count,
                    "error": r.error,
                    "duration": r.duration,
                }
                for r in self._summary.results
            ],
        }

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(summary_data, indent=2))


class ProgressTracker:
    """Track and display batch processing progress."""

    def __init__(self, total_targets: int):
        self.total = total_targets
        self.completed = 0
        self.failed = 0
        self._lock = threading.Lock()

    def update(self, progress: float, result: BatchResult):
        """Update progress."""
        with self._lock:
            if result.status == "completed":
                self.completed += 1
            else:
                self.failed += 1

            self._display(progress, result)

    def _display(self, progress: float, result: BatchResult):
        """Display progress update."""
        status_symbol = "✓" if result.status == "completed" else "✗"
        print(
            f"[{progress:.1f}%] {status_symbol} {result.target} "
            f"({result.findings_count} findings)"
        )


def create_batch_from_cli(
    targets: list[str] | None = None,
    target_file: Path | None = None,
    cidr: str | None = None,
    exclude: list[str] | None = None,
    parallel: int = 3,
    hunt_dir: str = "./hunt-data",
    depth: str = "standard",
) -> BatchProcessor:
    """
    Create a batch processor from CLI arguments.

    Args:
        targets: List of target URLs
        target_file: Path to file containing targets
        cidr: CIDR range to expand
        exclude: List of patterns to exclude
        parallel: Number of parallel jobs
        hunt_dir: Base hunt directory
        depth: Scan depth

    Returns:
        Configured BatchProcessor
    """
    config = BatchConfig(
        targets=targets or [],
        target_file=target_file,
        cidr_ranges=[cidr] if cidr else [],
        exclude_ranges=exclude or [],
        parallel_jobs=parallel,
        base_hunt_dir=hunt_dir,
        depth=depth,
    )

    return BatchProcessor(config)
