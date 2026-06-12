"""
core/executors/ — Security Tool Wrappers

Provides standardized wrappers for common security tools used in
bug bounty and penetration testing.

All tools return standardized SkillResult objects for agent consumption.
"""

from .base import ToolBase, ToolResult
from .httpx_executor import HttpxExecutor
from .nuclei_executor import NucleiExecutor
from .ffuf_executor import FfufExecutor
from .tool_manager import ToolManager

__all__ = [
    'ToolBase',
    'ToolResult',
    'HttpxExecutor',
    'NucleiExecutor',
    'FfufExecutor',
    'ToolManager',
]
