"""
core/ — Core Agent Execution Engine

Provides the unified interface and execution engine for Hermes agents.
"""

from .agent_interface import (
    AgentExecutionStatus,
    SkillResult,
    agent_skill,
    AgentHooks,
    ToolExecutor,
    AgentContext,
    validate_agent_input,
    retry_on_failure,
)

from .linkage import (
    ValueLinkageEngine,
    LinkagePriority,
    check_linkage_completeness,
    get_next_unconsumed_pair,
    mark_pair_consumed,
)

from .executors import (
    ToolBase,
    ToolResult,
    HttpxExecutor,
    NucleiExecutor,
    FfufExecutor,
    ToolManager,
)

from .batch import (
    BatchProcessor,
    BatchConfig,
    BatchResult,
    BatchSummary,
)

__all__ = [
    # Agent interface
    'AgentExecutionStatus',
    'SkillResult',
    'agent_skill',
    'AgentHooks',
    'ToolExecutor',
    'AgentContext',
    'validate_agent_input',
    'retry_on_failure',

    # Value linkage
    'ValueLinkageEngine',
    'LinkagePriority',
    'check_linkage_completeness',
    'get_next_unconsumed_pair',
    'mark_pair_consumed',

    # Tool executors
    'ToolBase',
    'ToolResult',
    'HttpxExecutor',
    'NucleiExecutor',
    'FfufExecutor',
    'ToolManager',

    # Batch processing
    'BatchProcessor',
    'BatchConfig',
    'BatchResult',
    'BatchSummary',
]
