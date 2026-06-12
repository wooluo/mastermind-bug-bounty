"""
core/linkage/ — Data Linkage Module

Provides automatic value-to-endpoint correlation for intelligent agent testing.
"""

from .value_linkage import (
    ValueLinkageEngine,
    LinkagePriority,
    check_linkage_completeness,
    get_next_unconsumed_pair,
    mark_pair_consumed,
)

__all__ = [
    'ValueLinkageEngine',
    'LinkagePriority',
    'check_linkage_completeness',
    'get_next_unconsumed_pair',
    'mark_pair_consumed',
]
