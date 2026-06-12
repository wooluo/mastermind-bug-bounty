"""
reporting/ — Report Generation Module

Provides multi-format report generation for bug bounty findings:
- Markdown reports
- HTML reports
- JSON reports
- PDF reports (optional)
"""

from .generator import ReportGenerator
from .templates import TemplateEngine
from .cvss import CVSSCalculator

__all__ = [
    'ReportGenerator',
    'TemplateEngine',
    'CVSSCalculator',
]
