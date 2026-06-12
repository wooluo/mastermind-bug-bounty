"""
core/ai_modules/ — AI-Driven Analysis Modules

真正需要 AI 参与的核心模块：

- JSAnalyzer: JavaScript 智能分析
- EndpointPrioritizer: 端点优先级排序
- VulnerabilityMatcher: CVE 匹配
- FuzzStrategyGenerator: Fuzz 策略生成
- PayloadGenerator: 智能 Payload 生成
- CryptoAttacker: 加密攻击
- BypassEngine: 绕过策略生成
- AttackChainComposer: 攻击链组合
- FindingValidator: 发现验证
"""

from .js_analyzer import JSAnalyzer, JSEndpoint, JSSecret, APICall
from .other_modules import (
    EndpointPrioritizer,
    VulnerabilityMatcher,
    FuzzStrategyGenerator, FuzzStrategy,
    PayloadGenerator,
    CryptoAttacker,
    BypassEngine,
    AttackChainComposer, AttackChain,
    FindingValidator,
)

__all__ = [
    # JS Analysis
    'JSAnalyzer',
    'JSEndpoint',
    'JSSecret',
    'APICall',

    # Other AI Modules
    'EndpointPrioritizer',
    'VulnerabilityMatcher',
    'FuzzStrategyGenerator',
    'FuzzStrategy',
    'PayloadGenerator',
    'CryptoAttacker',
    'BypassEngine',
    'AttackChainComposer',
    'AttackChain',
    'FindingValidator',
]
