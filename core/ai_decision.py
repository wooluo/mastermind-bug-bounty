"""
core/ai_decision.py — Hermes Agent Decision System

将 AI 判断交给 Hermes agent 来完成，而不是硬编码规则。

设计：
1. AIDecisionPoint - 定义需要 AI 决策的点
2. AIDecisionRequest - 结构化的决策请求
3. AgentDecisionEngine - 管理决策流程
4. 规则引擎作为 fallback
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, List, Dict
from enum import Enum

from shared.types import HuntState, Finding, Severity


class DecisionType(str, Enum):
    """决策类型。"""
    PRIORITY_ASSESSMENT = "priority_assessment"      # 评估优先级
    VULNERABILITY_VALIDATION = "vulnerability_validation"  # 验证漏洞
    BYPASS_STRATEGY = "bypass_strategy"             # 生成绕过策略
    ATTACK_CHAIN_COMPOSITION = "attack_chain_composition"  # 组合攻击链
    TECHNIQUE_SELECTION = "technique_selection"     # 选择测试技巧
    RESPONSE_INTERPRETATION = "response_interpretation"  # 解释响应结果


@dataclass
class AIDecisionRequest:
    """AI 决策请求。"""
    decision_type: DecisionType
    context: Dict[str, Any]
    options: List[Any] = None
    metadata: Dict[str, Any] = None

    def to_prompt(self) -> str:
        """转换为给 Hermes agent 的提示。"""
        prompts = {
            DecisionType.PRIORITY_ASSESSMENT: self._priority_prompt,
            DecisionType.VULNERABILITY_VALIDATION: self._validation_prompt,
            DecisionType.BYPASS_STRATEGY: self._bypass_prompt,
            DecisionType.ATTACK_CHAIN_COMPOSITION: self._chain_prompt,
            DecisionType.TECHNIQUE_SELECTION: self._technique_prompt,
            DecisionType.RESPONSE_INTERPRETATION: self._response_prompt,
        }
        return prompts.get(self.decision_type, str(self.context))

    def _priority_prompt(self) -> str:
        """优先级评估提示。"""
        endpoint = self.context.get('endpoint', {})
        return f"""作为安全专家，评估以下端点的攻击价值：

端点: {endpoint.get('url', 'N/A')}
方法: {endpoint.get('method', 'N/A')}
参数: {endpoint.get('params', [])}
认证要求: {endpoint.get('requires_auth', False)}

请返回评估结果（JSON 格式）:
{{
  "priority": "CRITICAL|HIGH|NORMAL|LOW",
  "reason": "简短理由",
  "confidence": 0.0-1.0
}}

注意：
- 管理功能 > 普通功能
- 写操作 > 读操作
- 需要认证 > 公开接口
"""

    def _validation_prompt(self) -> str:
        """漏洞验证提示。"""
        finding = self.context.get('finding', {})
        return f"""作为安全专家，验证以下发现是否是真实漏洞：

漏洞类型: {finding.get('vuln_class', 'N/A')}
目标: {finding.get('target_url', 'N/A')}
证据: {finding.get('evidence', '')[:200]}

请返回验证结果（JSON 格式）:
{{
  "is_valid": true/false,
  "confidence": 0.0-1.0,
  "false_positive_risk": 0.0-1.0,
  "recommendation": "简短建议"
}}

判断标准：
- 证据是否充分
- 是否可能是误报
- 需要什么额外验证
"""

    def _bypass_prompt(self) -> str:
        """绕过策略提示。"""
        situation = self.context.get('situation', {})
        return f"""作为绕过专家，针对以下情况生成绕过策略：

情况: {situation.get('type', '403 forbidden')}
目标: {situation.get('endpoint', 'N/A')}
当前尝试: {situation.get('current_attempts', [])[:2]}

请返回建议的绕过方法（JSON 格式）:
{{
  "strategies": [
    {{"method": "方法描述", "params": {{"key": "value"}}, "confidence": 0.0-1.0}}
  ],
  "reasoning": "策略选择的理由"
}}

常用技巧：
- HTTP 头伪装（X-Forwarded-For, User-Agent）
- 编码绕过（URL 编码、Unicode）
- 参数污染
- 方法切换
"""

    def _chain_prompt(self) -> str:
        """攻击链组合提示。"""
        findings = self.context.get('findings', [])
        finding_summaries = [
            f"- {f.get('vuln_class', 'N/A')}: {f.get('target_url', 'N/A')}"
            for f in findings[:5]
        ]

        return f"""作为攻击专家，组合以下漏洞形成攻击链：

发现的漏洞:
{chr(10).join(finding_summaries)}

请返回攻击链（JSON 格式）:
{{
  "chains": [
    [
      {{"step": 1, "finding": "vuln_class", "description": "利用方法"}},
      {{"step": 2, "finding": "vuln_class", "description": "下一步"}}
    ]
  ],
  "total_impact": "CRITICAL|HIGH|MEDIUM|LOW",
  "reasoning": "组合思路"
}}

考虑：
- 哪些漏洞可以串联
- 是否有前置条件
- 最终影响是什么
"""

    def _technique_prompt(self) -> str:
        """技巧选择提示。"""
        target = self.context.get('target', {})
        return f"""作为测试专家，选择最有效的测试技巧：

目标类型: {target.get('type', 'N/A')}
已知信息: {target.get('known_info', 'N/A')}

请返回推荐的测试技巧（JSON 格式）:
{{
  "recommended_techniques": [
    {{"name": "技巧名称", "payload": "示例", "confidence": 0.0-1.0}}
  ],
  "reasoning": "选择理由"
}}
"""

    def _response_prompt(self) -> str:
        """响应解释提示。"""
        response = self.context.get('response', {})
        return f"""作为分析专家，判断以下响应是否表示漏洞存在：

状态码: {response.get('status_code', 'N/A')}
响应头: {response.get('headers', {})}
响应体片段: {response.get('body', '')[:300]}

请返回分析结果（JSON 格式）:
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "indicators": ["发现的可疑指标"],
  "recommendation": "下一步建议"
}}

关注指标：
- 错误消息
- 异常状态码
- 时间差异
- 数据变化
"""


@dataclass
class AIDecision:
    """AI 决策结果。"""
    decision_type: DecisionType
    result: Any
    confidence: float = 0.0
    reasoning: str = ""
    made_by: str = "agent"  # agent | rule_fallback
    timestamp: str = ""


class AgentDecisionEngine:
    """
    Agent 决策引擎。

    管理 AI 决策的流程：
    1. 创建决策请求
    2. 调用 agent 钩子
    3. 如果 agent 处理，使用 agent 结果
    4. 如果 agent 未处理，使用规则 fallback
    """

    def __init__(self, state: HuntState):
        self.state = state
        self._decision_hooks: Dict[DecisionType, List[Callable]] = {}
        self._rule_engine = RuleEngine()

    def register_decision_hook(self, decision_type: DecisionType, hook: Callable):
        """注册决策钩子。"""
        if decision_type not in self._decision_hooks:
            self._decision_hooks[decision_type] = []
        self._decision_hooks[decision_type].append(hook)

    def request_decision(self, request: AIDecisionRequest) -> AIDecision:
        """
        请求决策。

        Args:
            request: 决策请求

        Returns:
            决策结果
        """
        # 尝试调用 agent 钩子
        hooks = self._decision_hooks.get(request.decision_type, [])

        for hook in hooks:
            try:
                result = hook(request)
                if result is not None:
                    return AIDecision(
                        decision_type=request.decision_type,
                        result=result,
                        made_by="agent",
                        timestamp=self._now_iso()
                    )
            except Exception as e:
                # Hook 失败，尝试下一个
                continue

        # 没有钩子或钩子都失败，使用规则引擎
        rule_result = self._rule_engine.decide(request)

        return AIDecision(
            decision_type=request.decision_type,
            result=rule_result,
            made_by="rule_fallback",
            timestamp=self._now_iso()
        )

    def _now_iso(self) -> str:
        """获取当前时间 ISO 格式。"""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class RuleEngine:
    """
    规则引擎（fallback）。

    当 agent 钩子不可用时，使用规则引擎做基础判断。
    """

    def decide(self, request: AIDecisionRequest) -> Any:
        """基于规则做决策。"""
        if request.decision_type == DecisionType.PRIORITY_ASSESSMENT:
            return self._priority_rules(request)
        elif request.decision_type == DecisionType.VULNERABILITY_VALIDATION:
            return self._validation_rules(request)
        elif request.decision_type == DecisionType.BYPASS_STRATEGY:
            return self._bypass_rules(request)
        elif request.decision_type == DecisionType.ATTACK_CHAIN_COMPOSITION:
            return self._chain_rules(request)
        else:
            return None

    def _priority_rules(self, request: AIDecisionRequest) -> Dict:
        """优先级评估规则。"""
        endpoint = request.context.get('endpoint', {})
        url = endpoint.get('url', '').lower()
        method = endpoint.get('method', 'GET')
        params = endpoint.get('params', [])
        requires_auth = endpoint.get('requires_auth', False)

        score = 0.0

        # URL 模式
        if any(p in url for p in ['admin', 'manage', 'config', 'settings']):
            score += 3
        elif any(p in url for p in ['user', 'profile', 'account']):
            score += 2
        elif any(p in url for p in ['api', 'data', 'export']):
            score += 1

        # 方法
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            score += 2

        # 认证
        if requires_auth:
            score += 2

        # 敏感参数
        sensitive_params = ['password', 'token', 'secret', 'key', 'credit']
        if any(p in str(params).lower() for p in sensitive_params):
            score += 3

        # 确定优先级
        if score >= 6:
            priority = 'CRITICAL'
        elif score >= 4:
            priority = 'HIGH'
        elif score >= 2:
            priority = 'NORMAL'
        else:
            priority = 'LOW'

        return {
            'priority': priority,
            'reason': f'规则引擎评估 (分数: {score})',
            'confidence': 0.5
        }

    def _validation_rules(self, request: AIDecisionRequest) -> Dict:
        """漏洞验证规则。"""
        finding = request.context.get('finding', {})
        vuln_class = finding.get('vuln_class', '').lower()
        evidence = (finding.get('evidence', '') or '').lower()

        is_valid = True
        confidence = 0.5
        recommendation = ''

        if 'sql' in vuln_class:
            sql_indicators = ['sql', 'mysql', 'postgresql', 'syntax error', 'union select']
            is_valid = any(indicator in evidence for indicator in sql_indicators)
            confidence = 0.7 if is_valid else 0.3
            recommendation = '需要手动验证 SQL 注入' if is_valid else '证据不足'

        elif 'xss' in vuln_class:
            is_valid = '<script>' in evidence or 'alert(' in evidence
            confidence = 0.6 if is_valid else 0.3
            recommendation = '需要验证 XSS 执行' if is_valid else '缺乏执行证据'

        elif 'cve' in vuln_class or 'known' in vuln_class:
            is_valid = True
            confidence = 0.9
            recommendation = '已知 CVE，建议修复'

        return {
            'is_valid': is_valid,
            'confidence': confidence,
            'false_positive_risk': 1.0 - confidence,
            'recommendation': recommendation
        }

    def _bypass_rules(self, request: AIDecisionRequest) -> Dict:
        """绕过策略规则。"""
        situation = request.context.get('situation', {})
        endpoint = situation.get('endpoint', '')

        strategies = [
            {
                'method': 'X-Forwarded-For 绕过',
                'params': {'headers': {'X-Forwarded-For': '127.0.0.1'}},
                'confidence': 0.6
            },
            {
                'method': 'User-Agent 伪装',
                'params': {'headers': {'User-Agent': 'Googlebot/2.1'}},
                'confidence': 0.5
            },
            {
                'method': 'HTTP 方法切换',
                'params': {'method': 'GET', 'headers': {'X-HTTP-Method-Override': 'GET'}},
                'confidence': 0.4
            },
        ]

        return {
            'strategies': strategies,
            'reasoning': '规则引擎提供的通用绕过策略'
        }

    def _chain_rules(self, request: AIDecisionRequest) -> List:
        """攻击链组合规则。"""
        findings = request.context.get('findings', [])

        # 按严重程度排序
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
        findings.sort(key=lambda f: severity_order.get(f.severity, 3))

        chains = []

        # 尝试组合
        idor_findings = [f for f in findings if 'idor' in f.vuln_class.lower()]
        info_disclosure = [f for f in findings if 'disclosure' in f.vuln_class.lower()]

        if idor_findings and info_disclosure:
            chain = [
                {'step': 1, 'finding': idor_findings[0].vuln_class, 'description': '访问其他用户资源'},
                {'step': 2, 'finding': info_disclosure[0].vuln_class, 'description': '泄露敏感信息'}
            ]
            chains.append(chain)

        return {
            'chains': chains,
            'total_impact': 'HIGH' if chains else 'MEDIUM',
            'reasoning': '规则引擎组合逻辑'
        }


# ---------------------------------------------------------------------------
# Agent 可用的决策接口
# ---------------------------------------------------------------------------

class AgentDecisionInterface:
    """
    Agent 决策接口。

    提供 @agent_skill 装饰的方法，让 agent 可以参与决策。
    """

    @staticmethod
    def create_priority_skill(state: HuntState):
        """创建优先级评估 skill。"""
        from core import agent_skill, SkillResult, AgentExecutionStatus

        @agent_skill(name="assess_endpoint_priority", category="decision")
        def assess_priority(endpoint: Dict) -> SkillResult:
            """Hermes agent 实现这个方法来评估端点优先级。"""
            # agent 会接收到 endpoint 数据，返回评估结果
            # 这里只是接口定义，实际由 agent 实现
            return SkillResult(
                status=AgentExecutionStatus.SUCCESS,
                data={
                    'priority': 'HIGH',      # agent 决定的优先级
                    'reason': 'agent 理由',  # agent 的推理
                    'confidence': 0.8
                }
            )

        return assess_priority

    @staticmethod
    def create_validation_skill(state: HuntState):
        """创建漏洞验证 skill。"""
        from core import agent_skill, SkillResult, AgentExecutionStatus

        @agent_skill(name="validate_finding", category="decision")
        def validate_finding(finding: Finding) -> SkillResult:
            """Hermes agent 实现这个方法来验证漏洞。"""
            return SkillResult(
                status=AgentExecutionStatus.SUCCESS,
                data={
                    'is_valid': True,
                    'confidence': 0.7,
                    'false_positive_risk': 0.3,
                    'recommendation': 'agent 建议'
                }
            )

        return validate_finding

    @staticmethod
    def create_bypass_skill(state: HuntState):
        """创建绕过策略 skill。"""
        from core import agent_skill, SkillResult, AgentExecutionStatus

        @agent_skill(name="generate_bypass", category="decision")
        def generate_bypass(situation: Dict) -> SkillResult:
            """Hermes agent 实现这个方法来生成绕过策略。"""
            return SkillResult(
                status=AgentExecutionStatus.SUCCESS,
                data={
                    'strategies': [
                        {'method': '方法', 'params': {}, 'confidence': 0.7}
                    ],
                    'reasoning': 'agent 推理'
                }
            )

        return generate_bypass


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def create_decision_engine(state: HuntState) -> AgentDecisionEngine:
    """创建决策引擎实例。"""
    return AgentDecisionEngine(state)
