# Hermes Agent 决策集成指南

## 概述

现在 AI 模块使用 **Hermes agent 决策** 而不是硬编码规则。

---

## 架构

```
┌─────────────────────────────────────────┐
│  Orchestrator                           │
│  └─ decision_engine                       │
└─────────────────────────────────────────┘
              │
              ↓ 决策请求
┌─────────────────────────────────────────┐
│  AgentDecisionEngine                     │
│  ┌─────────────────┐                   │
│  │ Agent Hook      │ ← 注册 agent skill   │
│  └─────────────────┘                   │
│  ┌─────────────────┐                   │
│  │ Rule Engine     │ ← fallback          │
│  └─────────────────┘                   │
└─────────────────────────────────────────┘
              │
              ↓ 决策结果
┌─────────────────────────────────────────┐
│  Orchestrator (继续执行)                │
└─────────────────────────────────────────┘
```

---

## Hermes Agent 如何参与决策

### 方式 1: 注册决策钩子

```python
from core import agent_skill, SkillResult, AgentExecutionStatus
from core.ai_decision import AgentDecisionEngine, AIDecisionRequest, DecisionType

# 创建决策引擎
decision_engine = AgentDecisionEngine(state)

# 注册 agent skill 为决策钩子
@agent_skill(name="assess_priority", category="decision")
def assess_priority(request: AIDecisionRequest) -> SkillResult:
    """Hermes agent 实现的优先级评估。"""
    # 获取端点信息
    endpoint = request.context.get('endpoint', {})

    # AI 判断
    if 'admin' in endpoint.get('url', '').lower():
        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            data={
                'priority': 'CRITICAL',
                'reason': '管理功能，高价值目标',
                'confidence': 0.9
            }
        )
    else:
        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            data={'priority': 'NORMAL', 'reason': '普通端点', 'confidence': 0.6}
        )

# 注册为决策钩子
decision_engine.register_decision_hook(
    DecisionType.PRIORITY_ASSESSMENT,
    assess_priority
)
```

### 方式 2: 在 Orchestrator 中注入

```python
orchestrator = Orchestrator(hunt_dir="./hunt-data")

# 传入决策函数
def ai_decision_fn(state):
    """Hermes agent 的决策函数。"""
    # 可以调用 agent skill
    return should_continue_hunt(state)

# 运行时会自动调用
state = orchestrator.run(
    target_url="https://example.com",
    ai_decision_fn=ai_decision_fn
)
```

---

## 决策类型

| 决策类型 | 何时触发 | Agent 返回 |
|---------|---------|-----------|
| `PRIORITY_ASSESSMENT` | 评估端点优先级 | `{priority, reason, confidence}` |
| `VULNERABILITY_VALIDATION` | 验证漏洞真实性 | `{is_valid, confidence, recommendation}` |
| `BYPASS_STRATEGY` | 生成绕过策略 | `{strategies: [...], reasoning}` |
| `ATTACK_CHAIN_COMPOSITION` | 组合攻击链 | `{chains: [...], total_impact}` |
| `TECHNIQUE_SELECTION` | 选择测试技巧 | `{recommended_techniques: [...]}` |

---

## 完整示例

### 示例：让 Hermes 评估端点优先级

```python
from core import agent_skill, SkillResult, AgentExecutionStatus
from core.ai_decision import AgentDecisionEngine, AIDecisionRequest, DecisionType
from workflow.orchestrator import Orchestrator

# 1. 创建决策引擎
decision_engine = AgentDecisionEngine(state)

# 2. 注册 agent skill
@agent_skill(name="judge_endpoint", category="decision")
def judge_endpoint(request: AIDecisionRequest) -> SkillResult:
    """Hermes agent 评估端点。"""
    endpoint = request.context.get('endpoint', {})
    url = endpoint.get('url', '')
    method = endpoint.get('method', 'GET')

    # Hermes 做智能判断
    reasoning = ""
    priority = "NORMAL"
    confidence = 0.5

    if 'admin' in url.lower():
        priority = "CRITICAL"
        reasoning = "管理接口，完全控制"
        confidence = 0.95
    elif 'api' in url.lower() and method == 'POST':
        priority = "HIGH"
        reasoning = "API 写操作，可能创建数据"
        confidence = 0.8
    else:
        reasoning = "常规端点，标准测试"
        confidence = 0.4

    return SkillResult(
        status=AgentExecutionStatus.SUCCESS,
        data={
            'priority': priority,
            'reason': reasoning,
            'confidence': confidence
        }
    )

# 3. 注册钩子
decision_engine.register_decision_hook(
    DecisionType.PRIORITY_ASSESSMENT,
    lambda req: judge_endpoint(req).data
)

# 4. 运行（会自动调用 agent）
orchestrator = Orchestrator()
orchestrator.decision_engine = decision_engine
state = orchestrator.run("https://example.com")
```

---

## 对比：之前 vs 现在

### 之前（规则引擎）

```python
def _assess_endpoint_priority(self, url, method, params, requires_auth):
    priority_score = 0
    if 'admin' in url.lower():
        priority_score += 3
    # ... 硬编码规则
    return 'CRITICAL' if priority_score >= 6 else 'HIGH'
```

### 现在（Hermes Agent 决策）

```python
def _assess_endpoint_priority(self, url, method, params, requires_auth):
    # 创建决策请求
    request = AIDecisionRequest(...)

    # 调用 agent 或 fallback 到规则
    decision = self.decision_engine.request_decision(request)

    return decision.result.get('priority')
```

---

## 工作流程

```
Recon 阶段发现端点
    ↓
创建 AIDecisionRequest (PRIORITY_ASSESSMENT)
    ↓
decision_engine.request_decision()
    ↓
尝试调用注册的 agent hooks
    ↓
┌─────────────────────┐
│ Agent Hook 存在？     │
└─────────────────────┘
    ↓ Yes              ↓ No
┌─────────────┐    ┌─────────────┐
│ Agent 决策  │    │ 规则引擎    │
└─────────────┘    └─────────────┘
    ↓                 ↓
返回决策结果
    ↓
Orchestrator 继续执行
```

---

## 优势

1. **灵活性**：Hermes agent 可以根据实时情况做决策
2. **可测试**：agent skill 可以单独测试
3. **fallback**：agent 不可用时自动使用规则引擎
4. **透明性**：每个决策都有记录和推理过程
5. **可扩展**：添加新决策类型只需注册新钩子

---

## 下一步

运行时会自动调用已注册的 agent skill 做决策！

如果没有注册 agent skill，会使用规则引擎 fallback。
