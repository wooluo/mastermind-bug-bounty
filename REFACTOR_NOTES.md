# 重构说明 v2.0

## 用户反馈后的架构改进

### 原问题诊断

用户正确指出：**"很多为 AI 而 AI 的地方"**

#### ❌ 之前的问题

**不需要 AI 的部分（过度封装）:**
1. `Tool Executors` - 本质就是 `subprocess.run()` + JSON 解析
2. `Value Linkage Engine` - 纯正则匹配，规则引擎即可
3. `Security 模块` - 确定性代码，AI 参与 overhead
4. `状态管理` - 纯 IO 操作

#### ⚠️ 真正需要 AI 的部分（空壳）:

1. **Orchestrator** - 只有 62 行 demo，没有真正执行逻辑
2. **JS 分析** - 空壳
3. **结果研判** - 空的硬编码
4. **Exploit 链** - 未实现
5. **Bypass 策略** - 未实现
6. **业务逻辑漏洞** - 未实现

---

## ✅ v2.0 改进

### 核心重构

#### 1. 重写 Orchestrator（workflow/orchestrator.py）

**之前:**
```python
def run(self, ...):
    print("  [Phase 1/6] RECON - Fingerprinting target...")
    self.state.completed_phases.append(PhaseName.RECON)
    # ... 5 个 phase 一模一样，全是 print
```

**现在:**
```python
def run(self, ...):
    # 真正执行每个 phase
    while current_phase:
        # 检查依赖
        # 触发钩子
        # 执行阶段逻辑
        # AI 决策点
        # 状态更新和保存
```

每个 phase 都有真实的执行器：
- `_execute_recon()` - JS 收集、分析、端点优先级排序
- `_execute_dependency_scan()` - CVE 匹配
- `_execute_api_fuzz()` - 策略生成、payload 生成、实际测试
- `_execute_crypto_attack()` - JWT 攻击、密钥测试
- `_execute_bypass()` - 403/WAF 绕过
- `_execute_exploit()` - 结果验证、攻击链组合、POC 生成

#### 2. 新增 AI 模块（core/ai_modules/）

真正需要 AI 判断的模块：

**JSAnalyzer** - JavaScript 智能分析
- 不仅仅是正则提取，而是理解上下文
- 判断哪些端点值得测试（优先级评分）
- 识别认证要求、参数类型
- 技术栈识别

**BypassEngine** - 绕过策略生成
- 403 绕过：X-Forwarded-For、User-Agent 伪装等
- WAF 绕过：编码、大小写变化、注释注入
- 认证绕过：参数污染、SQL 注入

**AttackChainComposer** - 攻击链组合
- 发现漏洞间的关联
- 组合攻击路径（IDOR → 敏感信息泄露）
- 评估攻击链整体影响

**FindingValidator** - 结果研判
- 真假漏洞判断
- 误报过滤
- 置信度评估

---

### 架构对比

#### 之前（v1.1）
```
┌─────────────────────────────────┐
│  Hermes                        │
└─────────────────────────────────┘
              ↓
┌─────────────────────────────────┐
│  @agent_skill (过度封装)        │
│  - subprocess wrapper          │
│  - JSON parsing                │
│  - Finding conversion         │
└─────────────────────────────────┘
              ↓
┌─────────────────────────────────┐
│  Orchestrator (空壳)           │
│  - 6 print statements         │
│  - 6 append() calls           │
└─────────────────────────────────┘
```

#### 现在（v2.0）
```
┌─────────────────────────────────┐
│  Hermes                        │
└─────────────────────────────────┘
              ↓
┌─────────────────────────────────┐
│  Orchestrator (真正的执行)      │
│  - 6 个 phase 执行器            │
│  - 依赖检查                     │
│  - 钩子系统                     │
│  - AI 决策点                   │
└─────────────────────────────────┘
              ↓
    ┌─────────┼─────────┐
    ↓         ↓         ↓
┌──────────┐ ┌──────────┐ ┌──────────┐
│ JSAnalyzer│ │BypassEngine│ │AttackChain│
│ - 智能分析  │ │ - 策略生成│ │ - 组合攻击│
│ - 优先级   │ │ - 绕过技巧│ │ - 影响评估│
└──────────┘ └──────────┘ └──────────┘
```

---

### 新功能清单

| 模块 | 功能 | AI 参与度 |
|------|------|----------|
| Orchestrator | 真正执行 6 个 phase | ★★★ 决策 |
| JSAnalyzer | JS 智能分析、端点评分 | ★★★ 判断 |
| EndpointPrioritizer | 高价值目标识别 | ★★★ 评估 |
| BypassEngine | 绕过策略生成 | ★★★ 创造 |
| AttackChainComposer | 攻击链组合 | ★★★ 推理 |
| FindingValidator | 结果研判 | ★★★ 判断 |
| FuzzStrategyGenerator | Fuzz 策略 | ★★★ 策划 |
| CryptoAttacker | 加密攻击 | ★★ 分析 |
| VulnerabilityMatcher | CVE 匹配 | ★ 规则 |
| PayloadGenerator | Payload 生成 | ★★ 变体 |

---

### 代码量对比

| 文件 | v1.1 | v2.0 | 变化 |
|------|------|------|------|
| orchestrator.py | 62 行 | 380+ 行 | +500% |
| ai_modules/ | 0 文件 | 5 文件 | 新增 |
| 总计 | ~600 行 | ~1800 行 | +200% |

---

### 下一步

真正的 AI 执行流程：

```
Recon 阶段
  ↓ JSAnalyzer 分析 → 发现 50 个端点
  ↓ EndpointPrioritizer 评分 → 标出 10 个高价值
  ↓ AI 决策 → "重点测试 API 和管理接口"

API Fuzz 阶段
  ↓ FuzzStrategyGenerator → 生成 3 种策略
  ↓ Value Linkage → 关联 20 个值-端点对
  ↓ PayloadGenerator → 生成定制化 payload
  ↓ 实际测试 → 发现 3 个潜在漏洞

Exploit 阶段
  ↓ FindingValidator → 验证发现
  ↓ AttackChainComposer → 发现 IDOR + 敏感信息泄露
  ↓ 生成组合攻击链 → POC

Bypass 阶段
  ↓ BypassEngine → 生成 5 种绕过方法
  ↓ 测试 → 403 绕过成功
  ↓ 新发现 → 认证绕过漏洞
```

---

## 总结

**去除:** 工具调用的过度封装
**添加:** 真正需要 AI 的决策逻辑
**结果:** 从"为 AI 而 AI"到"AI 真正发挥作用"

---

<div align="center">

**v2.0 — AI 真正参与渗透测试**

© 2026 Mastermind Bug Bounty

</div>
