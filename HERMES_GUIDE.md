# Hermes 智能体使用指南

> Mastermind Bug Bounty — 为 Hermes 智能体设计的渗透测试框架

本文档专门为 Hermes 智能体提供完整的使用说明，包括所有可用的模块、接口和最佳实践。

---

## 📋 目录

- [概述](#概述)
- [架构](#架构)
- [核心模块](#核心模块)
- [智能体接口](#智能体接口)
- [数据关联](#数据关联)
- [工具集成](#工具集成)
- [批量处理](#批量处理)
- [报告生成](#报告生成)
- [完整示例](#完整示例)
- [最佳实践](#最佳实践)

---

## 概述

Mastermind 是一个专为 Hermes 智能体设计的自动化渗透测试框架，提供：

- **统一的调用接口** - `@agent_skill` 装饰器简化开发
- **自动数据关联** - 智能匹配发现的值与待测试端点
- **工具集成** - 标准化的 httpx、nuclei、ffuf 调用
- **批量处理** - 并发扫描多个目标
- **报告生成** - 多格式输出（Markdown/HTML/JSON/PDF）

### 快速开始

```python
from core import agent_skill, SkillResult, AgentExecutionStatus
from shared.types import HuntState

@agent_skill(name="quick_scan", category="recon")
def quick_scan(state: HuntState) -> SkillResult:
    """快速扫描目标"""
    # 你的扫描逻辑
    return SkillResult(status=AgentExecutionStatus.SUCCESS, data={...})
```

---

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                      Hermes 智能体                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   Agent Interface (agent_interface.py)       │
│  - @agent_skill 装饰器                                        │
│  - AgentHooks 钩子系统                                         │
│  - AgentContext 上下文管理                                    │
└─────────────────────────────────────────────────────────────┘
                              │
          ┌──────────────────┼──────────────────┐
          ↓                  ↓                  ↓
┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│  Value Linkage    │ │   Tool Executors  │ │  Report Generator │
│  (value_linkage)  │ │  - httpx          │ │  (reporting)      │
│                   │ │  - nuclei         │ │                   │
│  - 自动关联       │ │  - ffuf           │ │  - Markdown       │
│  - 值提取         │ │  - tool_manager   │ │  - HTML           │
│  - 优先级排序     │ │                    │ │  - JSON           │
└───────────────────┘ └───────────────────┘ └───────────────────┘
          │
          ↓
┌─────────────────────────────────────────────────────────────┐
│                      HuntState                              │
│  - 状态管理                                                  │
│  - 智能查询方法                                              │
│  - 自动持久化                                                │
└─────────────────────────────────────────────────────────────┘
```

---

## 核心模块

### 模块导入

```python
# 核心接口
from core import (
    # 智能体接口
    agent_skill, SkillResult, AgentExecutionStatus,
    AgentHooks, AgentContext,
    validate_agent_input, retry_on_failure,

    # 数据关联
    ValueLinkageEngine, LinkagePriority,
    check_linkage_completeness, get_next_unconsumed_pair,

    # 工具执行
    ToolManager, HttpxExecutor, NucleiExecutor, FfufExecutor,

    # 批量处理
    BatchProcessor, BatchConfig, BatchResult, BatchSummary,
)

# 数据类型
from shared.types import (
    HuntState, Target, Finding, Severity, FindingStatus,
    PhaseName, HuntStatus,
    ValueEntry, UnconsumedPair, EndpointParamRequirement,
)

# 报告生成
from reporting import ReportGenerator, CVSSCalculator
```

---

## 智能体接口

### @agent_skill 装饰器

自动处理：
- 执行时间追踪
- 错误处理和重试
- 状态更新
- 日志记录

```python
from core import agent_skill, SkillResult, AgentExecutionStatus, AgentContext
from shared.types import HuntState, Finding, Severity

@agent_skill(name="endpoint_scan", category="recon")
def scan_endpoints(state: HuntState, target: str = None) -> SkillResult:
    """扫描端点并返回发现"""
    # 使用目标 URL 或 state.target.url
    url = target or state.target.url

    context = AgentContext(state)

    # 执行 HTTP 请求
    result = context.executor.http_request(url)

    if result.status != AgentExecutionStatus.SUCCESS:
        return SkillResult(
            status=AgentExecutionStatus.FAILED,
            error=f"Request failed: {result.error}"
        )

    # 返回结果
    return SkillResult(
        status=AgentExecutionStatus.SUCCESS,
        data={
            "url": url,
            "status_code": result.data.get("status_code"),
            "headers": result.data.get("headers"),
        },
        findings=result.findings,  # 自动添加到 state
    )
```

### AgentHooks 钩子系统

在关键点介入工作流程：

```python
from core import AgentHooks

hooks = AgentHooks()

# 预阶段钩子
@hooks.register('pre_phase')
def before_phase(phase: str, state: HuntState):
    """阶段开始前执行"""
    if phase == "exploit":
        # 检查是否有足够的发现
        if len(state.findings) == 0:
            return False  # 阻止进入 exploit 阶段
    return True

# 决策点钩子
@hooks.register('decision_point')
def should_proceed(state: HuntState):
    """智能决策点"""
    # 根据状态决定是否继续
    return state.current_phase != PhaseName.EXPLOIT or len(state.findings) > 0

# 触发钩子
hooks.pre_phase("recon", state)
result = hooks.should_proceed(state)
```

### AgentContext 上下文管理器

```python
from core import AgentContext

context = AgentContext(state, agent_id="hermes-001")

# 工具执行器
executor = context.executor
result = executor.http_request("https://example.com")

# 获取相关发现
findings = context.get_relevant_findings("sql_injection")

# 日志记录
context.log("Starting scan", level="info")
```

---

## 数据关联

### ValueLinkageEngine

自动关联发现的值与待测试端点：

```python
from core import ValueLinkageEngine, LinkagePriority

# 创建引擎
engine = ValueLinkageEngine()

# 处理状态并生成关联
result = engine.process_state(state)

print(f"总对数: {result.total_pairs}")
print(f"未消耗: {result.unconsumed_pairs}")
print(f"关键未消耗: {result.critical_unconsumed}")

# 获取特定优先级的对
critical_pairs = engine.get_unconsumed_pairs(
    state,
    priority=LinkagePriority.CRITICAL,
    limit=10
)

for pair in critical_pairs:
    print(f"  {pair.endpoint} - {pair.param_name}={pair.value[:20]}")
```

### 获取下一个任务

```python
from core.linkage import get_next_unconsumed_pair, mark_pair_consumed

# 获取下一个待处理任务
pair = get_next_unconsumed_pair(state)

if pair:
    print(f"测试: {pair.endpoint}")
    print(f"参数: {pair.param_name} = {pair.value}")

    # 执行测试...
    test_result = test_pair(pair)

    # 标记为已消耗
    if test_result.success:
        mark_pair_consumed(state, pair)
```

### 支持的数据类型

引擎自动提取以下类型的数据（按优先级）：

**CRITICAL 优先级：**
- JWT Tokens
- API Keys (AWS, Google, GitHub, Slack, Stripe)
- 认证令牌 (Bearer, Auth Token)
- CSRF Tokens
- Secrets
- Database URLs

**HIGH 优先级：**
- User IDs
- Session IDs
- Passwords
- Emails
- S3 Buckets

**NORMAL 优先级：**
- UUIDs
- Numeric IDs
- Internal URLs
- GraphQL Operations
- Phone Numbers
- Config Paths

**LOW 优先级：**
- Base64 encoded data
- Internal IPs

---

## 工具集成

### ToolManager

统一管理所有安全工具：

```python
from core import ToolManager

# 创建工具管理器
manager = ToolManager(state)

# 检查可用工具
available = manager.get_available_tools()
print(f"可用工具: {available}")

# 获取状态报告
status = manager.get_status_report()
print(f"可用: {status['available']}")
print(f"缺失: {status['missing']}")

# 获取安装命令
if status['missing']:
    print(manager.suggest_installation())
```

### HTTPX 执行器

```python
from core import HttpxExecutor

executor = HttpxExecutor(state)

# 快速端口/服务发现
result = executor.run(
    urls=["https://example.com"],
    ports=[80, 443, 8080, 8443],
    tech_detect=True,
    server=True,
)

# 解析结果
for endpoint in result.parsed_data["endpoints"]:
    print(f"{endpoint['url']} - {endpoint['status_code']}")
    if "technologies" in endpoint:
        print(f"  技术: {endpoint['technologies']}")
```

### Nuclei 执行器

```python
from core import NucleiExecutor

executor = NucleiExecutor(state)

# 漏洞扫描
result = executor.run(
    urls=["https://example.com"],
    severity=["critical", "high", "medium"],
    tags=["cve", "exposure", "misconfig"],
)

# 查看发现的漏洞
for vuln in result.parsed_data["vulnerabilities"]:
    print(f"[{vuln['severity']}] {vuln['template_id']}")
    print(f"  匹配位置: {vuln['matched_at']}")
    print(f"  标签: {', '.join(vuln['tags'])}")
```

### FFUF 执行器

```python
from core import FfufExecutor

executor = FfufExecutor(state)

# 目录模糊测试
result = executor.run(
    url="https://example.com/FUZZ",
    wordlist="/path/to/wordlist.txt",
    match_status="200,204,301,302,403",
    filter_size=0,
)

# 查看发现的路径
for finding in result.parsed_data["results"]:
    print(f"{finding['status']} - {finding['url']}")
```

---

## 批量处理

### 命令行批量扫描

```bash
# 从文件读取目标
python cli.py batch-run --target-file targets.txt --parallel 3

# 直接指定多个目标
python cli.py batch-run --targets https://a.com https://b.com https://c.com

# CIDR 范围扫描
python cli.py batch-run --cidr 192.168.1.0/24 --exclude 192.168.1.1

# 排除特定模式
python cli.py batch-run --target-file targets.txt --exclude admin test staging

# 输出结果
python cli.py batch-run --target-file targets.txt -o results.json
```

### 编程式批量处理

```python
from core import BatchProcessor, BatchConfig
from pathlib import Path

# 配置批量处理
config = BatchConfig(
    targets=["https://example.com", "https://test.com"],
    target_file=Path("targets.txt"),
    parallel_jobs=3,
    base_hunt_dir="./batch-results",
    depth="standard",
)

# 创建处理器
processor = BatchProcessor(config)

# 添加进度回调
def progress_callback(percent, result):
    print(f"[{percent:.1f}%] {result.target} - {result.findings_count} findings")

processor.set_progress_callback(progress_callback)

# 运行
summary = processor.run()

# 查看结果
print(f"总目标: {summary.total_targets}")
print(f"已完成: {summary.completed}")
print(f"失败: {summary.failed}")
print(f"总发现: {summary.total_findings}")

# 保存摘要
processor.save_summary(Path("batch_summary.json"))
```

---

## 报告生成

### 基础报告生成

```python
from reporting import ReportGenerator
from pathlib import Path

# 创建生成器
gen = ReportGenerator()

# 生成 Markdown 报告
md_report = gen.generate(state, format="markdown",
                        output_file=Path("report.md"))

# 生成 HTML 报告
html_report = gen.generate(state, format="html",
                          output_file=Path("report.html"))

# 生成 JSON 报告
json_report = gen.generate(state, format="json",
                          output_file=Path("report.json"))

# 生成所有格式
files = gen.generate_all(state, output_dir=Path("./reports"))
# 返回: {"markdown": Path(...), "html": Path(...), "json": Path(...)}
```

### 高级报告功能

```python
# 文本摘要
summary = gen.generate_summary(state)
print(summary)

# 执行摘要（给干系人）
exec_summary = gen.generate_executive_summary(state)
print(f"整体风险: {exec_summary['overall_risk']}")
print(f"风险评分: {exec_summary['risk_score']}")
print(f"建议: {exec_summary['recommendations']}")
```

### CVSS 评分

```python
from reporting import CVSSCalculator, estimate_cvss

# 快速估算
cvss_data = estimate_cvss("sql_injection")
print(f"CVSS: {cvss_data['base_score']} ({cvss_data['severity']})")
print(f"向量: {cvss_data['vector_string']}")

# 自定义计算
calculator = CVSSCalculator()
result = calculator.calculate(
    attack_vector="N",
    attack_complexity="L",
    privileges_required="N",
    user_interaction="N",
    scope="C",
    confidentiality="H",
    integrity="H",
    availability="H"
)
print(f"自定义 CVSS: {result['base_score']}")
```

---

## 完整示例

### 示例 1: 基础扫描流程

```python
from core import agent_skill, SkillResult, AgentExecutionStatus, AgentContext
from core import ValueLinkageEngine
from shared.types import HuntState, Finding, Severity
from workflow.orchestrator import Orchestrator

# 1. 初始化扫描
orch = Orchestrator(hunt_dir="./hunt-data")
state = orch.run("https://example.com")

# 2. 使用数据关联引擎
engine = ValueLinkageEngine()
linkage_result = engine.process_state(state)

# 3. 获取关键待测试对
critical_pairs = engine.get_unconsumed_pairs(state, priority="CRITICAL")

# 4. 定义测试技能
@agent_skill(name="test_pair", category="fuzzing")
def test_value_pair(state: HuntState, pair) -> SkillResult:
    context = AgentContext(state)

    # 构造测试 URL
    test_url = pair.endpoint.replace(f"{{{pair.param_name}}}", pair.value)

    # 执行请求
    result = context.executor.http_request(test_url)

    # 分析结果
    if "error" in result.data.get("body", "").lower():
        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            findings=[Finding(
                id=finding_id(),
                vuln_class="potential_injection",
                target_url=test_url,
                severity=Severity.HIGH,
                evidence=f"Error response when testing {pair.param_name}={pair.value}",
            )]
        )

    return SkillResult(status=AgentExecutionStatus.SUCCESS)

# 5. 测试所有关键对
for pair in critical_pairs:
    result = test_pair(state, pair)
    if result.findings:
        print(f"发现漏洞: {result.findings[0].vuln_class}")
```

### 示例 2: 使用工具集成

```python
from core import ToolManager, agent_skill, SkillResult, AgentExecutionStatus

@agent_skill(name="full_scan", category="recon")
def full_target_scan(state: HuntState) -> SkillResult:
    """完整目标扫描"""

    manager = ToolManager(state)

    # 检查可用工具
    available = manager.get_available_tools()

    all_findings = []

    # HTTPX 端点发现
    if "httpx" in available:
        httpx_result = manager.run_recon(urls=[state.target.url])
        if "httpx" in httpx_result:
            all_findings.extend(httpx_result["httpx"].findings)

    # Nuclei 漏洞扫描
    if "nuclei" in available:
        vuln_result = manager.run_vulnerability_scan(
            urls=[state.target.url],
            severity=["critical", "high", "medium"]
        )
        if vuln_result:
            all_findings.extend(vuln_result.findings)

    return SkillResult(
        status=AgentExecutionStatus.SUCCESS,
        data={
            "tools_used": available,
            "total_findings": len(all_findings),
        },
        findings=all_findings,
    )
```

### 示例 3: 带钩子的智能扫描

```python
from core import agent_skill, SkillResult, AgentExecutionStatus, AgentHooks
from core import ToolManager

# 创建钩子
hooks = AgentHooks()

@hooks.register('pre_phase')
def validate_phase(phase, state):
    """确保每个阶段有足够的数据"""
    if phase == "api_fuzz" and len(state.target.endpoints_discovered) == 0:
        print(f"警告: 没有端点，跳过 API fuzzing")
        return False
    return True

@hooks.register('post_finding')
def log_finding(finding, state):
    """记录每个发现"""
    print(f"[发现] {finding.severity.value}: {finding.vuln_class}")

# 使用钩子的扫描
@agent_skill(name="smart_scan", category="recon")
def smart_scan(state: HuntState) -> SkillResult:
    """智能扫描 - 使用钩子"""

    # 触发预阶段钩子
    if not hooks.pre_phase("recon", state):
        return SkillResult(status=AgentExecutionStatus.SKIPPED)

    manager = ToolManager(state)
    result = manager.run_recon(urls=[state.target.url])

    # 处理发现
    all_findings = []
    for tool_result in result.values():
        for finding in tool_result.findings:
            # 触发发现钩子
            filtered = hooks.on_finding(finding, state)
            if filtered:
                all_findings.append(filtered)

    # 触发后阶段钩子
    hooks.post_phase("recon", state)

    return SkillResult(
        status=AgentExecutionStatus.SUCCESS,
        findings=all_findings,
    )
```

---

## HuntState 智能查询

### 快速查询方法

```python
from shared.types import HuntState

state = HuntState(...)

# 获取关键待处理对
critical_pairs = state.get_unconsumed_critical_pairs()

# 获取待 fuzz 目标
fuzz_targets = state.get_pending_fuzzing_targets()

# 检查是否可转换阶段
can_proceed = state.should_transition(PhaseName.API_FUZZ)

# 获取相关上下文
context = state.get_relevant_context("fuzz api")
# 返回: {"hunt_id": ..., "target": ..., "endpoints": [...], ...}

# 按严重程度获取发现
high_severity = state.get_findings_by_severity(Severity.HIGH)

# 获取待处理发现
pending = state.get_pending_findings()

# 获取已批准发现
approved = state.get_approved_findings()

# 添加发现
state.add_finding(finding)

# 完成阶段
state.complete_phase(PhaseName.RECON)

# 获取摘要
summary = state.get_summary()
```

---

## 最佳实践

### 1. 技能设计原则

```python
# ✅ 好的设计
@agent_skill(name="check_auth_bypass", category="auth")
def check_auth_bypass(state: HuntState, endpoint: str) -> SkillResult:
    """
    检查认证绕过漏洞

    Args:
        state: 当前狩猎状态
        endpoint: 要测试的端点
    """
    context = AgentContext(state)

    # 验证输入
    if not endpoint.startswith(state.target.url):
        return SkillResult(
            status=AgentExecutionStatus.FAILED,
            error="端点不在目标范围内"
        )

    # 执行测试
    result = context.executor.http_request(
        endpoint,
        headers={"Authorization": "Bearer invalid"}
    )

    # 分析结果
    if result.data.get("status_code") == 200:
        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            findings=[Finding(...)]
        )

    return SkillResult(status=AgentExecutionStatus.SUCCESS)
```

### 2. 错误处理

```python
from core import retry_on_failure

@agent_skill(name="unstable_scan", category="recon")
@retry_on_failure(max_retries=3, backoff=1.0)
def unstable_operation(state: HuntState) -> SkillResult:
    """可能失败的操作 - 自动重试"""
    # 这个操作失败时会自动重试最多 3 次
    ...
```

### 3. 输入验证

```python
from core import validate_agent_input

@validate_agent_input(
    url=validate_target_url,  # 自动验证 URL
    count=lambda x: x > 0 and x <= 100  # 自定义验证
)
@agent_skill(name="validated_scan", category="recon")
def validated_scan(state: HuntState, url: str, count: int) -> SkillResult:
    """带输入验证的扫描"""
    # url 和 count 已经被验证
    ...
```

### 4. 资源管理

```python
@agent_skill(name="efficient_scan", category="recon")
def efficient_scan(state: HuntState) -> SkillResult:
    """资源高效的扫描"""
    context = AgentContext(state)

    # 检查是否已有足够数据
    if len(state.target.endpoints_discovered) > 100:
        context.log("端点已足够，跳过扫描", level="info")
        return SkillResult(status=AgentExecutionStatus.SKIPPED)

    # 只扫描需要的部分
    needed = 50 - len(state.target.endpoints_discovered)

    # 执行有限扫描
    ...
```

### 5. 日志和调试

```python
@agent_skill(name="debuggable_scan", category="recon")
def debuggable_scan(state: HuntState) -> SkillResult:
    """可调试的扫描"""
    context = AgentContext(state, agent_id="debug_agent")

    context.log("开始扫描", level="info")
    context.log(f"目标: {state.target.url}", level="debug")

    try:
        result = context.executor.http_request(state.target.url)
        context.log(f"状态码: {result.data.get('status_code')}", level="debug")
        return SkillResult(status=AgentExecutionStatus.SUCCESS, data=result.data)
    except Exception as e:
        context.log(f"错误: {str(e)}", level="error")
        return SkillResult(status=AgentExecutionStatus.FAILED, error=str(e))
```

---

## 常用模式

### 模式 1: 渐进式扫描

```python
@agent_skill(name="progressive_scan", category="recon")
def progressive_scan(state: HuntState) -> SkillResult:
    """渐进式扫描 - 从低到高强度"""

    phases = [
        ("basic", ["httpx"]),
        ("vuln", ["nuclei --severity critical"]),
        ("deep", ["nuclei --severity high,medium", "ffuf"]),
    ]

    for phase_name, tools in phases:
        context.log(f"执行阶段: {phase_name}")

        # 检查是否应该继续
        if not state.should_transition(PhaseName.EXPLOIT):
            break

        # 执行阶段工具
        ...
```

### 模式 2: 条件执行

```python
@agent_skill(name="conditional_scan", category="recon")
def conditional_scan(state: HuntState) -> SkillResult:
    """条件执行 - 基于状态决定"""

    # 检查技术栈
    if "react" in state.target.tech_stack:
        # React 应用 - 专注 JS 分析
        return analyze_javascript(state)
    elif "python" in state.target.tech_stack:
        # Python 应用 - 专注模板注入
        return test_ssti(state)
    else:
        # 通用扫描
        return generic_scan(state)
```

### 模式 3: 发现验证

```python
@agent_skill(name="validate_finding", category="triage")
def validate_finding(state: HuntState, finding: Finding) -> SkillResult:
    """验证发现的准确性"""

    context = AgentContext(state)

    # 重新测试
    result = context.executor.http_request(finding.target_url)

    # 验证证据
    if finding.evidence in result.data.get("body", ""):
        # 确认发现
        finding.status = FindingStatus.TRIAGE_APPROVED
        finding.confidence = 1.0
        return SkillResult(status=AgentExecutionStatus.SUCCESS)
    else:
        # 拒绝发现
        finding.status = FindingStatus.TRIAGE_REJECTED
        return SkillResult(status=AgentExecutionStatus.FAILED)
```

---

## 故障排查

### 常见问题

**Q: 工具不可用怎么办？**

```python
manager = ToolManager(state)
if "nuclei" not in manager.get_available_tools():
    print("Nuclei 不可用，使用替代方法")
    # 使用替代扫描逻辑
```

**Q: 内存使用过高？**

```python
# 定期清理
if len(state.findings) > 1000:
    # 只保留高严重性的
    state.findings = [f for f in state.findings
                      if f.severity in [Severity.CRITICAL, Severity.HIGH]]
```

**Q: 扫描速度慢？**

```python
# 调整并发
config = BatchConfig(parallel_jobs=5)  # 增加并发

# 或限制范围
context.log("限制扫描范围", level="info")
endpoints = state.target.endpoints_discovered[:50]
```

---

## API 参考摘要

### 核心类

| 类 | 描述 | 主要方法 |
|---|---|---|
| `AgentContext` | 智能体上下文 | `executor`, `log()`, `get_relevant_findings()` |
| `ToolManager` | 工具管理 | `run_recon()`, `run_vulnerability_scan()` |
| `ValueLinkageEngine` | 数据关联 | `process_state()`, `get_unconsumed_pairs()` |
| `ReportGenerator` | 报告生成 | `generate()`, `generate_all()` |
| `BatchProcessor` | 批量处理 | `run()`, `save_summary()` |

### 装饰器

| 装饰器 | 描述 | 参数 |
|---|---|---|
| `@agent_skill` | 技能装饰器 | `name`, `category`, `capture_findings` |
| `@retry_on_failure` | 重试装饰器 | `max_retries`, `backoff` |
| `@validate_agent_input` | 输入验证 | 参数名=验证函数 |

### 智能查询

| 方法 | 描述 |
|---|---|
| `state.get_unconsumed_critical_pairs()` | 获取关键待处理对 |
| `state.get_pending_fuzzing_targets()` | 获取待 fuzz 目标 |
| `state.should_transition(phase)` | 检查是否可转换 |
| `state.get_relevant_context(task)` | 获取相关上下文 |

---

## 更新日志

### v1.1 (当前版本)

- ✅ 添加智能体接口模块
- ✅ 实现数据关联引擎
- ✅ 集成 httpx、nuclei、ffuf
- ✅ 添加批量处理支持
- ✅ 实现多格式报告生成
- ✅ 扩展 HuntState 查询方法
- ✅ 添加 25+ 数据提取模式

---

## 支持

如有问题或建议，请通过以下方式联系：

- GitHub Issues: [github.com/wooluo/mastermind-bug-bounty]
- 文档: README_SECURITY.md

---

<div align="center">

**Built for Hermes — The Autonomous Security Agent**

© 2026 Mastermind Bug Bounty

</div>
