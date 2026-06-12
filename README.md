# Mastermind Bug Bounty

> **AI 驱动的自动化漏洞狩猎系统 — 为 Hermes 智能体设计**

从"工具"到"武器"的进化。专门为 Hermes 智能体优化的渗透测试框架。

---

## 🎯 特性

- **🤖 智能体友好** - 统一的 `@agent_skill` 接口，简化开发
- **🔗 自动关联** - 智能匹配发现的值与待测试端点
- **🛠️ 工具集成** - 标准化的 httpx、nuclei、ffuf 调用
- **📊 批量处理** - 并发扫描多个目标，支持 CIDR 扩展
- **📝 报告生成** - 多格式输出（Markdown/HTML/JSON/PDF）
- **🔒 安全加固** - SSRF 防护、加密存储、审计日志

---

## 🚀 快速开始

### 安装依赖

```bash
# 安装 Go 工具（可选，用于工具集成）
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
nuclei -update-templates
```

### 基础使用

```bash
# 单目标扫描
python cli.py run --target https://example.com

# 批量扫描
python cli.py batch-run --target-file targets.txt --parallel 3

# 查看状态
python cli.py status

# 列出阶段
python cli.py phases
```

---

## 📚 文档

| 文档 | 描述 |
|------|------|
| **[HERMES_GUIDE.md](HERMES_GUIDE.md)** | 📘 Hermes 智能体完整使用指南 |
| **[README_SECURITY.md](README_SECURITY.md)** | 🔒 安全加固说明 |

---

## 🏗️ 项目结构

```
mastermind-bug-bounty/
├── cli.py                      # CLI 入口
├── core/                       # 核心执行引擎
│   ├── agent_interface.py      # 智能体接口 (@agent_skill)
│   ├── batch.py                # 批量处理器
│   ├── linkage/                # 数据关联
│   │   └── value_linkage.py   # 自动值-端点关联
│   └── executors/              # 工具包装器
│       ├── httpx_executor.py
│       ├── nuclei_executor.py
│       └── ffuf_executor.py
├── reporting/                  # 报告生成
│   ├── generator.py
│   ├── templates.py
│   └── cvss.py
├── shared/                     # 共享模块
│   ├── security.py             # 安全功能
│   ├── types.py                # 数据类型
│   └── utils.py                # 工具函数
├── workflow/                   # 工作流
│   ├── orchestrator.py         # 流程编排
│   ├── pipeline.py             # 阶段定义
│   └── state.py                # 状态管理
└── tests/                      # 测试套件
```

---

## 💡 智能体使用示例

```python
from core import agent_skill, SkillResult, AgentExecutionStatus
from core import ToolManager

@agent_skill(name="full_scan", category="recon")
def full_scan(state) -> SkillResult:
    """完整目标扫描"""
    manager = ToolManager(state)

    # 执行侦察
    recon_result = manager.run_recon(urls=[state.target.url])

    # 执行漏洞扫描
    vuln_result = manager.run_vulnerability_scan(
        urls=[state.target.url],
        severity=["critical", "high"]
    )

    return SkillResult(
        status=AgentExecutionStatus.SUCCESS,
        findings=recon_result["httpx"].findings + vuln_result.findings
    )
```

更多示例请参阅 [HERMES_GUIDE.md](HERMES_GUIDE.md)。

---

## 🔧 核心功能

### 数据关联引擎

自动提取并关联发现的值与端点：

- **支持 25+ 种数据模式**（JWT, API Keys, CSRF Tokens 等）
- **智能优先级排序**（CRITICAL > HIGH > NORMAL > LOW）
- **自动值-端点配对**

```python
from core import ValueLinkageEngine

engine = ValueLinkageEngine()
result = engine.process_state(state)
critical_pairs = engine.get_unconsumed_pairs(state, priority="CRITICAL")
```

### 批量处理

高效处理多个目标：

```bash
# 文件输入
python cli.py batch-run --target-file targets.txt --parallel 5

# CIDR 扫描
python cli.py batch-run --cidr 192.168.1.0/24

# 排除模式
python cli.py batch-run --targets https://a.com https://b.com --exclude admin test
```

### 报告生成

多格式报告输出：

```python
from reporting import ReportGenerator

gen = ReportGenerator()
files = gen.generate_all(state, output_dir=Path("./reports"))
```

---

## 🧪 测试

```bash
# 运行所有测试
python tests/test_agent_interface.py
python tests/test_value_patterns.py
python tests/test_security.py
```

---

## 📊 安全特性

- ✅ SSRF 防护（禁止内网扫描）
- ✅ 云元数据保护（禁止 169.254.169.254）
- ✅ 路径遍历防护
- ✅ AES-256-GCM 加密
- ✅ HMAC 签名验证
- ✅ 持久化速率限制
- ✅ 审计日志
- ✅ 数据脱敏

详见 [README_SECURITY.md](README_SECURITY.md)。

---

## 🤝 贡献

欢迎贡献！请先阅读安全指南和测试要求。

---

## 📜 许可证

MIT License

---

## 🙏 致谢

Built for [Hermes](https://github.com/anthropics/claude-code) — The Autonomous Security Agent

---

<div align="center">

**安全加固 | 智能体优化 | 实战就绪**

© 2026 Mastermind Bug Bounty

</div>
