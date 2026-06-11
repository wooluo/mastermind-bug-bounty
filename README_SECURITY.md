# Mastermind Bug Bounty - Security Hardened Edition

> **AI 驱动的自动化漏洞狩猎系统 — 安全加固版 v1.1**
>
> 从"工具"到"武器"的进化，现在更安全了。

---

## 🛡️ 安全加固亮点

### 实施的安全修复

基于全面的安全审计，本版本实施了以下关键安全加固：

#### 1. **输入验证框架** ✓
- **SSRF防护**: 禁止内网地址扫描（127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16）
- **云元数据防护**: 阻止对169.254.169.254的访问
- **协议限制**: 仅允许http/https，拒绝file://、data://等危险协议
- **路径遍历防护**: 验证hunt_dir，防止../等路径遍历攻击

#### 2. **加密与签名** ✓
- **AES-256-GCM加密**: 可选的状态文件加密
- **HMAC签名验证**: 所有状态文件都有完整性验证
- **密钥管理**: 安全的密钥生成和存储（~/.mastermind/.hmac_key）

#### 3. **速率限制增强** ✓
- **持久化存储**: 重启后速率限制状态保持
- **指数退避**: 超限后阻塞时间指数增长
- **独立标识**: 按目标URL分别限制

#### 4. **审计日志** ✓
- **完整追踪**: 记录所有关键操作
- **时间戳**: UTC时间戳审计
- **敏感信息脱敏**: 自动脱敏凭证等敏感信息

#### 5. **数据保护** ✓
- **大小限制**: 限制单个finding和总state大小
- **输入清理**: 自动删除null字节和危险控制字符
- **安全文件权限**: 敏感文件设置为0600权限

---

## ✅ 安全测试套件

运行完整的安全测试：

```bash
python tests/test_security.py
```

测试覆盖：
- ✓ 输入验证（17个测试用例）
- ✓ 路径遍历防护（6个测试用例）
- ✓ 字符串清理（5个测试用例）
- ✓ 加密解密（4个测试用例）
- ✓ HMAC签名（4个测试用例）
- ✓ 速率限制（3个测试用例）
- ✓ 端口安全（16个测试用例）
- ✓ 数据脱敏（5个测试用例）

**所有测试通过！**

---

## 🔐 安全验证演示

### 拒绝内网扫描
```bash
$ python cli.py run --target http://127.0.0.1
[Security] ✗ Validation failed: Loopback address '127.0.0.1' is not allowed
```

### 拒绝文件协议
```bash
$ python cli.py run --target file:///etc/passwd
[Security] ✗ Validation failed: URL scheme 'file' is not allowed
```

### 拒绝云元数据访问
```bash
$ python cli.py run --target http://169.254.169.254
[Security] ✗ Validation failed: Link-local address '169.254.169.254' is not allowed
```

### 拒绝路径遍历
```bash
$ python cli.py run --target https://example.com --hunt-dir ../../../etc
[Security] ✗ Validation failed: Directory traversal (..) not allowed
```

---

## 📊 安全审计结果对比

| 类别 | 原版问题 | 加固后状态 |
|------|----------|-----------|
| Critical | 8个问题 | ✓ 全部修复 |
| High | 10个问题 | ✓ 全部修复 |
| Medium | 6个问题 | ✓ 全部修复 |

---

## 🚀 使用方法

```bash
# 运行安全诊断
python cli.py security-check

# 扫描目标（自动启用所有安全保护）
python cli.py run --target https://example.com

# 查看状态
python cli.py status

# 列出所有阶段
python cli.py phases
```

---

## 🏗️ 项目结构

```
mastermind-bug-bounty/
├── cli.py                      # 安全加固的CLI入口
├── shared/
│   ├── security.py            # 安全核心模块（新增）
│   ├── types.py               # 数据类型
│   └── utils.py               # 工具函数
├── workflow/
│   ├── orchestrator.py        # 流程编排
│   ├── pipeline.py            # 阶段定义
│   └── state.py               # 状态管理（加固版）
├── tests/
│   └── test_security.py       # 安全测试套件（新增）
└── README_SECURITY.md         # 本文档
```

---

## 🔑 安全密钥管理

HMAC密钥自动生成并安全存储：
- 位置: `~/.mastermind/.hmac_key`
- 权限: 0600（仅所有者可读写）
- 长度: 32字节（256位）
- 用途: 状态文件完整性验证

如需重新生成密钥：
```bash
rm ~/.mastermind/.hmac_key
python cli.py security-check  # 将自动生成新密钥
```

---

## 📝 审计日志

审计日志位置：`<hunt-dir>/audit.log`

日志格式：
```json
{
  "timestamp": "2026-06-11T08:30:00Z",
  "event": "hunt_completed",
  "details": "...",
  "success": true,
  "pid": 12345
}
```

---

## 🛠️ 安全配置

### 调整速率限制

编辑 `shared/security.py` 中的默认值：
```python
DEFAULT_RATE_THRESHOLD: int = 10  # 每分钟请求数
DEFAULT_WINDOW_SECONDS: int = 60    # 时间窗口（秒）
```

### 调整大小限制

编辑 `shared/security.py` 中的限制：
```python
MAX_STATE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_WORKLOG_SIZE = 500 * 1024 * 1024  # 500MB
MAX_SINGLE_FINDING_SIZE = 1 * 1024 * 1024  # 1MB
```

---

## 🎯 下一步计划

- [ ] 添加身份认证机制
- [ ] 实现状态文件自动加密
- [ ] 添加沙箱隔离执行环境
- [ ] 集成静态安全扫描（SAST）
- [ ] 实现零信任架构

---

## 📜 许可证

MIT License

---

<div align="center">

**Built for hunters who don't stop at detection — and stay secure while doing it.**

安全加固 | 2026-06-11
</div>
