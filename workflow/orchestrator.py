"""
workflow/orchestrator.py — Orchestrator v4.0 (AI-Driven)

真正的智能编排引擎，执行实际的渗透测试逻辑。

核心功能：
- 真正执行每个 phase 的逻辑
- 连接 pipeline 定义和实际执行代码
- 实现依赖关系检查和 phase 间的数据流转
- 在关键决策点让 AI 介入
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from shared.types import (
    HuntState, HuntStatus, PhaseName, Target, Finding,
    FindingStatus, Severity, AgentState, WorklogEntry,
)
from shared.utils import now_iso, hunt_id
from shared.security import validate_target_url, validate_hunt_dir
from workflow.pipeline import get_phase, get_next_phase, PIPELINE
from workflow.state import (
    create_hunt, save_hunt, log_event, load_hunt,
    add_finding, get_pending_findings,
)
from core.agent_interface import AgentHooks, AgentContext, SkillResult, AgentExecutionStatus
from core.linkage import ValueLinkageEngine, check_linkage_completeness
from core.executors import ToolManager


class Orchestrator:
    """
    真正的智能编排引擎。

    负责：
    - 执行渗透测试的各个阶段
    - 调度 AI 智能体参与决策
    - 协调工具执行
    - 组合攻击链
    """

    def __init__(self, hunt_dir: str | Path = "./hunt-data"):
        """初始化编排器。"""
        self.hunt_dir = Path(hunt_dir)
        self.state: HuntState | None = None
        self.hooks = AgentHooks()
        self.tool_manager: ToolManager | None = None
        self.linkage_engine: ValueLinkageEngine | None = None

        # Phase 执行器映射
        self._phase_executors = {
            PhaseName.RECON: self._execute_recon,
            PhaseName.DEPENDENCY_SCAN: self._execute_dependency_scan,
            PhaseName.API_FUZZ: self._execute_api_fuzz,
            PhaseName.CRYPTO_ATTACK: self._execute_crypto_attack,
            PhaseName.BYPASS: self._execute_bypass,
            PhaseName.EXPLOIT: self._execute_exploit,
            PhaseName.AI_SECURITY: self._execute_ai_security,
        }

        # Phase 间数据传递
        self._phase_context = {}

    def run(
        self,
        target_url: str,
        scope: list[str] | None = None,
        resume: bool = False,
        ai_decision_fn: Callable | None = None,
    ) -> HuntState:
        """
        运行完整的渗透测试流程。

        Args:
            target_url: 目标 URL
            scope: 测试范围
            resume: 是否从上次中断处继续
            ai_decision_fn: AI 决策函数（可选），用于需要 AI 判断的决策点

        Returns:
            最终的 HuntState
        """
        # 验证输入
        validated_url = validate_target_url(target_url)
        validated_dir = validate_hunt_dir(self.hunt_dir)

        # 加载或创建状态
        if resume:
            self.state = load_hunt(validated_dir)
            if not self.state:
                raise ValueError("无法恢复状态：未找到现有的 hunt")
        else:
            self.state = create_hunt(validated_url, scope, validated_dir)

        # 初始化工具
        self.tool_manager = ToolManager(self.state)
        self.linkage_engine = ValueLinkageEngine()

        # 设置 AI 决策回调
        if ai_decision_fn:
            self.hooks.register('decision_point', ai_decision_fn)

        print(f"\n{'='*60}")
        print(f"开始渗透测试: {validated_url}")
        print(f"Hunt ID: {self.state.hunt_id}")
        print(f"{'='*60}\n")

        # 执行各个阶段
        current_phase = self.state.current_phase
        start_time = time.time()

        while current_phase:
            phase_def = get_phase(current_phase.value if isinstance(current_phase, str) else current_phase.value)

            if not phase_def:
                break

            # 检查依赖
            if not self._check_dependencies(phase_def):
                print(f"阶段 {current_phase.value} 的依赖未满足，跳过")
                current_phase = get_next_phase(current_phase.value)
                continue

            # 触发 pre_phase 钩子
            if not self.hooks.pre_phase(current_phase.value, self.state):
                print(f"阶段 {current_phase.value} 被 pre_phase 钩子阻止")
                break

            # 执行阶段
            print(f"\n{'─'*60}")
            print(f"阶段: {current_phase.value.upper()}")
            print(f"描述: {phase_def.description}")
            print(f"{'─'*60}\n")

            try:
                phase_result = self._execute_phase(current_phase)

                # 更新状态
                self.state.completed_phases.append(current_phase)
                self.state.current_phase = get_next_phase(current_phase.value) or current_phase
                self.state.touch()
                save_hunt(self.state, self.hunt_dir)

                # 触发 post_phase 钩子
                self.hooks.post_phase(current_phase.value, self.state)

                # 决策点：让 AI 决定是否继续
                if not self.hooks.should_proceed(self.state):
                    print(f"\n决策点：AI 决定停止执行")
                    break

                current_phase = get_next_phase(current_phase.value)

            except Exception as e:
                print(f"阶段 {current_phase.value} 执行失败: {e}")
                log_event(self.hunt_dir, "phase_error", "orchestrator", {"error": str(e)})
                break

        # 完成
        duration = time.time() - start_time
        self.state.status = HuntStatus.COMPLETED
        self.state.touch()
        save_hunt(self.state, self.hunt_dir)

        print(f"\n{'='*60}")
        print(f"渗透测试完成")
        print(f"耗时: {duration:.1f} 秒")
        print(f"发现: {len(self.state.findings)} 个漏洞")
        print(f"{'='*60}\n")

        return self.state

    def _execute_phase(self, phase: PhaseName) -> SkillResult:
        """执行单个阶段。"""
        executor = self._phase_executors.get(phase)
        if not executor:
            return SkillResult(
                status=AgentExecutionStatus.FAILED,
                error=f"阶段 {phase.value} 没有执行器"
            )

        return executor()

    def _check_dependencies(self, phase_def) -> bool:
        """检查阶段的依赖是否满足。"""
        for dep in phase_def.depends_on:
            dep_phase = PhaseName(dep) if isinstance(dep, str) else dep
            if dep_phase not in self.state.completed_phases:
                return False
        return True

    # -----------------------------------------------------------------------
    # Phase 执行器
    # -----------------------------------------------------------------------

    def _execute_recon(self) -> SkillResult:
        """执行侦察阶段。"""
        from core.ai_modules import JSAnalyzer, EndpointPrioritizer

        context = AgentContext(self.state, agent_id="recon_agent")

        print("  [1/4] 端点发现...")
        # 使用 httpx 发现端点
        if self.tool_manager.is_available("httpx"):
            httpx = self.tool_manager.get_executor("httpx")
            result = httpx.run(urls=[self.state.target.url])

            # 更新状态
            if result.parsed_data.get("endpoints"):
                discovered = [e["url"] for e in result.parsed_data["endpoints"]]
                self.state.target.endpoints_discovered.extend(discovered)
                # 去重
                self.state.target.endpoints_discovered = list(set(self.state.target.endpoints_discovered))

                # 添加发现
                self.state.findings.extend(result.findings)

                print(f"    发现 {len(discovered)} 个端点")

        print("  [2/4] JS 文件收集...")
        # 收集 JS 文件
        js_analyzer = JSAnalyzer(self.state)
        js_files = js_analyzer.collect_js_files()

        if js_files:
            self.state.target.js_files = js_files
            print(f"    收集 {len(js_files)} 个 JS 文件")

        print("  [3/4] JS 分析...")
        # 分析 JS 文件
        if js_files:
            js_analysis = js_analyzer.analyze_all()

            # 提取的端点
            if js_analysis.get("endpoints"):
                self.state.target.endpoints_discovered.extend(js_analysis["endpoints"])
                print(f"    从 JS 提取 {len(js_analysis['endpoints'])} 个端点")

            # 提取的敏感数据
            if js_analysis.get("secrets"):
                print(f"    发现 {len(js_analysis['secrets'])} 个潜在密钥")

            # 更新技术栈
            if js_analysis.get("technologies"):
                self.state.target.tech_stack.update(js_analysis["technologies"])
                print(f"    识别技术栈: {', '.join(js_analysis['technologies'].keys())}")

        print("  [4/4] 端点优先级排序...")
        # 对端点进行优先级排序
        prioritizer = EndpointPrioritizer(self.state)
        high_value_endpoints = prioritizer.get_high_value_targets()

        print(f"    高价值端点: {len(high_value_endpoints)}")

        # 保存到上下文
        self._phase_context["recon"] = {
            "endpoints_discovered": len(self.state.target.endpoints_discovered),
            "js_files_analyzed": len(js_files),
            "high_value_targets": len(high_value_endpoints),
        }

        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            data=self._phase_context["recon"]
        )

    def _execute_dependency_scan(self) -> SkillResult:
        """执行依赖扫描阶段（CVE 检测）。"""
        from core.ai_modules import VulnerabilityMatcher

        print("  [1/2] 检测技术栈版本...")
        # 检测使用的技术和版本
        versions = {}
        for tech, version in self.state.target.tech_stack.items():
            if version:
                versions[tech] = version
                print(f"    {tech}: {version}")

        print("  [2/2] 匹配 CVE...")
        # 匹配已知 CVE
        vuln_matcher = VulnerabilityMatcher(self.state)
        cve_findings = vuln_matcher.match_cves(versions)

        for finding in cve_findings:
            self.state.add_finding(finding)
            print(f"    发现: {finding.vuln_class} ({finding.severity.value})")

        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            data={"cves_found": len(cve_findings)}
        )

    def _execute_api_fuzz(self) -> SkillResult:
        """执行 API 模糊测试阶段。"""
        from core.ai_modules import FuzzStrategyGenerator, PayloadGenerator

        print("  [1/4] 生成 Fuzz 策略...")
        # 生成 fuzz 策略
        strategy_gen = FuzzStrategyGenerator(self.state)
        strategies = strategy_gen.generate_strategies()

        print(f"    生成 {len(strategies)} 个 fuzz 策略")

        print("  [2/4] 关联数据值...")
        # 运行数据关联引擎
        linkage_result = self.linkage_engine.process_state(self.state)
        pairs = self.linkage_engine.get_unconsumed_pairs(
            self.state, priority="CRITICAL", limit=50
        )

        print(f"    生成 {len(pairs)} 个测试对")

        print("  [3/4] 生成 Payload...")
        # 生成测试 payload
        payload_gen = PayloadGenerator(self.state)
        payloads = payload_gen.generate_for_pairs(pairs)

        print(f"    生成 {len(payloads)} 个 payload")

        print("  [4/4] 执行 Fuzz...")
        # 执行模糊测试（这里简化，实际应该用 ffuf）
        findings = []
        for payload in payloads[:10]:  # 限制数量
            context = AgentContext(self.state)
            result = context.executor.http_request(
                payload["url"],
                method=payload.get("method", "GET"),
                params=payload.get("params")
            )

            if result.status == AgentExecutionStatus.SUCCESS:
                # 分析响应
                if self._analyze_fuzz_response(result.data, payload):
                    finding = Finding(
                        id=hunt_id()[:8],
                        vuln_class="api_vulnerability",
                        target_url=payload["url"],
                        severity=Severity.MEDIUM,
                        evidence=f"Fuzz payload: {payload.get('description', '')}",
                        timestamp=now_iso(),
                    )
                    findings.append(finding)
                    self.state.add_finding(finding)
                    print(f"    发现潜在漏洞: {payload['url']}")

        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            findings=findings,
            data={"findings": len(findings)}
        )

    def _execute_crypto_attack(self) -> SkillResult:
        """执行加密攻击阶段。"""
        from core.ai_modules import CryptoAttacker

        print("  [1/3] 检测加密机制...")
        crypto_attacker = CryptoAttacker(self.state)

        # 检测 JWT
        jwt_findings = crypto_attacker.attack_jwt()
        for finding in jwt_findings:
            self.state.add_finding(finding)
            print(f"    发现 JWT 问题: {finding.vuln_class}")

        # 检测弱加密
        weak_crypto = crypto_attacker.detect_weak_crypto()
        for finding in weak_crypto:
            self.state.add_finding(finding)
            print(f"    发现弱加密: {finding.vuln_class}")

        print("  [2/3] 尝试密钥攻击...")
        # 尝试已发现的密钥
        from core.linkage import get_next_unconsumed_pair
        pair = get_next_unconsumed_pair(self.state)
        if pair:
            print(f"    使用发现的密钥测试: {pair.value[:20]}...")

        print("  [3/3] 证书分析...")
        # 分析证书（简化）
        if "https" in self.state.target.url:
            cert_info = crypto_attacker.analyze_certificate(self.state.target.url)
            if cert_info.get("issues"):
                for issue in cert_info["issues"]:
                    print(f"    证书问题: {issue}")

        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            findings=jwt_findings + weak_crypto
        )

    def _execute_bypass(self) -> SkillResult:
        """执行绕过阶段。"""
        from core.ai_modules import BypassEngine

        print("  [1/3] 生成绕过策略...")
        bypass_engine = BypassEngine(self.state)
        strategies = bypass_engine.generate_bypass_strategies()

        print(f"    生成 {len(strategies)} 个绕过策略")

        print("  [2/3] 测试 403 绕过...")
        # 测试 403 绕过
        for endpoint in self.state.target.endpoints_discovered[:5]:
            bypass_methods = bypass_engine.get_403_bypass_methods(endpoint)
            for method in bypass_methods:
                context = AgentContext(self.state)
                result = context.executor.http_request(
                    method["url"],
                    headers=method.get("headers")
                )

                if result.status == AgentExecutionStatus.SUCCESS:
                    if result.data.get("status_code") == 200:
                        finding = Finding(
                            id=hunt_id()[:8],
                            vuln_class="access_control_bypass",
                            target_url=endpoint,
                            severity=Severity.HIGH,
                            evidence=f"成功绕过: {method.get('description', '')}",
                            timestamp=now_iso(),
                        )
                        self.state.add_finding(finding)
                        print(f"    绕过成功: {endpoint}")

        print("  [3/3] 测试认证绕过...")
        # 测试认证绕过
        auth_endpoints = [e for e in self.state.target.endpoints_discovered
                          if "auth" in e.lower() or "login" in e.lower()]
        for endpoint in auth_endpoints[:3]:
            bypass_methods = bypass_engine.get_auth_bypass_methods(endpoint)
            for method in bypass_methods:
                context = AgentContext(self.state)
                result = context.executor.http_request(
                    method["url"],
                    method=method.get("method", "POST"),
                    data=method.get("data")
                )

                # 分析结果
                ...

        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            data={"strategies_tested": len(strategies)}
        )

    def _execute_exploit(self) -> SkillResult:
        """执行漏洞利用阶段。"""
        from core.ai_modules import AttackChainComposer, FindingValidator

        print("  [1/3] 验证发现...")
        # 验证所有发现的漏洞
        validator = FindingValidator(self.state)
        validated_findings = []

        for finding in self.state.findings:
            if finding.status in [FindingStatus.DETECTED, FindingStatus.TRIAGE_PENDING]:
                validation_result = validator.validate(finding)
                finding.confidence = validation_result["confidence"]
                finding.status = FindingStatus.TRIAGE_APPROVED if validation_result["valid"] else FindingStatus.TRIAGE_REJECTED

                if validation_result["valid"]:
                    validated_findings.append(finding)
                    print(f"    确认: {finding.vuln_class}")

        print("  [2/3] 组合攻击链...")
        # 组合攻击链
        chain_composer = AttackChainComposer(self.state)
        attack_chains = chain_composer.compose_chains(validated_findings)

        print(f"    组合 {len(attack_chains)} 条攻击链")

        for chain in attack_chains:
            print(f"    攻击链: {' → '.join([f.v.vuln_class for f in chain])}")
            # 创建组合发现
            if len(chain) > 1:
                chain_finding = Finding(
                    id=hunt_id()[:8],
                    vuln_class="combined_attack_chain",
                    target_url=chain[0].target_url,
                    severity=Severity.HIGH,
                    evidence=f"组合攻击链: {len(chain)} 个漏洞",
                    poc_steps=[f"1. 利用 {f.vuln_class}" for f in chain],
                    timestamp=now_iso(),
                )
                self.state.add_finding(chain_finding)

        print("  [3/3] 生成 POC...")
        # 为高严重性发现生成 POC
        for finding in validated_findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                if not finding.poc_steps:
                    finding.poc_steps = self._generate_poc_steps(finding)
                    print(f"    生成 POC: {finding.vuln_class}")

        return SkillResult(
            status=AgentExecutionStatus.SUCCESS,
            findings=validated_findings,
            data={"chains_composed": len(attack_chains)}
        )

    def _execute_ai_security(self) -> SkillResult:
        """执行 AI 安全测试阶段（可选）。"""
        print("  [1/1] AI 安全测试...")
        # 测试 prompt injection、jailbreak 等
        # 这里是占位符，实际需要更复杂的逻辑

        return SkillResult(status=AgentExecutionStatus.SUCCESS)

    # -----------------------------------------------------------------------
    # 辅助方法
    # -----------------------------------------------------------------------

    def _analyze_fuzz_response(self, response: dict, payload: dict) -> bool:
        """分析 fuzz 响应，判断是否可能存在漏洞。"""
        # 检查异常响应
        status_code = response.get("status_code", 0)
        body = response.get("body", "")

        # 5xx 错误可能意味着漏洞
        if status_code >= 500:
            return True

        # 错误消息可能意味着注入成功
        error_indicators = ["sql", "mysql", "postgresql", "oracle", "syntax error",
                           "exception", "stack trace", "debug"]
        if any(indicator in body.lower() for indicator in error_indicators):
            return True

        # 时间差异可能意味着盲注
        # （这里简化，实际需要测量响应时间）

        return False

    def _generate_poc_steps(self, finding: Finding) -> list[str]:
        """为发现生成 POC 步骤。"""
        steps = [
            f"1. 目标: {finding.target_url}",
            f"2. 漏洞类型: {finding.vuln_class}",
        ]

        if finding.evidence:
            steps.append(f"3. 证据: {finding.evidence[:100]}")

        steps.append("4. 验证步骤（需手动确认）")

        return steps


# -----------------------------------------------------------------------
# 便捷函数
# -----------------------------------------------------------------------

def create_orchestrator(hunt_dir: str = "./hunt-data") -> Orchestrator:
    """创建编排器实例。"""
    return Orchestrator(hunt_dir=hunt_dir)
