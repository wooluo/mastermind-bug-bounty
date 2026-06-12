"""
core/ai_modules/js_analyzer.py — JavaScript 智能分析模块

真正需要 AI 参与的模块：

功能：
- 智能 JS 文件分析
- 端点提取和分类
- 敏感数据识别
- API 调用模式分析
- 判断哪些端点值得测试

这不是简单的正则匹配，而是需要理解代码上下文。
"""

from __future__ import annotations

import re
import json
from urllib.parse import urlparse, urljoin
from pathlib import Path
from typing import Any, List, Dict, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass

from shared.types import HuntState
from shared.utils import now_iso
from shared.security import validate_target_url


@dataclass
class JSEndpoint:
    """从 JS 中提取的端点信息。"""
    url: str
    method: str = "GET"
    params: List[str] = None
    requires_auth: bool = False
    content_type: str = "application/json"
    source_file: str = ""
    line_number: int = 0
    priority: str = "NORMAL"  # CRITICAL, HIGH, NORMAL, LOW


@dataclass
class JSSecret:
    """从 JS 中提取的敏感信息。"""
    type: str  # api_key, jwt, secret, etc.
    value: str
    context: str = ""
    source_file: str = ""
    line_number: int = 0
    confidence: float = 0.0


@dataclass
class APICall:
    """API 调用模式分析。"""
    function_name: str
    endpoints: List[str]
    headers: Dict[str, str] = None
    auth_required: bool = False
    error_handling: bool = False
    source_file: str = ""


class JSAnalyzer:
    """
    JavaScript 智能分析器。

    不是简单的正则匹配，而是：
    - 理解常见的 JS 框架模式（React, Vue, Angular）
    - 分析 API 调用的上下文
    - 识别敏感操作
    - 评估端点的攻击价值
    """

    # 常见的 API 调用模式
    API_PATTERNS = {
        'fetch': [
            r'fetch\(["\']([^"\']+)["\']',
            r'fetch\(`([^`]+)`',
            r'fetch\(\s*["\']([^"\']+)["\']',
        ],
        'axios': [
            r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'axios\(["\']([^"\']+)["\']',
        ],
        'xhr': [
            r'xhr\.open\(["\']([A-Z]+)["\'],\s*["\']([^"\']+)["\']',
            r'\.open\(["\']([A-Z]+)["\'],\s*["\']([^"\']+)["\']',
        ],
    }

    # 敏感操作关键词
    SENSITIVE_OPERATIONS = {
        'admin', 'delete', 'update', 'modify', 'create', 'upload',
        'download', 'export', 'import', 'payment', 'checkout',
        'transfer', 'password', 'login', 'register', 'auth',
    }

    # 认证相关模式
    AUTH_PATTERNS = [
        r'["\']authorization["\']\s*:\s*["\']([^"\']+)["\']',
        r'["\']token["\']\s*:\s*["\']([^"\']+)["\']',
        r'Bearer\s+([A-Za-z0-9\-._~+/]+)',
    ]

    def __init__(self, state: HuntState):
        """初始化 JS 分析器。"""
        self.state = state
        self.js_files: List[str] = []
        self.endpoints: List[JSEndpoint] = []
        self.secrets: List[JSSecret] = []
        self.api_calls: List[APICall] = []
        self.technologies: Dict[str, str] = {}

    def collect_js_files(self) -> List[str]:
        """
        收集目标的所有 JS 文件。

        Returns:
            发现的 JS 文件路径列表
        """
        import subprocess

        target = self.state.target.url
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        js_files = []

        # 方法 1: 从 httpx 结果中获取
        if hasattr(self.state, 'target') and self.state.target.endpoints_discovered:
            for endpoint in self.state.target.endpoints_discovered:
                if endpoint.endswith('.js'):
                    js_files.append(endpoint)
                elif '/static/js/' in endpoint or '/assets/js/' in endpoint:
                    js_files.append(endpoint)

        # 方法 2: 尝试常见的 JS 路径
        common_paths = [
            '/static/js/main.js',
            '/static/js/app.js',
            '/static/js/bundle.js',
            '/assets/js/main.js',
            '/js/app.js',
            '/app.js',
            '/main.js',
        ]

        for path in common_paths:
            url = urljoin(base_url, path)
            js_files.append(url)

        # 方法 3: 使用 httpx 发现（如果有）
        try:
            result = subprocess.run(
                ['httpx', '-u', base_url, '-silent', '-json',
                 '-match-regex', '\\.js$'],
                capture_output=True,
                timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.decode().strip().split('\n'):
                    try:
                        data = json.loads(line)
                        if 'url' in data:
                            js_files.append(data['url'])
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

        # 去重
        js_files = list(set(js_files))
        self.js_files = js_files

        return js_files

    def analyze_all(self) -> Dict[str, Any]:
        """
        分析所有 JS 文件。

        Returns:
            分析结果字典
        """
        results = {
            'endpoints': [],
            'secrets': [],
            'api_calls': [],
            'technologies': {},
            'stats': {
                'total_files': len(self.js_files),
                'analyzed_files': 0,
                'failed_files': 0,
            }
        }

        for js_file in self.js_files:
            try:
                file_result = self._analyze_file(js_file)
                results['endpoints'].extend(file_result['endpoints'])
                results['secrets'].extend(file_result['secrets'])
                results['api_calls'].extend(file_result['api_calls'])
                results['technologies'].update(file_result['technologies'])
                results['stats']['analyzed_files'] += 1
            except Exception as e:
                results['stats']['failed_files'] += 1

        # 去重端点
        seen = set()
        unique_endpoints = []
        for ep in results['endpoints']:
            if ep['url'] not in seen:
                seen.add(ep['url'])
                unique_endpoints.append(ep)
        results['endpoints'] = unique_endpoints

        # 保存到状态
        self.endpoints = results['endpoints']
        self.secrets = results['secrets']
        self.api_calls = results['api_calls']
        self.technologies = results['technologies']

        return results

    def _analyze_file(self, js_url: str) -> Dict[str, Any]:
        """分析单个 JS 文件。"""
        import subprocess

        # 获取 JS 内容
        try:
            result = subprocess.run(
                ['curl', '-s', '-L', '--max-time', '30', js_url],
                capture_output=True,
                timeout=30
            )
            if result.returncode != 0:
                return {'endpoints': [], 'secrets': [], 'api_calls': [], 'technologies': {}}

            content = result.stdout.decode('utf-8', errors='ignore')
        except Exception:
            return {'endpoints': [], 'secrets': [], 'api_calls': [], 'technologies': {}}

        results = {
            'endpoints': self._extract_endpoints(content, js_url),
            'secrets': self._extract_secrets(content, js_url),
            'api_calls': self._analyze_api_calls(content, js_url),
            'technologies': self._detect_technologies(content),
        }

        return results

    def _extract_endpoints(self, content: str, source_file: str) -> List[Dict]:
        """
        提取端点信息。

        不仅仅是正则匹配，还要：
        - 识别 HTTP 方法
        - 提取参数
        - 判断是否需要认证
        - 评估攻击价值
        """
        endpoints = []

        # 提取 API 调用
        for api_type, patterns in self.API_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    try:
                        if api_type == 'fetch':
                            # fetch(url)
                            url = match.group(1) if len(match.groups()) > 0 else match.group(0)
                            method = self._infer_method_from_context(content, match.start())
                        elif api_type == 'axios':
                            # axios.method(url) or axios(url, config)
                            if 'get' in match.group(0).lower():
                                method = 'GET'
                            elif 'post' in match.group(0).lower():
                                method = 'POST'
                            elif 'delete' in match.group(0).lower():
                                method = 'DELETE'
                            else:
                                method = 'POST'
                            url = match.group(2) if len(match.groups()) > 1 else match.group(1)
                        elif api_type == 'xhr':
                            method = match.group(1)
                            url = match.group(2)
                        else:
                            continue

                        # 清理 URL
                        url = self._clean_url(url, source_file)

                        # 提取参数
                        params = self._extract_params(url)

                        # 判断是否需要认证
                        requires_auth = self._requires_auth(content, match.start())

                        # 评估优先级
                        priority = self._assess_endpoint_priority(url, method, params, requires_auth)

                        endpoints.append({
                            'url': url,
                            'method': method,
                            'params': params,
                            'requires_auth': requires_auth,
                            'priority': priority,
                            'source_file': source_file,
                        })

                    except (IndexError, AttributeError):
                        continue

        return endpoints

    def _infer_method_from_context(self, content: str, pos: int) -> str:
        """从上下文推断 HTTP 方法。"""
        # 查找附近的代码
        context_start = max(0, pos - 200)
        context = content[context_start:pos + 100]

        # 寻找方法提示
        if 'POST' in context or 'post' in context.lower():
            return 'POST'
        elif 'PUT' in context or 'put' in context.lower():
            return 'PUT'
        elif 'DELETE' in context or 'delete' in context.lower():
            return 'DELETE'
        elif 'PATCH' in context or 'patch' in context.lower():
            return 'PATCH'

        return 'GET'

    def _clean_url(self, url: str, source_file: str) -> str:
        """清理和标准化 URL。"""
        # 移除模板字符串语法
        url = re.sub(r'\$\{[^}]+\}', '{param}', url)

        # 处理相对路径
        if url.startswith('/') or url.startswith('./'):
            base = urlparse(source_file)
            base_url = f"{base.scheme}://{base.netloc}"
            url = urljoin(base_url, url)

        return url

    def _extract_params(self, url: str) -> List[str]:
        """从 URL 或查询字符串中提取参数。"""
        params = []

        # 路径参数
        path_params = re.findall(r'\{([^}]+)\}', url)
        params.extend(path_params)

        # 查询参数
        parsed = urlparse(url)
        if parsed.query:
            query_params = parsed.query.split('&')
            for param in query_params:
                if '=' in param:
                    params.append(param.split('=')[0])
                else:
                    params.append(param)

        return params

    def _requires_auth(self, content: str, pos: int) -> bool:
        """判断 API 调用是否需要认证。"""
        # 检查附近的认证相关代码
        context_start = max(0, pos - 300)
        context_end = min(len(content), pos + 200)
        context = content[context_start:context_end].lower()

        auth_indicators = [
            'authorization', 'auth', 'token', 'bearer',
            'credentials', 'session', 'cookie'
        ]

        return any(indicator in context for indicator in auth_indicators)

    def _assess_endpoint_priority(
        self,
        url: str,
        method: str,
        params: List[str],
        requires_auth: bool
    ) -> str:
        """
        评估端点的攻击价值（优先级）。

        这需要 AI 判断：
        - 管理功能 > 普通功能
        - 写操作 > 读操作
        - 需要认证 > 公开接口
        - 敏感参数 > 普通参数
        """
        priority_score = 0

        # URL 模式分析
        url_lower = url.lower()

        # 高价值模式
        if any(pattern in url_lower for pattern in ['admin', 'manage', 'config', 'settings']):
            priority_score += 3
        elif any(pattern in url_lower for pattern in ['user', 'profile', 'account']):
            priority_score += 2
        elif any(pattern in url_lower for pattern in ['api', 'data', 'export']):
            priority_score += 1

        # 方法分析
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            priority_score += 2
        elif method == 'GET':
            priority_score += 0

        # 认证要求
        if requires_auth:
            priority_score += 2

        # 参数分析
        sensitive_params = ['password', 'token', 'secret', 'key', 'credit', 'ssn']
        if any(param in str(params).lower() for param in sensitive_params):
            priority_score += 3

        # 确定优先级
        if priority_score >= 6:
            return 'CRITICAL'
        elif priority_score >= 4:
            return 'HIGH'
        elif priority_score >= 2:
            return 'NORMAL'
        else:
            return 'LOW'

    def _extract_secrets(self, content: str, source_file: str) -> List[Dict]:
        """提取敏感信息。"""
        secrets = []

        # 使用 value_linkage 中的模式，但增加上下文分析
        from core.linkage.value_linkage import VALUE_PATTERNS

        for secret_type, patterns in VALUE_PATTERNS.items():
            if secret_type in ['internal_ip', 'phone', 'base64_secret']:
                continue  # 跳过不太重要的

            for pattern in patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    try:
                        value = match.group(1) if match.groups() else match.group(0)
                        if len(value) < 4:
                            continue

                        # 分析上下文判断是否是真正的密钥
                        context_start = max(0, match.start() - 100)
                        context_end = min(len(content), match.end() + 100)
                        context = content[context_start:context_end]

                        # 检查是否在注释或示例代码中
                        if self._is_in_comment_or_example(context, match.start() - context_start):
                            continue

                        # 评估置信度
                        confidence = self._assess_secret_confidence(value, context, secret_type)

                        secrets.append({
                            'type': secret_type,
                            'value': value,
                            'context': context[:100],
                            'source_file': source_file,
                            'confidence': confidence,
                        })

                    except (IndexError, AttributeError):
                        continue

        return secrets

    def _is_in_comment_or_example(self, context: str, offset: int) -> bool:
        """判断匹配是否在注释或示例代码中。"""
        # 简化检查：查看上下文中是否有注释标记
        lines = context.split('\n')
        for line in lines:
            if '//' in line or '#' in line or 'example' in line.lower():
                if offset > context.find(line):
                    return True
        return False

    def _assess_secret_confidence(self, value: str, context: str, secret_type: str) -> float:
        """评估密钥的置信度。"""
        confidence = 0.5  # 基础置信度

        # 高置信度指标
        if secret_type in ['jwt', 'api_key']:
            if value.startswith('eyJ') and secret_type == 'jwt':
                confidence += 0.3  # JWT 格式正确
            elif len(value) > 20 and secret_type == 'api_key':
                confidence += 0.3  # API 足够长

        # 上下文指标
        context_lower = context.lower()

        # 变量名包含 'secret', 'key', 'token' 等
        if any(keyword in context_lower for keyword in ['secret', 'private', 'token', 'key']):
            confidence += 0.1

        # 在赋值语句中
        if '=' in context and value in context.split('=')[-1]:
            confidence += 0.1

        return min(confidence, 1.0)

    def _analyze_api_calls(self, content: str, source_file: str) -> List[Dict]:
        """分析 API 调用模式。"""
        api_calls = []

        # 分析 fetch 调用
        fetch_matches = re.finditer(r'fetch\([^)]+\)', content)
        for match in fetch_matches:
            call_content = match.group(0)

            api_call = {
                'function_name': 'fetch',
                'endpoints': [],
                'headers': {},
                'auth_required': False,
                'error_handling': False,
                'source_file': source_file,
            }

            # 提取端点
            url_match = re.search(r'["\']([^"\']+)["\']', call_content)
            if url_match:
                api_call['endpoints'].append(url_match.group(1))

            # 检查认证
            for pattern in self.AUTH_PATTERNS:
                if re.search(pattern, call_content):
                    api_call['auth_required'] = True
                    break

            # 检查错误处理
            if '.catch' in content[match.end():match.end()+50] or 'try' in content[max(0, match.start()-50):match.start()]:
                api_call['error_handling'] = True

            if api_call['endpoints']:
                api_calls.append(api_call)

        return api_calls

    def _detect_technologies(self, content: str) -> Dict[str, str]:
        """检测使用的技术栈。"""
        technologies = {}

        # 前端框架
        if 'from react' in content or 'import React' in content or 'React.' in content:
            technologies['react'] = 'detected'
        if 'from vue' in content or 'Vue.' in content:
            technologies['vue'] = 'detected'
        if 'from angular' in content or 'ng-' in content:
            technologies['angular'] = 'detected'

        # 工具库
        if 'axios' in content:
            technologies['axios'] = 'detected'
        if 'jquery' in content or '$(' in content:
            technologies['jquery'] = 'detected'
        if 'lodash' in content or '_' in content:
            technologies['lodash'] = 'detected'

        # UI 库
        if 'material-ui' in content or '@mui/' in content:
            technologies['material-ui'] = 'detected'
        if 'antd' in content:
            technologies['ant-design'] = 'detected'
        if 'bootstrap' in content:
            technologies['bootstrap'] = 'detected'

        # 状态管理
        if 'redux' in content:
            technologies['redux'] = 'detected'
        if 'mobx' in content:
            technologies['mobx'] = 'detected'

        return technologies
