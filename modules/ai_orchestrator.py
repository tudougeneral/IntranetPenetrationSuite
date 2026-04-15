#!/usr/bin/env python3
"""
AI 智能调度器 - 集成AI能力自动调用渗透测试工具
"""

import json
import os
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import requests
from .kali_tools_integration import KaliToolsManager, AIKaliOrchestrator, ToolType


@dataclass
class ScanContext:
    """扫描上下文"""
    target: str
    target_type: str
    discovered_services: List[Dict] = None
    discovered_vulns: List[Dict] = None
    scan_phase: str = "initial"
    confidence_level: float = 0.0
    
    def __post_init__(self):
        if self.discovered_services is None:
            self.discovered_services = []
        if self.discovered_vulns is None:
            self.discovered_vulns = []


@dataclass
class AIAction:
    """AI决策动作"""
    action_type: str  # 'run_tool', 'analyze', 'report', 'stop'
    tool_name: Optional[str] = None
    parameters: Dict = None
    reason: str = ""
    confidence: float = 0.0
    expected_outcome: str = ""
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


class AIAnalyzer:
    """AI分析器 - 使用AI分析扫描结果并做出决策"""
    
    def __init__(self, api_key: str = None, api_base: str = "https://api.deepseek.com/v1"):
        self.api_key = api_key or os.getenv("AI_API_KEY")
        self.api_base = api_base
        self.enabled = self.api_key is not None
        self.analysis_history = []
        
    def analyze_target(self, target: str, context: ScanContext = None) -> Dict:
        """使用AI分析目标"""
        if not self.enabled:
            return self._fallback_analysis(target)
        
        prompt = f"""
你是一位专业的渗透测试专家AI助手。请分析以下目标并制定扫描策略。

目标: {target}
目标类型: {context.target_type if context else 'unknown'}

请提供以下信息（JSON格式）：
{{
    "target_classification": "目标分类（web应用/网络服务/API等）",
    "priority_vulnerabilities": ["可能存在的漏洞类型列表"],
    "recommended_tools": ["推荐的工具列表"],
    "scan_strategy": "扫描策略描述",
    "risk_level": "风险等级（low/medium/high/critical）",
    "special_considerations": "特殊注意事项"
}}
"""
        
        try:
            response = self._call_ai_api(prompt)
            return json.loads(response)
        except Exception as e:
            print(f"[AI] 分析失败，使用备用分析: {e}")
            return self._fallback_analysis(target)
    
    def analyze_results(self, tool_name: str, results: Dict, 
                       context: ScanContext) -> AIAction:
        """分析工具执行结果并决定下一步动作"""
        if not self.enabled:
            return self._fallback_decision(tool_name, results, context)
        
        prompt = f"""
你是一位专业的渗透测试专家AI助手。请分析以下扫描结果并决定下一步行动。

当前目标: {context.target}
扫描阶段: {context.scan_phase}
已执行工具: {tool_name}

工具执行结果:
```json
{json.dumps(results, indent=2, ensure_ascii=False)}
```

已发现的服务:
```json
{json.dumps(context.discovered_services, indent=2, ensure_ascii=False)}
```

已发现的漏洞:
```json
{json.dumps(context.discovered_vulns, indent=2, ensure_ascii=False)}
```

请决定下一步行动（JSON格式）：
{{
    "action_type": "run_tool/analyze/report/stop",
    "tool_name": "要使用的工具名称（如果是run_tool）",
    "parameters": {{"自定义参数": "值"}},
    "reason": "决策原因",
    "confidence": 0.95,
    "expected_outcome": "预期结果"
}}
"""
        
        try:
            response = self._call_ai_api(prompt)
            data = json.loads(response)
            return AIAction(**data)
        except Exception as e:
            print(f"[AI] 决策失败，使用备用决策: {e}")
            return self._fallback_decision(tool_name, results, context)
    
    def generate_exploit_suggestion(self, vuln: Dict, 
                                   context: ScanContext) -> str:
        """生成漏洞利用建议"""
        if not self.enabled:
            return self._fallback_exploit_suggestion(vuln)
        
        prompt = f"""
你是一位专业的渗透测试专家。请为以下漏洞提供利用建议。

目标: {context.target}
漏洞类型: {vuln.get('type', 'Unknown')}
漏洞详情: {json.dumps(vuln, indent=2, ensure_ascii=False)}

请提供：
1. 漏洞验证方法
2. 利用步骤
3. 可能的影响
4. 修复建议

请以Markdown格式返回。
"""
        
        try:
            return self._call_ai_api(prompt)
        except:
            return self._fallback_exploit_suggestion(vuln)
    
    def _call_ai_api(self, prompt: str) -> str:
        """调用AI API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "deepseek-chat",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 2000
        }
        
        response = requests.post(
            f"{self.api_base}/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            content = result['choices'][0]['message']['content']
            # 提取JSON部分
            json_match = re.search(r'```json\n(.*?)\n```', content, re.DOTALL)
            if json_match:
                return json_match.group(1)
            return content
        else:
            raise Exception(f"API调用失败: {response.status_code}")
    
    def _fallback_analysis(self, target: str) -> Dict:
        """备用目标分析"""
        if target.startswith('http'):
            return {
                "target_classification": "Web应用",
                "priority_vulnerabilities": ["XSS", "SQL注入", "CSRF", "信息泄露"],
                "recommended_tools": ["nikto", "dirb", "sqlmap"],
                "scan_strategy": "先进行Web扫描，然后根据发现进行深度测试",
                "risk_level": "medium",
                "special_considerations": "注意扫描频率，避免被封禁"
            }
        else:
            return {
                "target_classification": "网络服务",
                "priority_vulnerabilities": ["未授权访问", "弱口令", "服务漏洞"],
                "recommended_tools": ["nmap", "masscan"],
                "scan_strategy": "先进行端口扫描，识别服务后再深度测试",
                "risk_level": "medium",
                "special_considerations": "注意扫描速度，避免触发IDS/IPS"
            }
    
    def _fallback_decision(self, tool_name: str, results: Dict, 
                          context: ScanContext) -> AIAction:
        """备用决策逻辑"""
        # 根据已执行的工具和结果决定下一步
        executed_tools = [v.get('tool') for v in context.discovered_vulns]
        
        # 如果刚执行了nmap且发现了Web端口
        if tool_name == 'nmap':
            open_ports = results.get('open_ports', [])
            web_ports = [80, 443, 8080, 8443]
            has_web = any(p['port'] in web_ports for p in open_ports)
            
            if has_web and 'nikto' not in executed_tools:
                return AIAction(
                    action_type='run_tool',
                    tool_name='nikto',
                    parameters={'target': context.target},
                    reason='Nmap发现Web服务，使用Nikto进行Web漏洞扫描',
                    confidence=0.9,
                    expected_outcome='发现Web应用漏洞'
                )
        
        # 如果刚执行了nikto
        if tool_name == 'nikto':
            findings = results.get('findings', [])
            if findings and 'dirb' not in executed_tools:
                return AIAction(
                    action_type='run_tool',
                    tool_name='dirb',
                    parameters={'target': context.target},
                    reason='Nikto完成扫描，使用Dirb进行目录爆破',
                    confidence=0.8,
                    expected_outcome='发现隐藏目录和文件'
                )
        
        # 默认停止
        return AIAction(
            action_type='stop',
            reason='完成基础扫描',
            confidence=0.7,
            expected_outcome='扫描完成'
        )
    
    def _fallback_exploit_suggestion(self, vuln: Dict) -> str:
        """备用利用建议"""
        vuln_type = vuln.get('type', 'Unknown')
        
        suggestions = {
            'XSS': """
## XSS漏洞利用建议

### 验证方法
1. 在输入点注入 `<script>alert(1)</script>`
2. 观察是否弹出alert对话框

### 利用步骤
1. 构造恶意Payload
2. 发送给目标用户
3. 窃取Cookie或会话令牌

### 修复建议
- 对所有输出进行HTML实体编码
- 使用Content-Security-Policy
""",
            'SQL Injection': """
## SQL注入漏洞利用建议

### 验证方法
1. 在参数后添加单引号 `'`
2. 观察是否出现SQL错误

### 利用步骤
1. 确定注入点类型（数字型/字符型）
2. 使用SQLMap自动化利用
3. 提取数据库信息

### 修复建议
- 使用参数化查询
- 输入验证和过滤
"""
        }
        
        return suggestions.get(vuln_type, "请手动分析漏洞并制定利用方案")


class SmartScanner:
    """智能扫描器 - 集成AI和Kali工具的自动化扫描系统"""
    
    def __init__(self, api_key: str = None):
        self.tools_manager = KaliToolsManager()
        self.ai_analyzer = AIAnalyzer(api_key)
        self.orchestrator = AIKaliOrchestrator(self.tools_manager, self.ai_analyzer)
        self.context = None
        self.execution_log = []
        
    def scan(self, target: str, max_iterations: int = 10, 
             auto_exploit: bool = False) -> Dict:
        """
        执行智能扫描
        
        Args:
            target: 扫描目标
            max_iterations: 最大迭代次数
            auto_exploit: 是否自动尝试利用
        
        Returns:
            扫描结果报告
        """
        print(f"\n{'='*60}")
        print(f"[AI智能扫描] 目标: {target}")
        print(f"{'='*60}\n")
        
        # 初始化上下文
        self.context = ScanContext(
            target=target,
            target_type=self._classify_target(target)
        )
        
        # AI分析目标
        print("[1] AI分析目标...")
        analysis = self.ai_analyzer.analyze_target(target, self.context)
        print(f"    目标分类: {analysis.get('target_classification')}")
        print(f"    风险等级: {analysis.get('risk_level')}")
        print(f"    推荐工具: {', '.join(analysis.get('recommended_tools', []))}")
        
        # 执行扫描循环
        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            print(f"\n{'='*60}")
            print(f"[迭代 {iteration}/{max_iterations}]")
            print(f"{'='*60}")
            
            # 获取下一步动作
            if iteration == 1:
                # 第一次迭代，使用推荐工具
                action = self._get_initial_action(analysis)
            else:
                # 后续迭代，AI决策
                last_result = self.execution_log[-1] if self.execution_log else {}
                action = self.ai_analyzer.analyze_results(
                    last_result.get('tool', ''),
                    last_result.get('results', {}),
                    self.context
                )
            
            print(f"\n[AI决策] {action.reason}")
            print(f"    动作: {action.action_type}")
            print(f"    置信度: {action.confidence:.2%}")
            
            # 执行动作
            if action.action_type == 'stop':
                print("\n[AI] 扫描完成")
                break
            
            elif action.action_type == 'run_tool':
                result = self._execute_tool_action(action)
                self.execution_log.append({
                    'iteration': iteration,
                    'tool': action.tool_name,
                    'results': result.parsed_output if result.success else {},
                    'success': result.success
                })
                
                # 更新上下文
                self._update_context(result)
                
                # 如果发现了漏洞且启用了自动利用
                if auto_exploit and result.parsed_output.get('vulnerabilities'):
                    for vuln in result.parsed_output['vulnerabilities']:
                        self._handle_discovered_vulnerability(vuln)
            
            elif action.action_type == 'analyze':
                print("[AI] 分析当前结果...")
                # 可以在这里添加更深入的分析
        
        # 生成最终报告
        return self._generate_final_report()
    
    def _classify_target(self, target: str) -> str:
        """分类目标类型"""
        if target.startswith(('http://', 'https://')):
            return 'web'
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?$', target):
            return 'ip'
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return 'domain'
        return 'unknown'
    
    def _get_initial_action(self, analysis: Dict) -> AIAction:
        """获取初始动作"""
        recommended_tools = analysis.get('recommended_tools', [])
        
        if recommended_tools:
            return AIAction(
                action_type='run_tool',
                tool_name=recommended_tools[0],
                reason=f"AI推荐首先使用 {recommended_tools[0]}",
                confidence=0.9,
                expected_outcome=f"使用 {recommended_tools[0]} 收集目标信息"
            )
        
        return AIAction(
            action_type='run_tool',
            tool_name='nmap',
            reason="默认使用Nmap进行端口扫描",
            confidence=0.8,
            expected_outcome="发现开放端口和服务"
        )
    
    def _execute_tool_action(self, action: AIAction):
        """执行工具动作"""
        print(f"\n[执行] {action.tool_name}")
        print(f"    预期结果: {action.expected_outcome}")
        
        result = self.tools_manager.execute_tool(
            action.tool_name,
            self.context.target,
            custom_args=action.parameters.get('args', []),
            timeout=action.parameters.get('timeout', 300)
        )
        
        if result.success:
            print(f"    ✓ 执行成功 ({result.execution_time:.1f}s)")
            print(f"    发现: {len(result.parsed_output)} 项结果")
        else:
            print(f"    ✗ 执行失败: {result.stderr[:100]}")
        
        return result
    
    def _update_context(self, result):
        """更新扫描上下文"""
        # 更新发现的服务
        if 'open_ports' in result.parsed_output:
            for port_info in result.parsed_output['open_ports']:
                self.context.discovered_services.append({
                    'tool': result.tool_name,
                    **port_info
                })
        
        # 更新发现的漏洞
        if 'vulnerabilities' in result.parsed_output:
            for vuln in result.parsed_output['vulnerabilities']:
                self.context.discovered_vulns.append({
                    'tool': result.tool_name,
                    **vuln
                })
        
        # 更新扫描阶段
        self.context.scan_phase = f"after_{result.tool_name}"
    
    def _handle_discovered_vulnerability(self, vuln: Dict):
        """处理发现的漏洞"""
        print(f"\n[!] 发现漏洞: {vuln.get('name', 'Unknown')}")
        
        # 获取AI利用建议
        suggestion = self.ai_analyzer.generate_exploit_suggestion(
            vuln, self.context
        )
        
        print(f"\n[AI利用建议]")
        print(suggestion)
        
        # 保存到上下文
        vuln['exploit_suggestion'] = suggestion
    
    def _generate_final_report(self) -> Dict:
        """生成最终报告"""
        report = {
            'scan_summary': {
                'target': self.context.target,
                'target_type': self.context.target_type,
                'scan_time': datetime.now().isoformat(),
                'iterations': len(self.execution_log),
                'tools_executed': [e['tool'] for e in self.execution_log]
            },
            'discovered_services': self.context.discovered_services,
            'discovered_vulnerabilities': self.context.discovered_vulns,
            'execution_log': self.execution_log,
            'statistics': {
                'total_services': len(self.context.discovered_services),
                'total_vulnerabilities': len(self.context.discovered_vulns),
                'successful_executions': sum(1 for e in self.execution_log if e['success']),
                'failed_executions': sum(1 for e in self.execution_log if not e['success'])
            }
        }
        
        print(f"\n{'='*60}")
        print("[扫描完成] 统计信息")
        print(f"{'='*60}")
        print(f"发现服务: {report['statistics']['total_services']}")
        print(f"发现漏洞: {report['statistics']['total_vulnerabilities']}")
        print(f"成功执行: {report['statistics']['successful_executions']}")
        print(f"失败执行: {report['statistics']['failed_executions']}")
        
        return report
    
    def save_report(self, report: Dict, output_path: str):
        """保存报告到文件"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n[报告已保存] {output_path}")


# 便捷函数
def ai_scan(target: str, api_key: str = None, **kwargs) -> Dict:
    """
    便捷函数：执行AI智能扫描
    
    示例:
        result = ai_scan("https://example.com")
        result = ai_scan("192.168.1.1", auto_exploit=True)
    """
    scanner = SmartScanner(api_key)
    return scanner.scan(target, **kwargs)


if __name__ == '__main__':
    print("AI智能调度器模块")
    print("=" * 60)
    print("\n使用示例:")
    print("  from modules.ai_orchestrator import ai_scan")
    print("  result = ai_scan('https://example.com')")
    print("\n或:")
    print("  from modules.ai_orchestrator import SmartScanner")
    print("  scanner = SmartScanner()")
    print("  report = scanner.scan('192.168.1.1', auto_exploit=True)")
