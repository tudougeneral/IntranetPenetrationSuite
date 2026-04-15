#!/usr/bin/env python3
"""
Kali Linux 工具集成模块
集成常用渗透测试工具，实现AI自动调用
"""

import subprocess
import json
import re
import os
import tempfile
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import requests


class ToolType(Enum):
    """工具类型枚举"""
    PORT_SCAN = "port_scan"
    WEB_SCAN = "web_scan"
    SQL_INJECTION = "sql_injection"
    DIRECTORY_BRUTE = "directory_brute"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"


@dataclass
class ToolResult:
    """工具执行结果"""
    tool_name: str
    command: str
    return_code: int
    stdout: str
    stderr: str
    parsed_output: Dict
    execution_time: float
    success: bool


@dataclass
class ToolConfig:
    """工具配置"""
    name: str
    tool_type: ToolType
    executable: str
    default_args: List[str]
    description: str
    risk_level: str  # low, medium, high
    output_parser: callable


class KaliToolsManager:
    """Kali工具管理器"""
    
    def __init__(self):
        self.tools = {}
        self._init_tools()
        
    def _init_tools(self):
        """初始化所有可用工具"""
        self.tools = {
            # 端口扫描工具
            'nmap': ToolConfig(
                name='nmap',
                tool_type=ToolType.PORT_SCAN,
                executable='nmap',
                default_args=['-sV', '-sC', '-O', '--script=vuln'],
                description='网络端口扫描和服务识别',
                risk_level='medium',
                output_parser=self._parse_nmap_output
            ),
            'masscan': ToolConfig(
                name='masscan',
                tool_type=ToolType.PORT_SCAN,
                executable='masscan',
                default_args=['--rate', '1000'],
                description='高速端口扫描器',
                risk_level='medium',
                output_parser=self._parse_masscan_output
            ),
            
            # Web扫描工具
            'nikto': ToolConfig(
                name='nikto',
                tool_type=ToolType.WEB_SCAN,
                executable='nikto',
                default_args=['-h'],
                description='Web漏洞扫描器',
                risk_level='low',
                output_parser=self._parse_nikto_output
            ),
            'dirb': ToolConfig(
                name='dirb',
                tool_type=ToolType.DIRECTORY_BRUTE,
                executable='dirb',
                default_args=['-r', '-z', '10'],
                description='目录爆破工具',
                risk_level='low',
                output_parser=self._parse_dirb_output
            ),
            'gobuster': ToolConfig(
                name='gobuster',
                tool_type=ToolType.DIRECTORY_BRUTE,
                executable='gobuster',
                default_args=['dir', '-t', '50'],
                description='高速目录爆破工具',
                risk_level='low',
                output_parser=self._parse_gobuster_output
            ),
            
            # SQL注入工具
            'sqlmap': ToolConfig(
                name='sqlmap',
                tool_type=ToolType.SQL_INJECTION,
                executable='sqlmap',
                default_args=['--batch', '--random-agent', '--level=2', '--risk=1'],
                description='自动SQL注入工具',
                risk_level='high',
                output_parser=self._parse_sqlmap_output
            ),
            
            # 漏洞扫描工具
            'wpscan': ToolConfig(
                name='wpscan',
                tool_type=ToolType.VULNERABILITY_SCAN,
                executable='wpscan',
                default_args=['--random-user-agent', '--enumerate', 'vp'],
                description='WordPress漏洞扫描器',
                risk_level='low',
                output_parser=self._parse_wpscan_output
            ),
            'searchsploit': ToolConfig(
                name='searchsploit',
                tool_type=ToolType.VULNERABILITY_SCAN,
                executable='searchsploit',
                default_args=['--json'],
                description='漏洞利用数据库搜索',
                risk_level='low',
                output_parser=self._parse_searchsploit_output
            ),
            
            # 其他工具
            'whatweb': ToolConfig(
                name='whatweb',
                tool_type=ToolType.WEB_SCAN,
                executable='whatweb',
                default_args=['-a', '3'],
                description='Web指纹识别工具',
                risk_level='low',
                output_parser=self._parse_whatweb_output
            ),
            'wfuzz': ToolConfig(
                name='wfuzz',
                tool_type=ToolType.DIRECTORY_BRUTE,
                executable='wfuzz',
                default_args=['-c', '-z', 'file,/usr/share/wordlists/dirb/common.txt'],
                description='Web模糊测试工具',
                risk_level='medium',
                output_parser=self._parse_wfuzz_output
            ),
        }
    
    def check_tool_availability(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        try:
            result = subprocess.run(
                ['which', self.tools[tool_name].executable],
                capture_output=True,
                text=True
            )
            return result.return_code == 0
        except:
            return False
    
    def execute_tool(self, tool_name: str, target: str, 
                     custom_args: List[str] = None,
                     timeout: int = 300) -> ToolResult:
        """执行工具"""
        if tool_name not in self.tools:
            return ToolResult(
                tool_name=tool_name,
                command='',
                return_code=-1,
                stdout='',
                stderr=f'Unknown tool: {tool_name}',
                parsed_output={},
                execution_time=0,
                success=False
            )
        
        tool = self.tools[tool_name]
        args = [tool.executable] + tool.default_args + (custom_args or [])
        
        # 特殊处理某些工具的目标参数
        if tool_name in ['nikto', 'dirb', 'gobuster', 'wpscan']:
            args.append(target)
        elif tool_name == 'nmap':
            args.append(target)
        elif tool_name == 'sqlmap':
            args.extend(['-u', target])
        elif tool_name == 'whatweb':
            args.append(target)
        elif tool_name == 'wfuzz':
            # wfuzz 需要特殊格式
            args.append(target + '/FUZZ')
        elif tool_name == 'masscan':
            args.extend(['-p1-65535', target])
        elif tool_name == 'searchsploit':
            args.append(target)
        
        command = ' '.join(args)
        
        try:
            import time
            start_time = time.time()
            
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            execution_time = time.time() - start_time
            
            parsed_output = tool.output_parser(result.stdout + result.stderr)
            
            return ToolResult(
                tool_name=tool_name,
                command=command,
                return_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                parsed_output=parsed_output,
                execution_time=execution_time,
                success=result.returncode == 0
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=tool_name,
                command=command,
                return_code=-1,
                stdout='',
                stderr=f'Timeout after {timeout} seconds',
                parsed_output={},
                execution_time=timeout,
                success=False
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                command=command,
                return_code=-1,
                stdout='',
                stderr=str(e),
                parsed_output={},
                execution_time=0,
                success=False
            )
    
    # ==================== 输出解析器 ====================
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """解析Nmap输出"""
        result = {
            'open_ports': [],
            'services': [],
            'os_guess': None,
            'vulnerabilities': []
        }
        
        # 解析开放端口
        port_pattern = r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)'
        for match in re.finditer(port_pattern, output):
            port, proto, state, service, version = match.groups()
            result['open_ports'].append({
                'port': int(port),
                'protocol': proto,
                'state': state,
                'service': service,
                'version': version.strip()
            })
        
        # 解析漏洞信息
        vuln_pattern = r'\| (.+?):\s*\n\|\s*(.+)'
        for match in re.finditer(vuln_pattern, output):
            vuln_name = match.group(1)
            vuln_detail = match.group(2)
            result['vulnerabilities'].append({
                'name': vuln_name,
                'detail': vuln_detail
            })
        
        return result
    
    def _parse_masscan_output(self, output: str) -> Dict:
        """解析Masscan输出"""
        result = {'open_ports': []}
        port_pattern = r'Discovered open port (\d+)/(tcp|udp) on ([\d.]+)'
        for match in re.finditer(port_pattern, output):
            port, proto, ip = match.groups()
            result['open_ports'].append({
                'port': int(port),
                'protocol': proto,
                'ip': ip
            })
        return result
    
    def _parse_nikto_output(self, output: str) -> Dict:
        """解析Nikto输出"""
        result = {
            'findings': [],
            'osvdb_entries': [],
            'cgi_dirs': []
        }
        
        # 解析发现的问题
        finding_pattern = r'\+ (.+?) - (.+)'
        for match in re.finditer(finding_pattern, output):
            category = match.group(1)
            detail = match.group(2)
            result['findings'].append({
                'category': category,
                'detail': detail
            })
        
        return result
    
    def _parse_dirb_output(self, output: str) -> Dict:
        """解析Dirb输出"""
        result = {'directories': [], 'files': []}
        
        url_pattern = r'==> (.+?) <=='
        code_pattern = r'\+ (.+?) \(CODE:(\d+)\|SIZE:(\d+)\)'
        
        for match in re.finditer(code_pattern, output):
            url = match.group(1)
            code = int(match.group(2))
            size = int(match.group(3))
            
            entry = {'url': url, 'code': code, 'size': size}
            
            if url.endswith('/'):
                result['directories'].append(entry)
            else:
                result['files'].append(entry)
        
        return result
    
    def _parse_gobuster_output(self, output: str) -> Dict:
        """解析Gobuster输出"""
        result = {'directories': [], 'files': []}
        
        # 解析目录和文件
        pattern = r'/(\S+)\s+\(Status: (\d+)\)\s+\[Size: (\d+)\]'
        for match in re.finditer(pattern, output):
            path = match.group(1)
            status = int(match.group(2))
            size = int(match.group(3))
            
            entry = {'path': path, 'status': status, 'size': size}
            
            if path.endswith('/'):
                result['directories'].append(entry)
            else:
                result['files'].append(entry)
        
        return result
    
    def _parse_sqlmap_output(self, output: str) -> Dict:
        """解析SQLMap输出"""
        result = {
            'vulnerable': False,
            'dbms': None,
            'injection_points': [],
            'databases': []
        }
        
        # 检查是否存在漏洞
        if 'is vulnerable' in output.lower() or 'injectable' in output.lower():
            result['vulnerable'] = True
        
        # 解析数据库类型
        dbms_pattern = r'the back-end DBMS is (\S+)'
        match = re.search(dbms_pattern, output, re.IGNORECASE)
        if match:
            result['dbms'] = match.group(1)
        
        # 解析注入点
        injection_pattern = r'Parameter: (\S+) \((\S+)\)'
        for match in re.finditer(injection_pattern, output):
            result['injection_points'].append({
                'parameter': match.group(1),
                'type': match.group(2)
            })
        
        return result
    
    def _parse_wpscan_output(self, output: str) -> Dict:
        """解析WPScan输出"""
        result = {
            'wordpress_version': None,
            'plugins': [],
            'themes': [],
            'vulnerabilities': [],
            'users': []
        }
        
        # 解析WordPress版本
        version_pattern = r'WordPress version (\S+)'
        match = re.search(version_pattern, output)
        if match:
            result['wordpress_version'] = match.group(1)
        
        # 解析漏洞
        vuln_pattern = r'\[\!\] Title: (.+?)\s+Reference: (.+)'
        for match in re.finditer(vuln_pattern, output):
            result['vulnerabilities'].append({
                'title': match.group(1),
                'reference': match.group(2)
            })
        
        return result
    
    def _parse_searchsploit_output(self, output: str) -> Dict:
        """解析Searchsploit输出"""
        result = {'exploits': []}
        
        try:
            data = json.loads(output)
            for exploit in data.get('RESULTS_EXPLOIT', []):
                result['exploits'].append({
                    'title': exploit.get('Title'),
                    'path': exploit.get('Path'),
                    'edb_id': exploit.get('EDB-ID')
                })
        except json.JSONDecodeError:
            # 如果不是JSON格式，尝试文本解析
            pattern = r'(\S+)\s+\|\s+(.+?)\s+\|\s+(.+)'
            for match in re.finditer(pattern, output):
                result['exploits'].append({
                    'edb_id': match.group(1),
                    'type': match.group(2),
                    'title': match.group(3)
                })
        
        return result
    
    def _parse_whatweb_output(self, output: str) -> Dict:
        """解析WhatWeb输出"""
        result = {'technologies': [], 'plugins': []}
        
        # 解析识别的技术
        tech_pattern = r'\[(.+?)\]'
        for match in re.finditer(tech_pattern, output):
            result['technologies'].append(match.group(1))
        
        return result
    
    def _parse_wfuzz_output(self, output: str) -> Dict:
        """解析Wfuzz输出"""
        result = {'findings': []}
        
        # 解析发现的资源
        pattern = r'(\d+)\s+\S+\s+\S+\s+Ch\s+\d+\s+"(\S+)"'
        for match in re.finditer(pattern, output):
            result['findings'].append({
                'code': int(match.group(1)),
                'url': match.group(2)
            })
        
        return result
    
    def get_available_tools(self) -> List[str]:
        """获取所有可用工具的列表"""
        available = []
        for name, config in self.tools.items():
            if self.check_tool_availability(name):
                available.append(name)
        return available
    
    def get_tools_by_type(self, tool_type: ToolType) -> List[str]:
        """根据类型获取工具列表"""
        return [name for name, config in self.tools.items() 
                if config.tool_type == tool_type]


class AIKaliOrchestrator:
    """AI Kali工具调度器 - 智能选择和执行工具"""
    
    def __init__(self, tools_manager: KaliToolsManager, ai_helper=None):
        self.tools_manager = tools_manager
        self.ai_helper = ai_helper
        self.execution_history = []
        
    def analyze_target(self, target: str, target_info: Dict = None) -> Dict:
        """分析目标并决定使用哪些工具"""
        analysis = {
            'target': target,
            'target_type': self._classify_target(target),
            'recommended_tools': [],
            'execution_plan': [],
            'risk_assessment': {}
        }
        
        # 根据目标类型推荐工具
        target_type = analysis['target_type']
        
        if target_type == 'ip' or target_type == 'hostname':
            # 网络目标，先进行端口扫描
            analysis['recommended_tools'].extend([
                {'tool': 'nmap', 'priority': 1, 'reason': '端口和服务识别'},
                {'tool': 'masscan', 'priority': 2, 'reason': '高速端口扫描'}
            ])
        
        if target_type == 'web_url':
            # Web目标
            analysis['recommended_tools'].extend([
                {'tool': 'whatweb', 'priority': 1, 'reason': '技术栈识别'},
                {'tool': 'nikto', 'priority': 2, 'reason': 'Web漏洞扫描'},
                {'tool': 'dirb', 'priority': 3, 'reason': '目录爆破'},
                {'tool': 'gobuster', 'priority': 3, 'reason': '高速目录爆破'}
            ])
            
            # 检查是否是WordPress
            if target_info and target_info.get('is_wordpress'):
                analysis['recommended_tools'].append({
                    'tool': 'wpscan', 
                    'priority': 2, 
                    'reason': 'WordPress专项扫描'
                })
        
        # 生成执行计划
        analysis['execution_plan'] = self._generate_execution_plan(
            analysis['recommended_tools']
        )
        
        return analysis
    
    def _classify_target(self, target: str) -> str:
        """分类目标类型"""
        if target.startswith('http://') or target.startswith('https://'):
            return 'web_url'
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            return 'ip'
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return 'hostname'
        else:
            return 'unknown'
    
    def _generate_execution_plan(self, recommended_tools: List[Dict]) -> List[Dict]:
        """生成执行计划"""
        # 按优先级排序
        sorted_tools = sorted(recommended_tools, key=lambda x: x['priority'])
        
        plan = []
        for i, tool_info in enumerate(sorted_tools):
            plan.append({
                'step': i + 1,
                'tool': tool_info['tool'],
                'depends_on': [],  # 可以添加依赖关系
                'estimated_time': self._estimate_execution_time(tool_info['tool']),
                'reason': tool_info['reason']
            })
        
        return plan
    
    def _estimate_execution_time(self, tool_name: str) -> int:
        """估计工具执行时间（秒）"""
        estimates = {
            'nmap': 300,
            'masscan': 60,
            'nikto': 600,
            'dirb': 300,
            'gobuster': 120,
            'sqlmap': 600,
            'wpscan': 300,
            'whatweb': 30,
            'wfuzz': 180,
            'searchsploit': 10
        }
        return estimates.get(tool_name, 300)
    
    def execute_intelligent_scan(self, target: str, 
                                  target_info: Dict = None,
                                  max_tools: int = 5) -> List[ToolResult]:
        """执行智能扫描"""
        print(f"[AI] 开始智能分析目标: {target}")
        
        # 分析目标
        analysis = self.analyze_target(target, target_info)
        
        print(f"[AI] 目标类型: {analysis['target_type']}")
        print(f"[AI] 推荐工具: {len(analysis['recommended_tools'])} 个")
        
        # 获取可用工具
        available_tools = self.tools_manager.get_available_tools()
        print(f"[AI] 可用工具: {', '.join(available_tools)}")
        
        results = []
        executed_tools = set()
        
        # 按执行计划执行工具
        for step in analysis['execution_plan'][:max_tools]:
            tool_name = step['tool']
            
            # 检查工具是否可用
            if tool_name not in available_tools:
                print(f"[AI] 跳过 {tool_name} - 工具不可用")
                continue
            
            # 检查是否已经执行过
            if tool_name in executed_tools:
                continue
            
            print(f"\n[AI] 执行步骤 {step['step']}: {tool_name}")
            print(f"[AI] 原因: {step['reason']}")
            print(f"[AI] 预计耗时: {step['estimated_time']} 秒")
            
            # 执行工具
            result = self.tools_manager.execute_tool(
                tool_name, 
                target,
                timeout=step['estimated_time'] * 2
            )
            
            results.append(result)
            executed_tools.add(tool_name)
            
            if result.success:
                print(f"[AI] {tool_name} 执行成功")
                print(f"[AI] 发现: {len(result.parsed_output)} 项结果")
                
                # 根据结果调整后续计划
                self._adapt_plan_based_on_results(
                    analysis, result, step['step']
                )
            else:
                print(f"[AI] {tool_name} 执行失败: {result.stderr[:100]}")
        
        print(f"\n[AI] 智能扫描完成，共执行 {len(results)} 个工具")
        return results
    
    def _adapt_plan_based_on_results(self, analysis: Dict, 
                                      result: ToolResult, 
                                      current_step: int):
        """根据执行结果调整计划"""
        # 如果发现了开放端口，添加SQLMap
        if result.tool_name == 'nmap':
            open_ports = result.parsed_output.get('open_ports', [])
            web_ports = [80, 443, 8080, 8443, 3000, 5000, 8000]
            
            has_web = any(p['port'] in web_ports for p in open_ports)
            
            if has_web and 'sqlmap' not in [t['tool'] for t in analysis['recommended_tools']]:
                print(f"[AI] 检测到Web服务，添加SQL注入测试")
                analysis['recommended_tools'].append({
                    'tool': 'sqlmap',
                    'priority': current_step + 1,
                    'reason': '检测到的Web服务，进行SQL注入测试'
                })
        
        # 如果Nikto发现了SQL注入点，优先执行SQLMap
        if result.tool_name == 'nikto':
            findings = result.parsed_output.get('findings', [])
            sql_related = [f for f in findings if 'sql' in f.get('detail', '').lower()]
            
            if sql_related and 'sqlmap' not in [t['tool'] for t in analysis['recommended_tools']]:
                print(f"[AI] Nikto发现SQL相关漏洞，添加SQLMap测试")
                analysis['recommended_tools'].append({
                    'tool': 'sqlmap',
                    'priority': current_step + 1,
                    'reason': 'Nikto发现SQL相关漏洞'
                })
    
    def generate_comprehensive_report(self, results: List[ToolResult]) -> Dict:
        """生成综合报告"""
        report = {
            'summary': {
                'total_tools': len(results),
                'successful_tools': sum(1 for r in results if r.success),
                'failed_tools': sum(1 for r in results if not r.success),
                'total_execution_time': sum(r.execution_time for r in results)
            },
            'findings': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # 汇总所有发现
        for result in results:
            if result.success:
                report['findings'].append({
                    'tool': result.tool_name,
                    'findings': result.parsed_output
                })
                
                # 提取漏洞信息
                if 'vulnerabilities' in result.parsed_output:
                    for vuln in result.parsed_output['vulnerabilities']:
                        report['vulnerabilities'].append({
                            'tool': result.tool_name,
                            **vuln
                        })
        
        # 生成建议
        if report['vulnerabilities']:
            report['recommendations'].append(
                f"发现 {len(report['vulnerabilities'])} 个潜在漏洞，建议进一步验证"
            )
        
        return report


# 便捷函数
def run_kali_tool(tool_name: str, target: str, **kwargs) -> ToolResult:
    """便捷函数：运行单个Kali工具"""
    manager = KaliToolsManager()
    return manager.execute_tool(tool_name, target, **kwargs)


def run_intelligent_scan(target: str, **kwargs) -> List[ToolResult]:
    """便捷函数：运行智能扫描"""
    manager = KaliToolsManager()
    orchestrator = AIKaliOrchestrator(manager)
    return orchestrator.execute_intelligent_scan(target, **kwargs)


if __name__ == '__main__':
    # 测试代码
    print("Kali工具集成模块测试")
    
    manager = KaliToolsManager()
    available = manager.get_available_tools()
    print(f"可用工具: {available}")
    
    # 测试智能扫描
    if available:
        orchestrator = AIKaliOrchestrator(manager)
        # 注意：这里使用示例目标，实际使用时请替换为真实目标
        # results = orchestrator.execute_intelligent_scan("127.0.0.1")
        pass
