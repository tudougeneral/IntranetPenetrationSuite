#!/usr/bin/env python3
"""
Intranet Penetration Suite - 完整版
集成了：端口扫描、子域名扫描、指纹识别、Pro自动挖洞
Author: tudougeneral

【重要】仅用于您已获得书面授权的目标与环境；禁止未授权扫描。
"""

import argparse
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

from colorama import init, Fore, Style

init(autoreset=True)

DISCLAIMER = (
    f"{Fore.YELLOW}[!] 本工具仅用于授权范围内的安全测试。未授权扫描可能违法。{Style.RESET_ALL}"
)


def load_config(path):
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def hosts_from_scope_file(path):
    """从文件读取授权域名（每行一个域名或根 URL，# 为注释）。"""
    hosts = set()
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '://' in line:
                h = urlparse(line).hostname
                if h:
                    hosts.add(h.lower())
            else:
                hosts.add(line.lower().split('/')[0].split(':')[0])
    return sorted(hosts)


def read_first_target_url(path):
    if not path or not os.path.isfile(path):
        return None
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                return line if line.startswith('http') else f'http://{line}'
    return None


def print_banner():
    print(f"""{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    Intranet Penetration Suite - 完整版                         ║
║         作者: tudougeneral  |  Pro Hunt + 端口/子域/指纹                      ║
╚═══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def main():
    parser = argparse.ArgumentParser(description='内网渗透测试工具集 - 完整版（需授权使用）')
    parser.add_argument('-t', '--target', help='目标 IP、域名或 URL')
    parser.add_argument('-c', '--config', help='JSON 配置文件（见 config.example.json）')

    parser.add_argument('--port', action='store_true', help='端口扫描 (TCP connect)')
    parser.add_argument('--subdomain', action='store_true', help='子域名扫描')
    parser.add_argument('--fingerprint', action='store_true', help='指纹识别')

    parser.add_argument('--hunt-pro', action='store_true', help='Pro 自动挖洞')
    parser.add_argument('--passive-urls-file', help='被动模式：每行一个带查询串的 URL，不爬站')
    parser.add_argument('--json-fuzz', action='store_true', help='对 JSON POST 做浅层 SQL 报错探测')
    parser.add_argument('--no-open-redirect', action='store_true', help='关闭开放重定向探测')
    parser.add_argument('--no-header-audit', action='store_true', help='关闭响应头审计')

    parser.add_argument('--depth', type=int, default=None, help='爬取深度')
    parser.add_argument('--threads', type=int, default=None, help='线程数')
    parser.add_argument('--timeout', type=float, default=None, help='请求超时(秒)')
    parser.add_argument('--max-rps', type=float, default=None, help='全局限速 请求/秒，0 不限速')
    parser.add_argument('--max-retries', type=int, default=None, help='失败重试次数')
    parser.add_argument('--max-crawl-urls', type=int, default=None, help='最大爬取 URL 数')
    parser.add_argument('--allow-hosts', help='仅允许这些主机名(逗号分隔)，例: localhost,127.0.0.1')
    parser.add_argument(
        '--scope-file',
        help='SRC 推荐：从文件合并授权域名白名单（每行域名或 https://子域/ ）',
    )
    parser.add_argument(
        '--targets-file',
        help='批量根 URL（每行一个），依次扫描并合并去重写入同一报告',
    )
    parser.add_argument(
        '--strict-scope',
        action='store_true',
        help='必须配置 --allow-hosts 或 --scope-file，防止误扫未在清单内的主机',
    )
    parser.add_argument('--checkpoint', help='保存/恢复进度（已爬 URL + 已完成输入点 + 漏洞快照）')
    parser.add_argument('--resume', action='store_true', help='配合 --checkpoint 从中断处继续')
    parser.add_argument('--proxy', help='HTTP(S) 代理，如 http://127.0.0.1:8080 对接 Burp')
    parser.add_argument('--proxy-file', help='多代理轮询（每行一个 URL），用于多出口（非“伪造 IP”）')
    parser.add_argument('--no-verify-poc', action='store_true', help='关闭二次验证请求（仅初筛）')
    parser.add_argument('--write-html', action='store_true', help='自动生成与 JSON 同名的 *_report.html')
    
    # AI和Kali工具集成
    parser.add_argument('--ai-scan', action='store_true', help='启用AI智能扫描（自动选择和执行Kali工具）')
    parser.add_argument('--ai-key', help='AI API密钥（用于智能决策）')
    parser.add_argument('--kali-tool', help='指定要运行的Kali工具（如nmap,nikto,sqlmap等）')
    parser.add_argument('--auto-exploit', action='store_true', help='AI自动尝试利用发现的漏洞')
    parser.add_argument('--max-iterations', type=int, default=10, help='AI扫描最大迭代次数')

    # SRC 模式和快速扫描
    parser.add_argument('--src-mode', action='store_true', help='SRC 合规模式（安全扫描，低频率，仅保留核心漏洞检测）')
    parser.add_argument('--quick-scan', action='store_true', help='快速扫描模式（仅测试常见参数和高危漏洞，适合大面积资产）')

    parser.add_argument('--all', action='store_true', help='完整扫描（端口+子域+指纹+hunt）')
    parser.add_argument('-o', '--output', default=None, help='JSON 报告路径（默认 hunt_report.json）')
    parser.add_argument('--html', dest='html_report', default=None, help='额外输出 HTML 报告')
    parser.add_argument('--md', dest='md_report', default=None, help='额外输出 Markdown 报告')

    parser.add_argument('-v', '--verbose', action='store_true', help='调试输出')
    parser.add_argument('-q', '--quiet', action='store_true', help='仅必要输出')

    args = parser.parse_args()
    cfg = load_config(args.config)

    def pick(name, argval, default):
        if argval is not None:
            return argval
        return cfg.get(name, default)

    depth = pick('depth', args.depth, 3)
    threads = pick('threads', args.threads, 20)
    timeout = float(pick('timeout', args.timeout, 5.0))
    max_rps = float(pick('max_rps', args.max_rps, 0))
    max_retries = int(pick('max_retries', args.max_retries, 3))
    max_crawl_urls = int(pick('max_crawl_urls', args.max_crawl_urls, 500))
    verbose = args.verbose or cfg.get('verbose', False)
    quiet = args.quiet or cfg.get('quiet', False)
    output = args.output or cfg.get('output', 'hunt_report.json')
    
    # 启用所有功能
    json_fuzz = args.json_fuzz or cfg.get('enable_json_fuzz', True)
    enable_open_redirect = not args.no_open_redirect and cfg.get('enable_open_redirect', True)
    enable_idor = cfg.get('enable_idor', True)
    enable_file_upload = cfg.get('enable_file_upload', True)
    enable_weak_credentials = cfg.get('enable_weak_credentials', True)
    enable_backup_scan = cfg.get('enable_backup_scan', True)
    enable_directory_scan = cfg.get('enable_directory_scan', True)
    enable_header_audit = not args.no_header_audit and cfg.get('enable_header_audit', True)
    enable_cors_check = cfg.get('enable_cors_check', True)
    enable_xss = cfg.get('enable_xss', True)
    enable_sqli = cfg.get('enable_sqli', True)

    allow_hosts = args.allow_hosts
    if allow_hosts:
        allow_hosts = [x.strip().lower() for x in allow_hosts.split(',') if x.strip()]
    else:
        allow_hosts = cfg.get('allow_hosts')
        if isinstance(allow_hosts, str):
            allow_hosts = [x.strip().lower() for x in allow_hosts.split(',') if x.strip()]
        elif isinstance(allow_hosts, list):
            allow_hosts = [str(x).strip().lower() for x in allow_hosts]
        else:
            allow_hosts = None

    if args.scope_file:
        if not os.path.isfile(args.scope_file):
            print(f"{Fore.RED}[!] scope 文件不存在: {args.scope_file}{Style.RESET_ALL}")
            sys.exit(1)
        scope_hosts = hosts_from_scope_file(args.scope_file)
        allow_hosts = list({*(allow_hosts or []), *scope_hosts})

    target = args.target
    seed_url = target
    if not seed_url and args.targets_file:
        seed_url = read_first_target_url(args.targets_file)

    print_banner()
    print(DISCLAIMER)
    print(f"[*] Start time: {datetime.now()}")

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    need_target = args.all or args.port or args.subdomain or args.fingerprint or args.hunt_pro
    if need_target and not seed_url:
        print(f"{Fore.RED}[!] 请使用 -t/--target，或提供非空的 --targets-file{Style.RESET_ALL}")
        sys.exit(1)

    # 端口扫描
    if args.port or args.all:
        print(f"\n{Fore.CYAN}[+] TCP 端口扫描: {seed_url}{Style.RESET_ALL}")
        from modules.port_scanner import scan as port_scan
        open_ports = port_scan(seed_url, threads=min(threads, 100), timeout=min(float(timeout), 3.0))
        for p in open_ports:
            print(f"    {Fore.GREEN}[+] {p['port']}/tcp open  ({p['service']}){Style.RESET_ALL}")
        if not open_ports:
            print(f"    {Fore.YELLOW}未发现常见开放端口（或主机不可达）{Style.RESET_ALL}")

    # 子域名扫描
    if args.subdomain or args.all:
        dom = urlparse(seed_url).hostname if seed_url and '://' in seed_url else (seed_url or '').split('/')[0]
        print(f"\n{Fore.CYAN}[+] 子域名扫描: {dom}{Style.RESET_ALL}")
        from modules.subdomain_scanner import scan
        results = scan(dom, 'wordlists/subdomains.txt')
        print(f"    {Fore.GREEN}[+] 发现 {len(results)} 个子域名{Style.RESET_ALL}")

    # 指纹识别
    if args.fingerprint or args.all:
        fp_url = seed_url if seed_url.startswith('http') else f'http://{seed_url}'
        print(f"\n{Fore.CYAN}[+] 指纹识别: {fp_url}{Style.RESET_ALL}")
        from modules.fingerprint import scan
        scan(fp_url)

    # Pro 自动挖洞
    if args.hunt_pro or args.all:
        print(f"\n{Fore.CYAN}[+] Pro Auto Hunter{Style.RESET_ALL}")
        from modules.auto_hunter_pro import ProAutoHunter

        passive_lines = None
        if args.passive_urls_file:
            with open(args.passive_urls_file, encoding='utf-8') as pf:
                passive_lines = pf.readlines()

        hunt_targets = []
        if args.targets_file:
            with open(args.targets_file, encoding='utf-8') as tf:
                for line in tf:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    hunt_targets.append(line if line.startswith('http') else f'http://{line}')
        else:
            hunt_targets = [target if target.startswith('http') else f'http://{target}']

        verify_poc = not args.no_verify_poc
        strict_scope = args.strict_scope or cfg.get('strict_scope', False)
        checkpoint = args.checkpoint if len(hunt_targets) == 1 else None
        if args.checkpoint and len(hunt_targets) > 1:
            print(f"{Fore.YELLOW}[!] 批量目标时忽略 --checkpoint（请对单目标使用）{Style.RESET_ALL}")

        merged_vulns = []
        merged_info = {'batch': True, 'per_target': [], 'backup_files': [], 'sensitive_directories': [], 'header_audit': []}
        batch_summaries = []
        last_hunter = None

        for hunt_url in hunt_targets:
            print(f"[DEBUG] 使用的爬取深度: {depth}")
            # 快速扫描模式配置
            if args.quick_scan:
                hunter = ProAutoHunter(
                    threads=20,  # 适中的线程数
                    timeout=5,  # 较短的超时时间
                    max_rps=10,  # 适当的速率限制
                    max_retries=2,  # 较少的重试次数
                    max_crawl_urls=200,  # 较少的爬取URL数
                    verbose=verbose,
                    quiet=quiet,
                    allow_hosts=allow_hosts,
                    enable_json_fuzz=False,  # 禁用JSON模糊测试
                    enable_open_redirect=False,  # 禁用开放重定向检测
                    enable_idor=False,  # 禁用越权检测
                    enable_header_audit=True,  # 启用头部审计
                    strict_scope=strict_scope,
                    verify_poc=False,  # 禁用漏洞验证
                    checkpoint_path=checkpoint,
                    resume=args.resume,
                    proxy_url=args.proxy or cfg.get('proxy'),
                    proxy_file=args.proxy_file or cfg.get('proxy_file'),
                    enable_file_upload=False,  # 禁用文件上传检测
                    enable_weak_credentials=False,  # 禁用弱口令检测
                    enable_backup_scan=False,  # 禁用备份文件扫描
                    enable_directory_scan=False,  # 禁用目录扫描
                    enable_xss=True,  # 启用XSS检测
                    enable_sqli=True,  # 启用SQL注入检测
                    src_mode=False,  # 禁用SRC模式
                    quick_scan=True,  # 启用快速扫描
                )
            else:
                # 完整扫描模式
                hunter = ProAutoHunter(
                    threads=30,  # 适中的线程数
                    timeout=10,  # 合理的超时时间
                    max_rps=0,  # 无速率限制
                    max_retries=3,  # 适当的重试次数
                    max_crawl_urls=1000,  # 合理的爬取URL数
                    verbose=verbose,
                    quiet=quiet,
                    allow_hosts=allow_hosts,
                    enable_json_fuzz=True,  # 启用JSON模糊测试
                    enable_open_redirect=True,  # 启用开放重定向检测
                    enable_idor=True,  # 启用越权检测
                    enable_header_audit=True,  # 启用头部审计
                    strict_scope=strict_scope,
                    verify_poc=verify_poc,
                    checkpoint_path=checkpoint,
                    resume=args.resume,
                    proxy_url=args.proxy or cfg.get('proxy'),
                    proxy_file=args.proxy_file or cfg.get('proxy_file'),
                    enable_file_upload=True,  # 启用文件上传检测
                    enable_weak_credentials=True,  # 启用弱口令检测
                    enable_backup_scan=True,  # 启用备份文件扫描
                    enable_directory_scan=True,  # 启用目录扫描
                    enable_xss=True,  # 启用XSS检测
                    enable_sqli=True,  # 启用SQL注入检测
                    src_mode=False,  # 禁用SRC模式
                    quick_scan=False,  # 禁用快速扫描
                )
            r = hunter.hunt(hunt_url, depth=depth, passive_urls=passive_lines)
            last_hunter = hunter
            merged_vulns.extend(r.get('vulnerabilities', []))
            merged_info['per_target'].append({'target': hunt_url, 'summary': r.get('summary', {})})
            inf = r.get('info') or {}
            merged_info['backup_files'].extend(inf.get('backup_files') or [])
            merged_info['sensitive_directories'].extend(inf.get('sensitive_directories') or [])
            merged_info['header_audit'].extend(inf.get('header_audit') or [])
            batch_summaries.append(r.get('summary', {}))

        seen = set()
        deduped = []
        for v in merged_vulns:
            p = urlparse(v.get('url', ''))
            key = (v.get('type'), v.get('parameter'), p.path[:200], (p.hostname or '').lower())
            if key in seen:
                continue
            seen.add(key)
            deduped.append(v)

        final_summary = {
            'target': hunt_targets[0] if len(hunt_targets) == 1 else f'批量 {len(hunt_targets)} 个目标',
            'batch_targets': hunt_targets,
            'start_time': batch_summaries[0].get('start_time', '') if batch_summaries else '',
            'end_time': batch_summaries[-1].get('end_time', '') if batch_summaries else '',
            'total_vulnerabilities': len(deduped),
            'backup_files_found': sum(s.get('backup_files_found', 0) for s in batch_summaries),
            'sensitive_dirs_found': sum(s.get('sensitive_dirs_found', 0) for s in batch_summaries),
            'input_points_found': sum(s.get('input_points_found', 0) for s in batch_summaries),
            'header_audit_count': sum(s.get('header_audit_count', 0) for s in batch_summaries),
        }
        last_hunter.results = {
            'vulnerabilities': deduped,
            'summary': final_summary,
            'info': merged_info,
        }

        html_out = args.html_report
        if args.write_html and not html_out:
            base = output.rsplit('.', 1)[0] if output and '.' in output else (output or 'hunt_report')
            html_out = base + '_report.html'

        last_hunter.generate_report(output, html_path=html_out, md_path=args.md_report)

    # AI智能扫描和Kali工具集成
    if args.ai_scan or args.kali_tool:
        print(f"\n{Fore.CYAN}[+] AI智能扫描和Kali工具集成{Style.RESET_ALL}")
        
        # 导入模块
        try:
            from modules.kali_tools_integration import KaliToolsManager, run_kali_tool, run_intelligent_scan
            from modules.ai_orchestrator import SmartScanner, ai_scan
            
            kali_manager = KaliToolsManager()
            
            # 检查可用工具
            available_tools = kali_manager.get_available_tools()
            if available_tools:
                print(f"    {Fore.GREEN}[+] 可用Kali工具: {', '.join(available_tools)}{Style.RESET_ALL}")
            else:
                print(f"    {Fore.YELLOW}[!] 未检测到Kali工具，请确保已安装{Style.RESET_ALL}")
            
            # 指定运行单个Kali工具
            if args.kali_tool:
                print(f"\n{Fore.CYAN}[*] 执行Kali工具: {args.kali_tool}{Style.RESET_ALL}")
                result = run_kali_tool(args.kali_tool, seed_url)
                
                if result.success:
                    print(f"    {Fore.GREEN}[+] 执行成功 ({result.execution_time:.1f}s){Style.RESET_ALL}")
                    print(f"    {Fore.GREEN}[+] 发现: {len(result.parsed_output)} 项结果{Style.RESET_ALL}")
                    
                    # 保存结果
                    kali_output = output.replace('.json', f'_{args.kali_tool}.json')
                    with open(kali_output, 'w', encoding='utf-8') as f:
                        json.dump({
                            'tool': args.kali_tool,
                            'target': seed_url,
                            'command': result.command,
                            'results': result.parsed_output,
                            'raw_output': result.stdout[:5000]  # 限制大小
                        }, f, indent=2, ensure_ascii=False)
                    print(f"    {Fore.GREEN}[+] 结果已保存: {kali_output}{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.RED}[!] 执行失败: {result.stderr[:200]}{Style.RESET_ALL}")
            
            # AI智能扫描
            if args.ai_scan:
                print(f"\n{Fore.CYAN}[*] 启动AI智能扫描{Style.RESET_ALL}")
                print(f"    目标: {seed_url}")
                print(f"    最大迭代: {args.max_iterations}")
                print(f"    自动利用: {'是' if args.auto_exploit else '否'}")
                
                # 获取AI API密钥
                ai_key = args.ai_key or cfg.get('ai_api_key') or os.getenv('AI_API_KEY')
                
                if ai_key:
                    print(f"    {Fore.GREEN}[+] AI API已配置{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.YELLOW}[!] 未配置AI API，将使用备用决策逻辑{Style.RESET_ALL}")
                
                # 执行AI扫描
                scanner = SmartScanner(ai_key)
                report = scanner.scan(
                    seed_url,
                    max_iterations=args.max_iterations,
                    auto_exploit=args.auto_exploit
                )
                
                # 保存AI扫描报告
                ai_output = output.replace('.json', '_ai_scan.json')
                scanner.save_report(report, ai_output)
                
                # 打印摘要
                print(f"\n{Fore.CYAN}[*] AI扫描摘要{Style.RESET_ALL}")
                print(f"    执行工具: {report['scan_summary']['tools_executed']}")
                print(f"    发现服务: {report['statistics']['total_services']}")
                print(f"    发现漏洞: {report['statistics']['total_vulnerabilities']}")
                
        except ImportError as e:
            print(f"    {Fore.RED}[!] 导入模块失败: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"    {Fore.RED}[!] AI扫描出错: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()

    print(f"\n{Fore.CYAN}[*] End time: {datetime.now()}{Style.RESET_ALL}")


if __name__ == '__main__':
    main()
