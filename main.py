#!/usr/bin/env python3
"""
Intranet Penetration Suite - 内网渗透测试工具集
Author: tudougeneral
"""

import argparse
import sys
from datetime import datetime
from colorama import init, Fore, Style

# 初始化颜色
init(autoreset=True)


def print_banner():
    print(f"""{Fore.CYAN}
╔═══════════════════════════════════════════════════════════╗
║     Intranet Penetration Suite - 内网渗透测试工具集        ║
║                     Author: tudougeneral                   ║
╚═══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def main():
    parser = argparse.ArgumentParser(description='内网渗透测试工具集')
    parser.add_argument('-t', '--target', help='目标IP或域名')
    parser.add_argument('--port', action='store_true', help='端口扫描')
    parser.add_argument('--subdomain', action='store_true', help='子域名扫描')
    parser.add_argument('--dir', action='store_true', help='目录扫描')
    parser.add_argument('--sql', help='SQL注入检测 (输入URL)')
    parser.add_argument('--xss', help='XSS检测 (输入URL)')
    parser.add_argument('--brute', action='store_true', help='弱口令爆破')
    parser.add_argument('--fingerprint', action='store_true', help='指纹识别')
    parser.add_argument('--all', action='store_true', help='完整扫描')
    parser.add_argument('-o', '--output', help='报告输出文件')

    args = parser.parse_args()

    print_banner()
    print(f"[*] Start time: {datetime.now()}")

    if not len(sys.argv) > 1:
        parser.print_help()
        sys.exit(1)

    # 端口扫描
    if args.port or args.all:
        print(f"\n[+] 开始端口扫描: {args.target}")
        # TODO: 调用端口扫描模块

    # 子域名扫描
    if args.subdomain or args.all:
        print(f"\n[+] 开始子域名扫描: {args.target}")
        from modules.subdomain_scanner import scan
        results = scan(args.target, 'wordlists/subdomains.txt')
        print(f"\n[+] 共发现 {len(results)} 个子域名")
        for subdomain, ip in results:
            print(f"  {subdomain} -> {ip}")

    # 目录扫描
    if args.dir or args.all:
        print(f"\n[+] 开始目录扫描: {args.target}")
        from modules.dir_scanner import scan
        # 确保URL有协议
        target_url = args.target if args.target.startswith('http') else f"http://{args.target}"
        results = scan(target_url, 'wordlists/directories.txt')
        print(f"\n[+] 共发现 {len(results)} 个目录/文件")

    # SQL注入检测
    if args.sql:
        print(f"\n[+] 开始SQL注入检测: {args.sql}")
        from modules.sql_injector import scan
        results = scan(args.sql)
        if results:
            print(f"\n{Fore.RED}[!] 发现 {len(results)} 个SQL注入漏洞{Style.RESET_ALL}")
            for r in results:
                print(f"  参数: {r['parameter']}")
                print(f"  Payload: {r['payload']}")
                print(f"  类型: {r['type']}")
        else:
            print(f"{Fore.GREEN}[+] 未发现SQL注入漏洞{Style.RESET_ALL}")

    # XSS检测
    if args.xss:
        print(f"\n[+] 开始XSS检测: {args.xss}")
        from modules.xss_scanner import scan
        results = scan(args.xss)
        if results:
            print(f"\n{Fore.RED}[!] 发现 {len(results)} 个XSS漏洞{Style.RESET_ALL}")
            for r in results:
                print(f"  参数: {r['parameter']}")
                print(f"  Payload: {r['payload']}")
        else:
            print(f"{Fore.GREEN}[+] 未发现XSS漏洞{Style.RESET_ALL}")

    # 指纹识别
    if args.fingerprint or args.all:
       print(f"\n[+] 开始指纹识别: {args.target}")
       from modules.fingerprint import scan
       scan(args.target)

    # 弱口令爆破
    if args.brute or args.all:
        print(f"\n[+] 开始弱口令爆破: {args.target}")
        from modules.brute_force import brute_http_basic
        # 读取字典
        with open('wordlists/usernames.txt', 'r') as f:
            users = [line.strip() for line in f]
        with open('wordlists/passwords.txt', 'r') as f:
            passwd = [line.strip() for line in f]
        results = brute_http_basic(args.target, users, passwd)
        print(f"\n[+] 共发现 {len(results)} 个有效密码")

    # 生成报告
    if args.output:
        print(f"\n[+] 正在生成报告: {args.output}")
        from modules.report import generate_html_report
        # 收集扫描结果
        scan_results = {
            'target': args.target,
            'scan_type': 'full' if args.all else 'custom',
            'ports': [],  # 端口扫描结果
            'subdomains': [],  # 子域名结果
            'directories': [],  # 目录结果
            'sql_injections': [],  # SQL注入结果
            'xss_vulns': [],  # XSS结果
        }
        generate_html_report(scan_results, args.output)
    print(f"\n[*] End time: {datetime.now()}")

if __name__ == '__main__':
    main()