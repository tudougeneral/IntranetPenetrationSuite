#!/usr/bin/env python3
"""
子域名扫描模块 - 通过DNS字典爆破发现子域名
"""

import dns.resolver
import threading
from colorama import Fore, Style

# 配置DNS解析器
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '114.114.114.114']
resolver.timeout = 2
resolver.lifetime = 2


def resolve_subdomain(subdomain):
    """解析子域名，返回IP地址"""
    try:
        answers = resolver.resolve(subdomain, 'A')
        for answer in answers:
            return str(answer)
    except:
        return None


def scan_subdomain(domain, word, results, index, total):
    """扫描单个子域名"""
    subdomain = f"{word}.{domain}"
    ip = resolve_subdomain(subdomain)
    if ip:
        results.append((subdomain, ip))
        print(f"{Fore.GREEN}[+] {subdomain} -> {ip}{Style.RESET_ALL}")


def scan(domain, wordlist_path, threads_num=50):
    """
    子域名扫描主函数
    domain: 目标域名
    wordlist_path: 字典文件路径
    threads_num: 线程数
    """
    # 读取字典
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] 字典文件不存在: {wordlist_path}{Style.RESET_ALL}")
        return []

    print(f"\n[*] 目标域名: {domain}")
    print(f"[*] 字典数量: {len(words)}")
    print(f"[*] 线程数: {threads_num}\n")

    results = []
    threads = []

    for i, word in enumerate(words):
        t = threading.Thread(target=scan_subdomain, args=(domain, word, results, i, len(words)))
        threads.append(t)
        t.start()

        # 控制并发数
        if len(threads) >= threads_num:
            for t in threads:
                t.join()
            threads = []

    # 等待剩余线程
    for t in threads:
        t.join()

    return results


if __name__ == '__main__':
    # 测试代码
    results = scan('baidu.com', '../wordlists/subdomains.txt')
    print(f"\n[*] 共发现 {len(results)} 个子域名")
    for subdomain, ip in results:
        print(f"  {subdomain} -> {ip}")