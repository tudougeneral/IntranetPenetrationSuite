#!/usr/bin/env python3
"""
目录扫描模块 - 通过字典爆破发现网站目录
"""

import requests
import threading
from colorama import Fore, Style

# 常见的状态码含义
STATUS_CODES = {
    200: 'OK',
    301: 'Moved Permanently',
    302: 'Found',
    403: 'Forbidden',
    404: 'Not Found',
    500: 'Internal Server Error'
}


def check_dir(url, word, results, timeout=3):
    """检测单个目录"""
    # 拼接完整URL
    if url.endswith('/'):
        target = f"{url}{word}"
    else:
        target = f"{url}/{word}"

    try:
        resp = requests.get(target, timeout=timeout, allow_redirects=False)
        status = resp.status_code

        # 只记录非404的状态码
        if status != 404:
            results.append((target, status))
            if status == 200:
                print(f"{Fore.GREEN}[+] {target} -> {status} {STATUS_CODES.get(status, '')}{Style.RESET_ALL}")
            elif status in [301, 302]:
                print(f"{Fore.YELLOW}[+] {target} -> {status} {STATUS_CODES.get(status, '')}{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}[+] {target} -> {status} {STATUS_CODES.get(status, '')}{Style.RESET_ALL}")
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        pass


def scan(url, wordlist_path, threads_num=30, timeout=3):
    """
    目录扫描主函数
    url: 目标URL
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

    print(f"\n[*] 目标URL: {url}")
    print(f"[*] 字典数量: {len(words)}")
    print(f"[*] 线程数: {threads_num}\n")

    results = []
    threads = []

    for word in words:
        t = threading.Thread(target=check_dir, args=(url, word, results, timeout))
        threads.append(t)
        t.start()

        if len(threads) >= threads_num:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    return results


if __name__ == '__main__':
    results = scan('http://baidu.com', '../wordlists/directories.txt')
    print(f"\n[*] 共发现 {len(results)} 个目录")
    for target, status in results:
        print(f"  {target} -> {status}")