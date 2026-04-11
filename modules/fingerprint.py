#!/usr/bin/env python3
"""
指纹识别模块 - 识别Web服务器、CMS、框架
"""

import requests
from colorama import Fore, Style

# 指纹特征库
FINGERPRINTS = {
    'nginx': ['nginx', 'Nginx'],
    'apache': ['Apache', 'apache'],
    'IIS': ['Microsoft-IIS', 'IIS'],
    'PHP': ['PHP', 'php'],
    'ASP.NET': ['ASP.NET', 'asp.net'],
    'Java': ['Java', 'JSP', 'Servlet'],
    'Python': ['Python', 'Django', 'Flask'],
    'WordPress': ['wp-content', 'wp-includes', 'WordPress'],
    'DedeCMS': ['dedecms', 'DedeCMS'],
    'ThinkPHP': ['thinkphp', 'ThinkPHP'],
    'jQuery': ['jquery', 'jQuery'],
    'Bootstrap': ['bootstrap', 'Bootstrap'],
}


def detect_server(response):
    """识别Web服务器"""
    server = response.headers.get('Server', '')
    if server:
        for key in FINGERPRINTS:
            if key.lower() in server.lower():
                return key
    return None


def detect_framework(response):
    """识别框架/CMS"""
    detected = []
    html = response.text.lower()

    for name, signatures in FINGERPRINTS.items():
        for sig in signatures:
            if sig.lower() in html or sig.lower() in str(response.headers):
                detected.append(name)
                break

    return list(set(detected))


def detect_powered_by(response):
    """识别后端语言"""
    powered_by = response.headers.get('X-Powered-By', '')
    if powered_by:
        return powered_by
    return None


def scan(url, timeout=10):
    """
    指纹识别主函数
    url: 目标URL
    """
    print(f"\n[*] 目标URL: {url}")

    try:
        resp = requests.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
    except Exception as e:
        print(f"{Fore.RED}[!] 连接失败: {e}{Style.RESET_ALL}")
        return None

    result = {
        'url': url,
        'status_code': resp.status_code,
        'server': detect_server(resp),
        'powered_by': detect_powered_by(resp),
        'frameworks': detect_framework(resp),
    }

    print(f"\n{Fore.GREEN}[+] 扫描结果{Style.RESET_ALL}")
    print(f"  状态码: {result['status_code']}")
    if result['server']:
        print(f"  Web服务器: {result['server']}")
    if result['powered_by']:
        print(f"  后端语言: {result['powered_by']}")
    if result['frameworks']:
        print(f"  框架/CMS: {', '.join(result['frameworks'])}")

    return result


if __name__ == '__main__':
    scan('https://www.baidu.com')