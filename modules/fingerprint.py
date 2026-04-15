#!/usr/bin/env python3
"""
指纹识别模块 - 识别Web服务器、CMS、框架
"""

import requests
from colorama import Fore, Style

import json
import os

# 加载外部指纹库
def load_fingerprints(config_path='config/fingerprints.json'):
    if os.path.isfile(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

FINGERPRINTS = load_fingerprints()

def detect_from_response(response):
    """根据响应全方位识别指纹"""
    detected = []
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    html = response.text.lower()
    cookies = [c.name.lower() for c in response.cookies]

    for category, rules in FINGERPRINTS.items():
        for rule in rules:
            name = rule['name']
            match = False
            
            # 1. 检查头部
            if 'headers' in rule:
                for k, v in rule['headers'].items():
                    if k.lower() in headers and v.lower() in headers[k.lower()]:
                        match = True
                        break
            
            # 2. 检查文本
            if not match and 'text' in rule:
                for sig in rule['text']:
                    if sig.lower() in html:
                        match = True
                        break
            
            # 3. 检查 Cookie
            if not match and 'cookies' in rule:
                for sig in rule['cookies']:
                    if any(sig.lower() in c for c in cookies):
                        match = True
                        break
            
            if match:
                detected.append({'name': name, 'category': category})
                
    return detected

def scan(url, timeout=10):
    """
    指纹识别主函数
    url: 目标URL
    """
    print(f"\n[*] 目标URL: {url}")

    try:
        resp = requests.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
    except Exception as e:
        print(f"{Fore.RED}[!] 连接失败: {e}{Style.RESET_ALL}")
        return None

    results = detect_from_response(resp)
    
    print(f"\n{Fore.GREEN}[+] 扫描结果{Style.RESET_ALL}")
    print(f"  状态码: {resp.status_code}")
    
    if results:
        for res in results:
            print(f"  [{res['category']}] {res['name']}")
    else:
        print("  未识别到指纹")

    return results


if __name__ == '__main__':
    scan('https://www.baidu.com')