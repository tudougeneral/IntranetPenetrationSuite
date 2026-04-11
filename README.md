# Intranet Penetration Suite

内网渗透测试工具集 - 一个集成了多种信息收集和漏洞检测功能的 Python 工具包。

## 🚀 功能特点

| 模块 | 功能 | 状态 |
|------|------|------|
| 端口扫描 | TCP端口扫描、服务识别、Banner抓取 | ✅ |
| 子域名扫描 | DNS字典爆破、泛解析检测 | ✅ |
| 目录扫描 | HTTP目录/文件爆破、状态码识别 | ✅ |
| SQL注入检测 | 基于时间/布尔的盲注检测、报错注入 | ✅ |
| XSS检测 | 反射型XSS检测、多种Payload自动测试 | ✅ |
| 弱口令爆破 | HTTP基础认证、表单登录爆破 | ✅ |
| 指纹识别 | Web服务器、CMS、后端语言识别 | ✅ |
| 报告生成 | HTML/JSON格式报告 | ✅ |

## 📦 安装

```bash
git clone https://github.com/tudougeneral/IntranetPenetrationSuite.git
cd IntranetPenetrationSuite
pip install -r requirements.txt
🎯 使用方法
基础用法
bash
# 完整扫描
python main.py -t 192.168.1.1 --all

# 端口扫描
python main.py -t 192.168.1.1 --port

# 子域名扫描
python main.py -t baidu.com --subdomain

# 目录扫描
python main.py -t http://target.com --dir

# SQL注入检测
python main.py --sql "http://test.com/page?id=1"

# XSS检测
python main.py --xss "http://test.com/search?q=test"

# 指纹识别
python main.py -t https://baidu.com --fingerprint

# 弱口令爆破
python main.py -t http://target.com/login --brute

# 生成报告
python main.py -t target.com --all -o report.html
📸 运行截图
子域名扫描
[*] 目标域名: baidu.com
[*] 字典数量: 35
[*] 线程数: 50

[+] www.baidu.com -> 110.242.68.66
[+] api.baidu.com -> 110.242.74.199
[+] mail.baidu.com -> 220.181.57.216
...

[+] 共发现 16 个子域名
目录扫描
text
[*] 目标URL: http://baidu.com
[*] 字典数量: 45

[+] http://baidu.com/robots.txt -> 200 OK
[+] http://baidu.com/phpmyadmin -> 301 Moved Permanently
[+] http://baidu.com/admin -> 403 Forbidden
...

[+] 共发现 43 个目录/文件
指纹识别
[*] 目标URL: https://baidu.com

[+] 扫描结果
  状态码: 200
  Web服务器: nginx
📁 项目结构
IntranetPenetrationSuite/
├── modules/
│   ├── port_scanner.py      # 端口扫描
│   ├── subdomain_scanner.py # 子域名扫描
│   ├── dir_scanner.py       # 目录扫描
│   ├── sql_injector.py      # SQL注入检测
│   ├── xss_scanner.py       # XSS检测
│   ├── brute_force.py       # 弱口令爆破
│   ├── fingerprint.py       # 指纹识别
│   └── report.py            # 报告生成
├── wordlists/               # 字典文件
├── output/                  # 输出目录
├── logs/                    # 日志目录
├── config.py                # 配置文件
├── main.py                  # 主入口
└── requirements.txt         # 依赖列表
🛠️ 技术栈
Python 3.14

requests - HTTP请求

dnspython - DNS解析

colorama - 彩色输出

tqdm - 进度条

📌 待优化
添加更多检测Payload

支持HTTPS证书检测

添加CVE漏洞检测

支持代理模式

添加并发控制优化

👤 作者
tudougeneral

📄 许可证
MIT
