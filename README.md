# IntranetPenetrationSuite

<div align="center">
  <img src="https://trae-api-cn.mchost.guru/api/ide/v1/text_to_image?prompt=cybersecurity%20tool%20logo%20with%20shield%20and%20network%20symbols%2C%20modern%20design%2C%20blue%20and%20black%20color%20scheme&image_size=square_hd" alt="IntranetPenetrationSuite Logo" width="200">
  
  <h3>🔥 内网 / Web 授权安全测试辅助工具集</h3>
  <p>集成端口探测、子域扫描、指纹识别、Pro 自动挖洞等强大功能</p>
  
  <div style="display: flex; gap: 10px; justify-content: center; margin: 20px 0;">
    <span style="background: #4CAF50; color: white; padding: 5px 10px; border-radius: 5px;">安全合规</span>
    <span style="background: #2196F3; color: white; padding: 5px 10px; border-radius: 5px;">高效扫描</span>
    <span style="background: #FF9800; color: white; padding: 5px 10px; border-radius: 5px;">智能检测</span>
    <span style="background: #9C27B0; color: white; padding: 5px 10px; border-radius: 5px;">详细报告</span>
  </div>
</div>

## 📋 项目概览

IntranetPenetrationSuite 是一款专业的内网与 Web 安全测试工具，专为安全研究人员、渗透测试工程师和企业安全团队设计。我们致力于提供高效、合规、智能的安全测试解决方案，帮助用户快速发现并修复安全漏洞。

### 🌟 核心优势

- **🚀 快速扫描**：支持快速模式，仅测试常见参数和高危漏洞，大幅提升扫描速度
- **⚖️ SRC 合规**：提供安全合规扫描模式，低频率，仅保留核心漏洞检测，符合漏洞平台提交要求
- **🌐 Web 界面**：内置 Flask Web 界面，操作更直观，适合团队协作
- **🤖 AI 集成**：支持 AI 智能扫描和 Kali 工具集成，提升漏洞检测能力
- **🔄 多模式扫描**：支持主动爬取和被动 URL 测试，满足不同场景需求
- **📊 详细报告**：生成 HTML、JSON、Markdown 格式的详细报告，包含 PoC 和修复建议

## 🚨 法律与授权

**仅用于您已获得书面授权的目标（如 SRC 公告明确列出的域名与范围）。** 超出公告范围、未授权扫描可能违法。使用本仓库即表示您知悉并自行承担合规责任。

### SRC 挖洞建议

- 使用 `--scope-file` + `--strict-scope` 锁定公告域名，避免误扫旁站
- 使用 `--checkpoint` / `--resume` 防止长时间任务中断丢进度
- 使用 `--proxy` 对接 Burp 做人工复核；`--proxy-file` 为**代理池轮询**（需自备合法代理）
- 报告用 `--write-html` 生成含 PoC curl、复现步骤、修复建议的 HTML，便于整理提交材料

## 🛠️ 安装

### 📋 环境要求

- **Python 3.7+**：确保安装了合适版本的 Python
- **pip 包管理器**：用于安装项目依赖

### 🚀 安装依赖

```bash
pip install -r requirements.txt
```

### 📦 依赖说明

| 依赖包 | 版本 | 用途 |
|--------|------|------|
| requests | 最新 | HTTP 请求处理 |
| beautifulsoup4 | 最新 | HTML 解析和提取 |
| colorama | 最新 | 终端彩色输出，提升用户体验 |
| flask | 最新 | Web 界面服务 |

## 🚀 快速开始

### 1. 🖥️ 命令行模式

#### Pro 自动挖洞

```bash
# 基础扫描
python main.py -t http://127.0.0.1:8888 --hunt-pro -o hunt_report.json

# 生成 HTML 报告
python main.py -t http://127.0.0.1:8888 --hunt-pro -o hunt_report.json --write-html

# 快速扫描模式
python main.py -t http://127.0.0.1:8888 --hunt-pro --quick-scan

# SRC 合规模式
python main.py -t http://127.0.0.1:8888 --hunt-pro --src-mode

# 被动模式（仅测试提供的 URL 列表）
python main.py -t http://127.0.0.1:8888 --hunt-pro --passive-urls-file urls.txt

# 限制扫描范围
python main.py -t http://127.0.0.1:8888 --hunt-pro --allow-hosts 127.0.0.1,localhost

# 批量扫描
python main.py --targets-file targets.txt --hunt-pro -o batch_report.json
```

#### 完整扫描（端口+子域+指纹+挖洞）

```bash
python main.py -t http://127.0.0.1:8888 --all -o full_report.json
```

### 2. 🌐 Web 界面模式

```bash
# 启动 Web 服务
python web_app.py

# 访问
http://localhost:5000
```

### 3. 🧪 本地演示服务

```bash
# 启动测试服务器（包含 XSS 测试环境）
python test_server.py

# 另开终端进行扫描
python main.py -t http://127.0.0.1:8888 --hunt-pro
```

## 📁 项目结构

```
IntranetPenetrationSuite/
├── main.py            # 主入口文件
├── web_app.py         # Web 界面
├── modules/           # 核心模块
│   ├── auto_hunter_pro.py  # Pro 自动挖洞
│   ├── port_scanner.py     # 端口扫描
│   ├── subdomain_scanner.py # 子域名扫描
│   ├── fingerprint.py      # 指纹识别
│   ├── report.py           # 报告生成
│   ├── ai_orchestrator.py  # AI 智能扫描
│   └── kali_tools_integration.py # Kali 工具集成
├── scripts/           # 辅助脚本
├── tests/             # 测试用例
├── wordlists/         # 字典文件
├── config/            # 配置文件
├── data/              # 数据文件
├── requirements.txt   # 依赖文件
└── README.md          # 项目说明
```

## 🎯 功能特性

### 🚀 核心功能

1. **Pro 自动挖洞**
   - **XSS 漏洞检测**：支持反射型、存储型和 DOM 型 XSS 检测
   - **SQL 注入检测**：支持多种数据库类型的注入测试
   - **命令注入检测**：检测系统命令执行漏洞
   - **开放重定向检测**：识别不安全的重定向参数
   - **越权访问检测**：发现水平和垂直越权漏洞
   - **头部注入检测**：检测 HTTP 头部注入漏洞
   - **HTTP 方法模糊测试**：测试不常见 HTTP 方法的安全性
   - **响应头安全审计**：检查安全相关的 HTTP 响应头配置

2. **端口扫描**
   - **TCP connect 扫描**：快速检测开放端口
   - **常见端口识别**：识别 1000+ 常见服务端口
   - **服务识别**：自动识别运行在端口上的服务类型

3. **子域名扫描**
   - **基于字典的子域名枚举**：使用内置字典快速发现子域名
   - **结果去重**：自动去重，避免重复扫描

4. **指纹识别**
   - **Web 框架识别**：识别 50+ 常见 Web 框架
   - **CMS 识别**：检测主流 CMS 系统版本
   - **服务器软件识别**：识别 Web 服务器、数据库等软件

5. **AI 智能扫描**
   - **自动选择合适的扫描工具**：根据目标特点智能选择扫描策略
   - **智能漏洞检测**：利用 AI 提高漏洞检测准确率
   - **自动利用尝试（可选）**：对发现的漏洞进行验证

### 🎨 扫描模式

| 模式 | 特点 | 适用场景 |
|------|------|----------|
| **正常模式** | 完整功能，深度扫描，全面检测所有类型漏洞 | 详细安全评估、渗透测试 |
| **快速模式** | 仅高危漏洞，快速扫描，节省时间和资源 | 大面积资产筛查、日常安全检查 |
| **SRC 模式** | 安全合规，低频率，符合漏洞平台规则 | 漏洞平台提交、授权安全测试 |

## 🔧 配置说明

### 🖥️ 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-t, --target` | 目标 URL/域名/IP | 无 |
| `--hunt-pro` | 启用 Pro 自动挖洞 | 禁用 |
| `--quick-scan` | 快速扫描模式 | 禁用 |
| `--src-mode` | SRC 合规模式 | 禁用 |
| `--depth` | 爬取深度 | 3 |
| `--threads` | 线程数 | 20 |
| `--timeout` | 请求超时(秒) | 5.0 |
| `--max-crawl-urls` | 最大爬取 URL 数 | 500 |
| `--allow-hosts` | 允许的主机名 | 无 |
| `--scope-file` | 授权域名文件 | 无 |
| `--checkpoint` | 保存/恢复进度 | 无 |
| `--resume` | 从中断处继续 | 禁用 |
| `--proxy` | HTTP 代理 | 无 |
| `-o, --output` | JSON 报告路径 | hunt_report.json |
| `--write-html` | 生成 HTML 报告 | 禁用 |
| `-v, --verbose` | 详细输出 | 禁用 |
| `-q, --quiet` | 静默输出 | 禁用 |

### 配置文件

使用 `config.example.json` 作为模板创建配置文件：

```json
{
  "threads": 20,
  "timeout": 5.0,
  "max_rps": 0,
  "max_retries": 3,
  "max_crawl_urls": 500,
  "enable_xss": true,
  "enable_sqli": true,
  "enable_open_redirect": true,
  "enable_idor": true,
  "enable_header_audit": true,
  "allow_hosts": ["example.com", "www.example.com"]
}
```

## 📊 报告说明

### 📋 报告格式

- **JSON**：详细的结构化数据，便于后续分析和处理
- **HTML**：美观的可视化报告，包含 PoC、复现步骤和修复建议
- **Markdown**：简洁的文本报告，适合快速查看和分享

### 📝 报告内容

- **扫描摘要**：目标信息、扫描时间、发现的漏洞数量和严重程度分布
- **漏洞详情**：漏洞类型、影响 URL、相关参数、测试 Payload、详细描述
- **安全配置检查**：HTTP 响应头配置、CORS 设置、安全证书状态等
- **敏感信息发现**：备份文件、配置文件、API 密钥等敏感信息
- **输入点统计**：表单、URL 参数、Cookie 等输入点的数量和分布
- **修复建议**：针对每个漏洞的详细修复方案和最佳实践

## 🧪 测试

```bash
# 运行测试
pytest tests/ -q

# 详细测试
pytest tests/ -v
```

## 🤝 贡献指南

### 代码规范

- 遵循 PEP 8 代码风格
- 使用有意义的变量和函数名
- 添加适当的注释
- 编写测试用例

### 提交流程

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详情见 [LICENSE](LICENSE) 文件

## 🌟 致谢

- 感谢所有贡献者的努力
- 参考了多个开源安全工具的设计理念
- 使用了多个优秀的第三方库

## 📞 联系方式

- 作者: tudougeneral
- 项目地址: [GitHub Repository](https://github.com/tudougeneral/IntranetPenetrationSuite)

---

**注意**：本工具仅用于授权范围内的安全测试，请勿用于非法用途。使用本工具产生的任何后果由使用者自行承担。
