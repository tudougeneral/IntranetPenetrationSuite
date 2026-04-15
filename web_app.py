#!/usr/bin/env python3
"""
IntranetPenetrationSuite - Web 界面
"""

from flask import Flask, render_template_string, request, jsonify
from modules.auto_hunter_pro import ProAutoHunter
import threading
import json
import os

app = Flask(__name__)

# 存储扫描任务状态
scans = {}

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IntranetPenetrationSuite - 自动化漏洞扫描</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        h1 {
            font-size: 2.5em;
            color: white;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .subtitle {
            color: rgba(255,255,255,0.8);
            font-size: 1.1em;
        }
        .card {
            background: white;
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 25px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        input[type="text"] {
            width: 100%;
            padding: 14px;
            font-size: 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .radio-group {
            display: flex;
            gap: 20px;
            margin-top: 10px;
        }
        .radio-option {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
        }
        .radio-option input[type="radio"] {
            accent-color: #667eea;
        }
        button {
            width: 100%;
            padding: 15px;
            font-size: 18px;
            font-weight: bold;
            border: none;
            border-radius: 8px;
            background: linear-gradient(90deg, #667eea, #764ba2);
            color: white;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .result-card {
            background: white;
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .vuln-critical { color: #ff4444; border-left: 4px solid #ff4444; padding-left: 15px; margin: 10px 0; }
        .vuln-high { color: #ff8844; border-left: 4px solid #ff8844; padding-left: 15px; margin: 10px 0; }
        .vuln-medium { color: #ffcc44; border-left: 4px solid #ffcc44; padding-left: 15px; margin: 10px 0; }
        .vuln-low { color: #44ff44; border-left: 4px solid #44ff44; padding-left: 15px; margin: 10px 0; }
        .info { color: #44aaff; }
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid #fff;
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .stat {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        .stat-number {
            font-size: 1.8em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }
        .footer {
            text-align: center;
            padding: 30px 0;
            color: rgba(255,255,255,0.7);
            font-size: 0.9em;
        }
        h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 IntranetPenetrationSuite</h1>
            <div class="subtitle">自动化漏洞扫描工具 | 输入网址，一键检测</div>
        </div>

        <div class="card">
            <div class="form-group">
                <label for="target">目标URL</label>
                <input type="text" id="target" placeholder="请输入目标URL (例如: http://example.com)" value="http://xyh.ecut.edu.cn">
            </div>
            
            <div class="form-group">
                <label>扫描模式</label>
                <div style="space-y: 10px;">
                    <label class="radio-option" style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px;">
                        <input type="radio" name="scan_mode" value="normal" checked style="margin-top: 2px;">
                        <div>
                            <span style="font-weight: 600;">正常</span>
                            <span style="display: block; font-size: 0.9em; color: #666; margin-top: 3px;">完整功能，包括所有漏洞检测</span>
                        </div>
                    </label>
                    <label class="radio-option" style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px;">
                        <input type="radio" name="scan_mode" value="quick" style="margin-top: 2px;">
                        <div>
                            <span style="font-weight: 600;">快速</span>
                            <span style="display: block; font-size: 0.9em; color: #666; margin-top: 3px;">仅测试常见参数和高危漏洞</span>
                        </div>
                    </label>
                    <label class="radio-option" style="display: flex; align-items: flex-start; gap: 10px;">
                        <input type="radio" name="scan_mode" value="src" style="margin-top: 2px;">
                        <div>
                            <span style="font-weight: 600;">SRC</span>
                            <span style="display: block; font-size: 0.9em; color: #666; margin-top: 3px;">安全合规扫描，低频率</span>
                        </div>
                    </label>
                </div>
            </div>
            
            <div class="form-group">
                <label>输出模式</label>
                <div style="space-y: 10px;">
                    <label class="radio-option" style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px;">
                        <input type="radio" name="output_mode" value="normal" checked style="margin-top: 2px;">
                        <div>
                            <span style="font-weight: 600;">正常</span>
                            <span style="display: block; font-size: 0.9em; color: #666; margin-top: 3px;">显示扫描进度和结果</span>
                        </div>
                    </label>
                    <label class="radio-option" style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px;">
                        <input type="radio" name="output_mode" value="quiet" style="margin-top: 2px;">
                        <div>
                            <span style="font-weight: 600;">静默</span>
                            <span style="display: block; font-size: 0.9em; color: #666; margin-top: 3px;">只显示最终结果</span>
                        </div>
                    </label>
                    <label class="radio-option" style="display: flex; align-items: flex-start; gap: 10px;">
                        <input type="radio" name="output_mode" value="verbose" style="margin-top: 2px;">
                        <div>
                            <span style="font-weight: 600;">详细</span>
                            <span style="display: block; font-size: 0.9em; color: #666; margin-top: 3px;">显示所有调试信息</span>
                        </div>
                    </label>
                </div>
            </div>
            
            <button onclick="startScan()" id="scanBtn">开始扫描</button>
        </div>

        <div id="result" style="display: none;">
            <div class="result-card">
                <h3>📊 扫描结果</h3>
                <div class="stats" id="stats"></div>
                <div id="vulns"></div>
                <div id="info"></div>
            </div>
        </div>

        <div class="footer">
            ⚠️ 仅用于授权测试 | 禁止未授权扫描
        </div>
    </div>

    <script>
        let scanId = null;

        function startScan() {
            const target = document.getElementById('target').value;
            if (!target) {
                alert('请输入目标URL');
                return;
            }

            // 获取选中的扫描模式
            const scanMode = document.querySelector('input[name="scan_mode"]:checked').value;
            // 获取选中的输出模式
            const outputMode = document.querySelector('input[name="output_mode"]:checked').value;

            document.getElementById('scanBtn').disabled = true;
            document.getElementById('scanBtn').innerHTML = '<span class="loading"></span> 扫描中...';
            document.getElementById('result').style.display = 'none';

            fetch('/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: target, scan_mode: scanMode, output_mode: outputMode})
            })
            .then(res => res.json())
            .then(data => {
                scanId = data.scan_id;
                checkStatus();
            });
        }

        function checkStatus() {
            fetch(`/status/${scanId}`)
            .then(res => res.json())
            .then(data => {
                if (data.status === 'completed') {
                    showResults(data.result);
                    document.getElementById('scanBtn').disabled = false;
                    document.getElementById('scanBtn').innerHTML = '开始扫描';
                } else if (data.status === 'running') {
                    document.getElementById('scanBtn').innerHTML = `扫描中... ${data.progress || ''}`;
                    setTimeout(checkStatus, 2000);
                } else {
                    document.getElementById('scanBtn').disabled = false;
                    document.getElementById('scanBtn').innerHTML = '开始扫描';
                    alert('扫描失败: ' + data.error);
                }
            });
        }

        function showResults(result) {
            const summary = result.summary;
            const vulns = result.vulnerabilities;

            // 统计
            const statsHtml = `
                <div class="stat"><div class="stat-number">${summary.total_vulnerabilities || 0}</div><div class="stat-label">总漏洞数</div></div>
                <div class="stat"><div class="stat-number">${summary.input_points_found || 0}</div><div class="stat-label">输入点</div></div>
                <div class="stat"><div class="stat-number">${summary.backup_files_found || 0}</div><div class="stat-label">备份文件</div></div>
                <div class="stat"><div class="stat-number">${summary.sensitive_dirs_found || 0}</div><div class="stat-label">敏感目录</div></div>
            `;
            document.getElementById('stats').innerHTML = statsHtml;

            // 漏洞列表
            let vulnsHtml = '<h3>⚠️ 发现的漏洞</h3>';
            if (vulns.length === 0) {
                vulnsHtml += '<p class="info">✅ 未发现漏洞</p>';
            } else {
                for (const v of vulns) {
                    const level = v.risk_level || 'low';
                    vulnsHtml += `
                        <div class="vuln-${level}">
                            <strong>[${v.type}]</strong> ${v.url}<br>
                            <small>参数: ${v.parameter} | Payload: ${v.payload}</small>
                        </div>
                    `;
                }
            }
            document.getElementById('vulns').innerHTML = vulnsHtml;

            // 信息
            let infoHtml = '<h3>📋 安全配置检查</h3>';
            if (result.info && result.info.header_audit) {
                for (const h of result.info.header_audit) {
                    infoHtml += `<div class="info">⚠️ ${h.detail}</div>`;
                }
            }
            document.getElementById('info').innerHTML = infoHtml;

            document.getElementById('result').style.display = 'block';
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    scan_mode = data.get('scan_mode', 'normal')
    output_mode = data.get('output_mode', 'normal')

    if not target:
        return jsonify({'error': '缺少目标URL'}), 400

    import uuid
    scan_id = str(uuid.uuid4())[:8]

    scans[scan_id] = {'status': 'running', 'result': None, 'progress': 0}

    def run_scan():
        try:
            from modules.auto_hunter_pro import ProAutoHunter
            from urllib.parse import urlparse
            
            # 解析目标主机，自动设置扫描范围，防止误扫外部域名导致漏扫或误扫
            parsed = urlparse(target)
            host = parsed.hostname
            allow_hosts = [host] if host else None
            
            # 根据输出模式设置 verbose 和 quiet
            verbose = output_mode == 'verbose'
            quiet = output_mode == 'quiet'
            
            # 根据扫描模式配置
            if scan_mode == 'quick':
                # 快速扫描模式
                hunter = ProAutoHunter(
                    threads=20,  # 适中的线程数
                    timeout=5,  # 较短的超时时间
                    max_rps=10,  # 适当的速率限制
                    max_retries=2,  # 较少的重试次数
                    max_crawl_urls=200,  # 较少的爬取URL数
                    verbose=verbose,
                    quiet=quiet,
                    allow_hosts=allow_hosts,
                    enable_json_fuzz=False,  # 禁用JSON模糊测试
                    enable_open_redirect=False,  # 禁用开放重定向检测
                    enable_idor=False,  # 禁用越权检测
                    enable_header_audit=True,  # 启用头部审计
                    strict_scope=False,
                    verify_poc=False,  # 禁用漏洞验证
                    enable_file_upload=False,  # 禁用文件上传检测
                    enable_weak_credentials=False,  # 禁用弱口令检测
                    enable_backup_scan=False,  # 禁用备份文件扫描
                    enable_directory_scan=False,  # 禁用目录扫描
                    enable_xss=True,  # 启用XSS检测
                    enable_sqli=True,  # 启用SQL注入检测
                    src_mode=False,  # 禁用SRC模式
                    quick_scan=True,  # 启用快速扫描
                )
            elif scan_mode == 'src':
                # SRC模式
                hunter = ProAutoHunter(
                    threads=3,  # 低线程数
                    timeout=10,  # 合理的超时时间
                    max_rps=2,  # 低速率限制
                    max_retries=3,  # 适当的重试次数
                    max_crawl_urls=100,  # 较少的爬取URL数
                    verbose=verbose,
                    quiet=quiet,
                    allow_hosts=allow_hosts,
                    enable_json_fuzz=False,  # 禁用JSON模糊测试
                    enable_open_redirect=False,  # 禁用开放重定向检测
                    enable_idor=False,  # 禁用越权检测
                    enable_header_audit=True,  # 启用头部审计
                    strict_scope=False,
                    verify_poc=True,  # 启用漏洞验证
                    enable_file_upload=False,  # 禁用文件上传检测
                    enable_weak_credentials=False,  # 禁用弱口令检测
                    enable_backup_scan=False,  # 禁用备份文件扫描
                    enable_directory_scan=False,  # 禁用目录扫描
                    enable_xss=True,  # 启用XSS检测
                    enable_sqli=True,  # 启用SQL注入检测
                    src_mode=True,  # 启用SRC模式
                    quick_scan=False,  # 禁用快速扫描
                )
            else:
                # 正常扫描模式
                hunter = ProAutoHunter(
                    threads=20,  # 适中的线程数
                    timeout=5,  # 较短的超时时间
                    max_rps=20,  # 适当的速率限制
                    max_retries=2,  # 较少的重试次数
                    max_crawl_urls=300,  # 合理的爬取URL数
                    verbose=verbose,
                    quiet=quiet,
                    allow_hosts=allow_hosts,
                    enable_json_fuzz=False,  # 禁用JSON模糊测试
                    enable_open_redirect=False,  # 禁用开放重定向检测
                    enable_idor=False,  # 禁用越权检测
                    enable_header_audit=True,  # 启用头部审计
                    strict_scope=False,
                    verify_poc=False,  # 禁用漏洞验证
                    enable_file_upload=False,  # 禁用文件上传检测
                    enable_weak_credentials=False,  # 禁用弱口令检测
                    enable_backup_scan=False,  # 禁用备份文件扫描
                    enable_directory_scan=False,  # 禁用目录扫描
                    enable_xss=True,  # 启用XSS检测
                    enable_sqli=True,  # 启用SQL注入检测
                    src_mode=False,  # 禁用SRC模式
                    quick_scan=False,  # 禁用快速扫描
                )
            
            # 使用 depth=3 深度扫描（与 CLI 增强版一致）
            result = hunter.hunt(target, depth=3)
            scans[scan_id]['result'] = result
            scans[scan_id]['status'] = 'completed'
        except Exception as e:
            scans[scan_id]['status'] = 'failed'
            scans[scan_id]['error'] = str(e)

    threading.Thread(target=run_scan).start()

    return jsonify({'scan_id': scan_id})


@app.route('/status/<scan_id>')
def get_status(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'status': 'not_found'}), 404

    return jsonify({
        'status': scan['status'],
        'result': scan.get('result'),
        'progress': scan.get('progress', 0),
        'error': scan.get('error')
    })


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     IntranetPenetrationSuite - Web 界面                       ║
    ║     访问: http://localhost:5000                               ║
    ║     Ctrl+C 停止服务                                           ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=5000, debug=False)