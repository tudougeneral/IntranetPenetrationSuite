#!/usr/bin/env python3
"""
报告生成模块 - 生成 HTML / JSON / Markdown 格式的扫描报告
"""

import html as html_module
import json
from datetime import datetime
from colorama import Fore, Style


def write_hunt_html(results, output_file):
    """ProAutoHunter 结果 -> SRC 友好 HTML（描述、复现、修复、风险）。"""
    summary = results.get('summary', {})
    info = results.get('info', {})
    vulns = results.get('vulnerabilities', [])

    cards = []
    for i, v in enumerate(vulns, 1):
        steps = v.get('reproduction_steps') or []
        steps_html = '<ol>' + ''.join(f'<li>{html_module.escape(str(s))}</li>' for s in steps) + '</ol>'
        extra = v.get('extra_payloads') or []
        extra_html = ''
        if extra:
            extra_html = '<p><b>其它 payload 尝试</b>：<code>' + html_module.escape(
                ', '.join(str(x)[:120] for x in extra[:8])
            ) + '</code></p>'
        verified = v.get('verified')
        vtag = (
            '<span class="pill ok">已二次验证</span>'
            if verified is True
            else ('<span class="pill skip">未自动验证</span>' if verified is None else '<span class="pill warn">需人工复核</span>')
        )
        cards.append(
            f"""
<section class="card">
  <div class="card-head">
    <span class="badge">{html_module.escape(str(v.get('type', '')))}</span>
    {vtag}
    <span class="pill sev">{html_module.escape(str(v.get('risk_level', v.get('confidence', ''))))}</span>
    <span class="dedup">dedup_id: <code>{html_module.escape(str(v.get('dedup_id', '')))}</code></span>
  </div>
  <h3>#{i} {html_module.escape(str(v.get('type', '')))}</h3>
  <p><b>漏洞描述</b>：{html_module.escape(str(v.get('evidence', '')))}</p>
  <p><b>风险说明</b>：{html_module.escape(str(v.get('risk_detail', '')))}</p>
  <p><b>参数</b>：<code>{html_module.escape(str(v.get('parameter', '')))}</code>
     &nbsp;|&nbsp; <b>Payload</b>：<code>{html_module.escape(str(v.get('payload', ''))[:400])}</code></p>
  <p><b>URL</b>：<code class="break">{html_module.escape(str(v.get('url', ''))[:800])}</code></p>
  <h4>复现步骤</h4>
  {steps_html}
  <h4>PoC（curl）</h4>
  <pre class="poc">{html_module.escape(str(v.get('poc_curl', '(生成中或见 JSON)')))}</pre>
  <h4>修复建议</h4>
  <p class="fix">{html_module.escape(str(v.get('remediation', '参考 OWASP 对应类别修复。')))}</p>
  {extra_html}
</section>"""
        )

    body_cards = '\n'.join(cards) if cards else '<p class="empty">未发现漏洞条目（或已全部去重）。</p>'

    ha = info.get('header_audit') or []
    ha_html = '<ul class="audit">' + ''.join(
        f'<li>{html_module.escape(str(x))}</li>' for x in ha
    ) + '</ul>' if ha else '<p class="muted">无</p>'

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SRC 漏洞扫描报告 — IntranetPenetrationSuite</title>
  <style>
    :root {{ --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8; --ok: #4ade80; --warn: #fbbf24; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; background: var(--bg); color: var(--text); line-height: 1.55; }}
    .wrap {{ max-width: 960px; margin: 0 auto; padding: 28px 20px 60px; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 8px; }}
    .meta {{ background: var(--card); padding: 16px 20px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #334155; }}
    .meta b {{ color: var(--accent); }}
    .card {{ background: var(--card); border-radius: 12px; padding: 20px 22px; margin-bottom: 20px; border: 1px solid #334155; }}
    .card-head {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }}
    .badge {{ background: #7c3aed; color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }}
    .pill {{ font-size: 11px; padding: 3px 8px; border-radius: 999px; }}
    .pill.ok {{ background: #14532d; color: #86efac; }}
    .pill.warn {{ background: #713f12; color: #fde68a; }}
    .pill.skip {{ background: #334155; color: var(--muted); }}
    .pill.sev {{ background: #991b1b; color: #fecaca; }}
    .dedup {{ font-size: 11px; color: var(--muted); margin-left: auto; }}
    h3 {{ margin: 0 0 12px; font-size: 1.15rem; }}
    h4 {{ color: var(--accent); font-size: 0.95rem; margin: 16px 0 8px; }}
    pre.poc {{ background: #0f172a; padding: 14px; border-radius: 8px; overflow-x: auto; font-size: 13px; border: 1px solid #334155; }}
    .fix {{ background: #172554; padding: 12px 14px; border-radius: 8px; border-left: 4px solid var(--accent); }}
    code.break {{ word-break: break-all; font-size: 12px; }}
    .audit {{ color: var(--muted); }}
    .muted {{ color: var(--muted); }}
    .empty {{ color: var(--muted); text-align: center; padding: 40px; }}
    footer {{ text-align: center; color: var(--muted); font-size: 12px; margin-top: 40px; }}
  </style>
</head>
<body>
<div class="wrap">
  <h1>SRC 漏洞扫描报告</h1>
  <p style="color:var(--muted);margin-top:0;">IntranetPenetrationSuite Pro Hunt — 请在授权范围内使用</p>
  <div class="meta">
    <b>目标</b>：{html_module.escape(str(summary.get('target', '')))}<br>
    <b>时间</b>：{html_module.escape(str(summary.get('start_time', '')))} → {html_module.escape(str(summary.get('end_time', '')))}<br>
    <b>统计</b>：漏洞 {summary.get('total_vulnerabilities', 0)} 条（已按类型+路径+参数去重） |
    备份 {summary.get('backup_files_found', 0)} |
    敏感目录 {summary.get('sensitive_dirs_found', 0)} |
    输入点 {summary.get('input_points_found', 0)}
  </div>
  <h2 style="font-size:1.1rem;">漏洞详情</h2>
  {body_cards}
  <h2 style="font-size:1.1rem;">响应头审计</h2>
  {ha_html}
  <footer>Generated by IntranetPenetrationSuite | 提交 SRC 前请脱敏并遵守平台规则</footer>
</div>
</body>
</html>"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(doc)


def write_hunt_markdown(results, output_file):
    lines = ['# SRC / Pro Hunt 报告\n\n']
    s = results.get('summary', {})
    lines.append(f"- **目标**: `{s.get('target', '')}`\n")
    lines.append(f"- **漏洞数**: {s.get('total_vulnerabilities', 0)}\n\n")
    for i, v in enumerate(results.get('vulnerabilities', []), 1):
        lines.append(f"## {i}. {v.get('type', '')} (`{v.get('dedup_id', '')}`)\n\n")
        lines.append(f"- **风险**: {v.get('risk_level', '')} — {v.get('risk_detail', '')}\n")
        lines.append(f"- **验证**: {v.get('verified')}\n")
        lines.append(f"- **URL**: `{v.get('url', '')}`\n")
        lines.append(f"- **参数**: `{v.get('parameter', '')}`\n\n")
        lines.append('### 复现步骤\n\n')
        for step in v.get('reproduction_steps') or []:
            lines.append(f'1. {step}\n')
        lines.append('\n### PoC\n\n```bash\n' + str(v.get('poc_curl', '')) + '\n```\n\n')
        lines.append('### 修复建议\n\n' + str(v.get('remediation', '')) + '\n\n---\n\n')
    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines(lines)


def generate_html_report(scan_results, output_file):
    """
    生成HTML格式报告
    scan_results: 字典格式的扫描结果
    output_file: 输出文件路径
    """
    html_template = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>渗透测试报告 - IntranetPenetrationSuite</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            background: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
        }}
        .info {{
            background: #d1ecf1;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }}
        .vuln-high {{
            background: #f8d7da;
            border-left: 5px solid #dc3545;
            padding: 10px;
            margin: 10px 0;
        }}
        .vuln-medium {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 10px;
            margin: 10px 0;
        }}
        .vuln-low {{
            background: #d1ecf1;
            border-left: 5px solid #17a2b8;
            padding: 10px;
            margin: 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            color: #7f8c8d;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 渗透测试报告</h1>
        <div class="info">
            <strong>生成时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>目标:</strong> {scan_results.get('target', 'N/A')}<br>
            <strong>扫描类型:</strong> {scan_results.get('scan_type', 'N/A')}
        </div>

        <h2>📊 扫描摘要</h2>
        <table>
             <tr><th>项目</th><th>数量</th></tr>
             <tr><td>开放端口</td><td>{len(scan_results.get('ports', []))}</td></tr>
             <tr><td>子域名</td><td>{len(scan_results.get('subdomains', []))}</td></tr>
             <tr><td>敏感目录</td><td>{len(scan_results.get('directories', []))}</td></tr>
             <tr><td>SQL注入</td><td>{len(scan_results.get('sql_injections', []))}</td></tr>
             <tr><td>XSS漏洞</td><td>{len(scan_results.get('xss_vulns', []))}</td></tr>
        </table>

        <h2>🖥️ 开放端口</h2>
        {generate_port_table(scan_results.get('ports', []))}

        <h2>🌐 子域名</h2>
        {generate_subdomain_table(scan_results.get('subdomains', []))}

        <h2>📁 敏感目录</h2>
        {generate_directory_table(scan_results.get('directories', []))}

        <h2>⚠️ 漏洞详情</h2>
        {generate_vuln_section(scan_results)}

        <div class="footer">
            Generated by IntranetPenetrationSuite | Author: tudougeneral
        </div>
    </div>
</body>
</html>"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_template)

    print(f"{Fore.GREEN}[+] 报告已生成: {output_file}{Style.RESET_ALL}")


def generate_port_table(ports):
    if not ports:
        return "<p>未扫描或未发现开放端口</p>"
    html = "<table><tr><th>端口</th><th>服务</th></tr>"
    for port in ports:
        html += f"<tr><td>{port.get('port', 'N/A')}</td><td>{port.get('service', 'unknown')}</td></tr>"
    html += "</table>"
    return html


def generate_subdomain_table(subdomains):
    if not subdomains:
        return "<p>未扫描或未发现子域名</p>"
    html = "<table><tr><th>子域名</th><th>IP</th></tr>"
    for sub in subdomains:
        html += f"<tr><td>{sub.get('domain', 'N/A')}</td><td>{sub.get('ip', 'N/A')}</td></tr>"
    html += "</table>"
    return html


def generate_directory_table(directories):
    if not directories:
        return "<p>未扫描或未发现敏感目录</p>"
    html = "<table><tr><th>目录</th><th>状态码</th></tr>"
    for d in directories:
        html += f"<tr><td>{d.get('path', 'N/A')}</td><td>{d.get('status', 'N/A')}</td></tr>"
    html += "</table>"
    return html


def generate_vuln_section(scan_results):
    html = ""

    sql_vulns = scan_results.get('sql_injections', [])
    if sql_vulns:
        for vuln in sql_vulns:
            html += f"""
            <div class="vuln-high">
                <strong>[高危] SQL注入漏洞</strong><br>
                URL: {vuln.get('url', 'N/A')}<br>
                参数: {vuln.get('parameter', 'N/A')}<br>
                Payload: {vuln.get('payload', 'N/A')}
            </div>"""

    xss_vulns = scan_results.get('xss_vulns', [])
    if xss_vulns:
        for vuln in xss_vulns:
            html += f"""
            <div class="vuln-medium">
                <strong>[中危] XSS漏洞</strong><br>
                URL: {vuln.get('url', 'N/A')}<br>
                参数: {vuln.get('parameter', 'N/A')}<br>
                Payload: {vuln.get('payload', 'N/A')}
            </div>"""

    if not sql_vulns and not xss_vulns:
        html = "<p>未发现漏洞</p>"

    return html


def generate_json_report(scan_results, output_file):
    """生成JSON格式报告"""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(scan_results, f, indent=4, ensure_ascii=False)
    print(f"{Fore.GREEN}[+] JSON报告已生成: {output_file}{Style.RESET_ALL}")


if __name__ == '__main__':
    test_results = {
        'target': 'example.com',
        'scan_type': 'full',
        'ports': [{'port': 80, 'service': 'http'}, {'port': 443, 'service': 'https'}],
        'subdomains': [{'domain': 'www.example.com', 'ip': '1.1.1.1'}],
        'directories': [{'path': '/admin', 'status': 200}],
        'sql_injections': [],
        'xss_vulns': []
    }
    generate_html_report(test_results, 'report.html')
