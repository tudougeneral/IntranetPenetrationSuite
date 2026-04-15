#!/usr/bin/env python3
"""本地测试服务器 - 模拟 XSS 漏洞"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class VulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # 获取 name 参数
        name = params.get('name', [''])[0]

        # 直接输出参数内容（存在XSS漏洞）
        html = f"""<!DOCTYPE html>
<html>
<head><title>XSS Test</title></head>
<body>
<h1>XSS 漏洞测试页面</h1>
<form method="GET" action="/">
    <input type="text" name="name" value="{name}">
    <input type="submit" value="提交">
</form>
<div>你输入的内容是: {name}</div>
</body>
</html>"""

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8888), VulnHandler)
    print('服务器启动: http://localhost:8888')
    server.serve_forever()