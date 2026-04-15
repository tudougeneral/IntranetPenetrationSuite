"""SRC 报告用：修复建议、风险说明（与漏洞类型对应）。"""

REMEDIATION = {
    'XSS': (
        '对用户可控输出按上下文进行编码（HTML 实体、JavaScript、URL 等）；启用内容安全策略（CSP）；'
        '在模板引擎中默认开启自动转义。'
    ),
    'SQL注入': (
        '使用参数化查询（PreparedStatement 等）或 ORM 绑定参数；避免拼接 SQL；'
        '数据库账号遵循最小权限；可配合 WAF 作为纵深防御。'
    ),
    '命令注入': (
        '避免将用户输入传入系统 shell；若必须调用外部命令，使用白名单并严格校验参数；'
        '优先使用带参数列表的 API（如 subprocess 列表形式）而非 shell=True。'
    ),
    'SSRF': (
        '对目标 URL 使用白名单或解析后校验 host 不允许内网/元数据地址；'
        '禁用不必要的协议（file、gopher 等）；出站请求经代理审计。'
    ),
    '路径遍历': (
        '使用规范路径（realpath）并校验结果仍在允许目录内；禁止用户控制完整文件路径；'
        '文件访问使用 ID 映射而非原始路径字符串。'
    ),
    '开放重定向': (
        '跳转目标使用服务端维护的 token→URL 映射，或仅允许相对路径且校验不以 // 开头；'
        '禁止直接把查询参数作为 Location。'
    ),
    'CORS 风险': (
        '勿同时使用 Access-Control-Allow-Origin: * 与 Allow-Credentials: true；'
        '按业务精确回显 Origin 并校验白名单。'
    ),
    'CORS 信息': '评估业务是否需要跨域；若不需要则收紧 ACAO。',
    'Cookie': '对敏感 Cookie 设置 HttpOnly、Secure、SameSite；避免前端脚本读取会话标识。',
    '安全头缺失': '按需补全 X-Frame-Options、CSP、X-Content-Type-Options 等安全响应头。',
}

RISK_LABEL = {
    'high': '高 — 可导致数据泄露、代码执行或严重业务影响，建议优先修复。',
    'medium': '中 — 可利用性依赖场景，建议在迭代内修复。',
    'low': '低 — 信息级或利用条件苛刻，可排期处理。',
}


def remediation_for(vuln_type: str) -> str:
    return REMEDIATION.get(vuln_type, '根据 OWASP 对应类别进行修复与代码审计。')


def risk_description(confidence: str) -> str:
    return RISK_LABEL.get((confidence or 'low').lower(), RISK_LABEL['low'])
