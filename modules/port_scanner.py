#!/usr/bin/env python3
"""TCP 连接扫描（授权范围内使用）。"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211,
)


def _check_port(host: str, port: int, timeout: float) -> tuple:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        err = sock.connect_ex((host, port))
        return port, err == 0
    except OSError:
        return port, False
    finally:
        sock.close()


def scan(host: str, ports=None, threads: int = 50, timeout: float = 1.5):
    """
    对 host 做 TCP connect 扫描。
    返回 [{'port': int, 'open': bool, 'service': str}, ...]（仅开放端口列表由调用方过滤）。
    """
    host = host.strip()
    if host.startswith('http://') or host.startswith('https://'):
        from urllib.parse import urlparse
        host = urlparse(host).hostname or host
    ports = list(ports or COMMON_PORTS)
    open_ports = []
    with ThreadPoolExecutor(max_workers=min(threads, len(ports) or 1)) as ex:
        futs = {ex.submit(_check_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            port, ok = fut.result()
            if ok:
                open_ports.append({'port': port, 'open': True, 'service': _guess_service(port)})
    open_ports.sort(key=lambda x: x['port'])
    return open_ports


def _guess_service(port: int) -> str:
    names = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http',
        443: 'https', 445: 'smb', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
        6379: 'redis', 8080: 'http-alt', 8443: 'https-alt', 9200: 'elasticsearch',
    }
    return names.get(port, 'unknown')
