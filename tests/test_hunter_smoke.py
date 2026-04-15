"""轻量单元测试（不依赖外网）。"""
import os
import sys

import pytest

# 保证可 import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_passive_inputs_parses_query():
    from modules.auto_hunter_pro import ProAutoHunter

    h = ProAutoHunter(max_rps=0, threads=1)
    lines = ['http://example.com/page?foo=1&bar=2']
    inputs = h.inputs_from_passive_urls(lines)
    names = {i['name'] for i in inputs}
    assert names == {'foo', 'bar'}


def test_allow_hosts_blocks_foreign():
    from modules.auto_hunter_pro import ProAutoHunter

    h = ProAutoHunter(allow_hosts={'example.com'}, max_rps=0, threads=1)
    lines = ['http://evil.com/?x=1']
    assert h.inputs_from_passive_urls(lines) == []


def test_host_allowed():
    from modules.auto_hunter_pro import ProAutoHunter

    h = ProAutoHunter(allow_hosts={'127.0.0.1'}, max_rps=0, threads=1)
    assert h._host_allowed('http://127.0.0.1:8080/')
    assert not h._host_allowed('http://192.168.1.1/')


def test_port_scanner_returns_list():
    from modules.port_scanner import scan

    r = scan('127.0.0.1', ports=[65533], threads=1, timeout=0.3)
    assert isinstance(r, list)


def test_report_hunt_html(tmp_path):
    from modules.report import write_hunt_html

    p = tmp_path / 'o.html'
    write_hunt_html(
        {
            'summary': {'target': 't', 'start_time': '', 'end_time': '', 'total_vulnerabilities': 0},
            'vulnerabilities': [{'type': 'XSS', 'confidence': 'high', 'parameter': 'n', 'url': 'u', 'payload': 'p', 'evidence': 'e'}],
            'info': {'header_audit': []},
        },
        str(p),
    )
    assert p.read_text(encoding='utf-8').find('XSS') >= 0
