#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试扫描功能
"""

import json
import time
from datetime import datetime

# 添加项目根目录到Python路径
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.auto_hunter_pro import ProAutoHunter


def test_scan():
    """
    测试扫描功能
    """
    print("[*] 测试扫描功能...")
    
    # 测试目标
    test_url = "https://www.sjzc.edu.cn"
    
    try:
        # 初始化扫描器
        hunter = ProAutoHunter(
            threads=5,
            timeout=5,
            max_rps=0,
            max_retries=2,
            max_crawl_urls=100,
            verbose=True,
            quiet=False
        )
        
        print(f"[+] 开始扫描: {test_url}")
        
        # 执行扫描
        result = hunter.hunt(test_url, depth=1)
        
        print(f"[+] 扫描完成")
        print(f"[+] 发现漏洞: {len(result.get('vulnerabilities', []))}")
        print(f"[+] 扫描摘要: {result.get('summary', {})}")
        
        # 保存结果
        output_file = f"test_scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print(f"[+] 结果已保存到: {output_file}")
        
    except Exception as e:
        print(f"[!] 扫描失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    # 忽略SSL警告
    import warnings
    warnings.filterwarnings('ignore')
    
    test_scan()
