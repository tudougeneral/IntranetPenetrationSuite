#!/usr/bin/env python3
import os
import requests
import json

class AIVerifier:
    def __init__(self, api_key=None, api_base="https://api.deepseek.com/v1"):
        self.api_key = api_key or os.getenv("AI_API_KEY")
        self.api_base = api_base
        self.enabled = self.api_key is not None

    def verify_vulnerability(self, vuln_type, url, payload, response_text):
        """使用 AI 对漏洞进行二次验证"""
        if not self.enabled:
            return None, "AI Verification Disabled"

        prompt = f"""
        你是一个专业的安全专家。请分析以下 Web 响应是否包含真正的漏洞。
        
        漏洞类型: {vuln_type}
        目标 URL: {url}
        使用的 Payload: {payload}
        
        响应正文 (前 1000 字符):
        {response_text[:1000]}
        
        请判断：
        1. 是否为真实漏洞 (True/False)
        2. 置信度 (0.0 - 1.0)
        3. 简短理由
        4. 修复建议
        
        请以 JSON 格式返回。
        """

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            data = {
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"}
            }
            resp = requests.post(f"{self.api_base}/chat/completions", headers=headers, json=data, timeout=10)
            if resp.status_code == 200:
                result = resp.json()['choices'][0]['message']['content']
                return json.loads(result), None
        except Exception as e:
            return None, str(e)
        
        return None, "Unknown error"
