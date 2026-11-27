# -*- coding: utf-8 -*-
"""CSRF 检测：检查页面表单是否缺少 CSRF token"""
import re
import requests
from . import common

# CSRF token 字段常见命名（name 里含这些关键词）
TOKEN_RE = re.compile(r'name=["\'][^"\']*(?:csrf|_token|token|authenticity)[^"\']*["\']', re.I)


def csrf_check(url, session=None):
    """检测页面里的表单是否缺少 CSRF 防护，返回结构化结果"""
    result = {
        "module": "csrf",
        "target": url,
        "vulnerable": False,
        "payload": None,
        "detail": None,
    }
    req = session if session else requests
    try:
        r = req.get(url, timeout=5)
    except requests.RequestException as e:
        result["error"] = str(e)
        return result

    html = r.text
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", html, re.S | re.I)
    result["forms"] = len(forms)

    no_token = 0
    for form in forms:
        has_token = bool(TOKEN_RE.search(form))
        # 有输入框或按钮的表单才需要 CSRF 防护
        has_input = bool(re.search(r"<input\b|<button\b", form, re.I))
        if has_input and not has_token:
            no_token += 1

    if no_token > 0:
        result["vulnerable"] = True
        result["detail"] = f"发现 {no_token} 个表单缺少 CSRF token 防护"
    else:
        result["detail"] = f"检测了 {len(forms)} 个表单，均有 CSRF 防护或无敏感表单"
    return result
