# -*- coding: utf-8 -*-
"""反射型 XSS 检测"""
import random
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def xss_check(url):
    """返回结构化结果（dict）"""
    result = {
        "module": "xss",
        "target": url,
        "vulnerable": False,
        "payload": None,
        "test_url": None,
        "detail": None,
    }

    marker = "xsstest" + str(random.randint(100000, 999999))
    payload = f"<script>alert('{marker}')</script>"
    result["payload"] = payload

    parts = urlparse(url)
    if not parts.query:
        result["detail"] = "URL 无参数（?key=value），无法测反射型 XSS"
        return result

    # 把所有参数的值都替换成 payload，再重新编码
    qs = parse_qs(parts.query, keep_blank_values=True)
    for k in qs:
        qs[k] = [payload]
    test_url = urlunparse((parts.scheme, parts.netloc, parts.path,
                           parts.params, urlencode(qs, doseq=True), parts.fragment))
    result["test_url"] = test_url

    try:
        r = requests.get(test_url, timeout=5)
    except requests.RequestException as e:
        result["error"] = str(e)
        return result

    if payload in r.text:
        result["vulnerable"] = True
        result["detail"] = "payload 原样回显，未做 HTML 转义"
    elif marker in r.text:
        result["detail"] = "payload 被 HTML 转义（< 变成 &lt;）"
    else:
        result["detail"] = "payload 未回显"
    return result
