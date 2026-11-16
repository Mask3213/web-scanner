# -*- coding: utf-8 -*-
"""反射型 XSS 检测（支持 GET / POST）"""
import random
import requests
from . import common


def xss_check(url, data=None, param=None):
    """对指定参数做反射型 XSS 检测，返回结构化结果"""
    method, base, params = common.parse_target(url, data)
    pname = common.pick_param(params, param)
    result = {
        "module": "xss",
        "target": url,
        "param": pname,
        "vulnerable": False,
        "payload": None,
        "test": None,
        "detail": None,
    }
    if pname is None:
        result["error"] = "目标没有可注入的参数"
        return result

    marker = "xsstest" + str(random.randint(100000, 999999))
    payload = f"<script>alert('{marker}')</script>"
    result["payload"] = payload

    # 用 payload 直接替换参数值
    params[pname] = payload
    result["test"] = common.display(method, base, params)

    try:
        r = common.send(method, base, params)
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
