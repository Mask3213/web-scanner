# -*- coding: utf-8 -*-
"""存储型 XSS 检测：提交 payload → 访问页面检查是否持久化回显"""
import random
from urllib.parse import parse_qsl
import requests
from . import common


def stored_xss_check(url, param="message", view_url=None, data=None, session=None):
    """对留言/评论类功能做存储型 XSS 检测

    url      提交 payload 的地址（POST）
    view_url 查看结果的地址（GET），默认与 url 相同
    data     提交时额外的 POST 字段（如需要 submit），格式 "k=v&k2=v2"
    """
    view = view_url or url
    result = {
        "module": "stored_xss",
        "target": url,
        "param": param,
        "vulnerable": False,
        "payload": None,
        "detail": None,
    }

    marker = "storedxss" + str(random.randint(100000, 999999))
    payload = f"<script>alert('{marker}')</script>"
    result["payload"] = payload

    submit_params = dict(parse_qsl(data, keep_blank_values=True)) if data else {}
    submit_params[param] = payload

    # 1) 提交 payload（存储）
    try:
        common.send("POST", url, submit_params, session=session)
    except requests.RequestException as e:
        result["error"] = "提交失败: " + str(e)
        return result

    # 2) 访问页面检查是否回显
    try:
        r = common.send("GET", view, {}, session=session)
    except requests.RequestException as e:
        result["error"] = "读取页面失败: " + str(e)
        return result

    if payload in r.text:
        result["vulnerable"] = True
        result["detail"] = "payload 被存储并在页面中回显"
    elif marker in r.text:
        result["detail"] = "payload 被 HTML 转义（未构成 XSS）"
    else:
        result["detail"] = "payload 未回显"
    return result
