# -*- coding: utf-8 -*-
"""命令注入（RCE）检测：注入额外系统命令，看输出是否回显"""
import random
import requests
from . import common


def rce_check(url, data=None, param=None):
    """对指定参数做命令注入检测，返回结构化结果"""
    method, base, params = common.parse_target(url, data)
    pname = common.pick_param(params, param)
    result = {
        "module": "rce",
        "target": url,
        "param": pname,
        "vulnerable": False,
        "payload": None,
        "detail": None,
    }
    if pname is None:
        result["error"] = "目标没有可注入的参数"
        return result
    orig = params.get(pname, "")

    # 带随机数的标记，用来确认"回显的是我们注入的命令"
    marker = "rcemark" + str(random.randint(100000, 999999))

    # 兼容 Windows(&) 和 Linux(;) 的命令分隔符
    seps = [" & echo ", "; echo "]

    for sep in seps:
        p = dict(params)
        p[pname] = orig + sep + marker
        try:
            r = common.send(method, base, p)
        except requests.RequestException:
            continue
        if marker in r.text:
            result["vulnerable"] = True
            result["payload"] = orig + sep + marker
            result["detail"] = "注入的命令输出回显在页面中"
            result["test"] = common.display(method, base, p)
            return result

    result["detail"] = "未检测到命令执行回显"
    return result
