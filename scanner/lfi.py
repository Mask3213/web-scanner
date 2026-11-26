# -*- coding: utf-8 -*-
"""本地文件包含（LFI）检测：目录穿越读取敏感文件"""
import requests
from . import common, config


def lfi_check(url, data=None, param=None):
    """对指定参数做文件包含检测，返回结构化结果"""
    method, base, params = common.parse_target(url, data)
    pname = common.pick_param(params, param)
    result = {
        "module": "lfi",
        "target": url,
        "param": pname,
        "vulnerable": False,
        "payload": None,
        "detail": None,
    }
    if pname is None:
        result["error"] = "目标没有可注入的参数"
        return result

    for path, markers in config.LFI_PAYLOADS:
        p = dict(params)
        p[pname] = path
        try:
            r = common.send(method, base, p)
        except requests.RequestException:
            continue
        body = r.text.lower()
        for marker in markers:
            if marker in body:
                result["vulnerable"] = True
                result["payload"] = path
                result["detail"] = f"成功读取到文件内容（特征：{marker}）"
                result["test"] = common.display(method, base, p)
                return result

    result["detail"] = "未检测到文件包含"
    return result
