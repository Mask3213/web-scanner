# -*- coding: utf-8 -*-
"""任意文件上传检测：上传含危险扩展名的文件，看是否被接受"""
import random
import requests
from . import common, config


def upload_check(url, file_field=None, submit_field=None, session=None):
    """对文件上传点做检测，返回结构化结果

    url          上传接口地址（form action）
    file_field   文件表单字段名（默认 config.UPLOAD_FILE_FIELD）
    submit_field 提交按钮字段名（默认 config.UPLOAD_SUBMIT_FIELD）
    """
    file_field = file_field or config.UPLOAD_FILE_FIELD
    submit_field = submit_field or config.UPLOAD_SUBMIT_FIELD
    result = {
        "module": "upload",
        "target": url,
        "vulnerable": False,
        "payload": None,
        "detail": None,
    }

    marker = "uploadmark" + str(random.randint(100000, 999999))
    # 危险扩展名 .php：任其上传，等于可挂 webshell / 拿服务器权限
    filename = f"{marker}.php"
    content = f"<?php echo '{marker}'; ?>"

    files = {file_field: (filename, content, "application/octet-stream")}
    data = {submit_field: "1"}

    req = session if session else requests
    try:
        r = req.post(url, files=files, data=data, timeout=10)
    except requests.RequestException as e:
        result["error"] = str(e)
        return result

    body = r.text
    if "上传成功" in body or "保存的路径" in body or "new_path" in body:
        result["vulnerable"] = True
        result["payload"] = filename
        result["detail"] = "危险扩展名(.php)文件被接受，存在任意文件上传"
    else:
        result["detail"] = "上传被拦截或未成功"
    return result
