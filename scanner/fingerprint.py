# -*- coding: utf-8 -*-
"""指纹识别：识别 Web 服务器 / 语言 / 框架"""
import requests

# 页面关键词 → 框架/系统名
FRAMEWORK_MARKS = [
    ("wordpress", "WordPress"),
    ("thinkphp", "ThinkPHP"),
    ("laravel", "Laravel"),
    ("pikachu", "Pikachu"),
    ("dvwa", "DVWA"),
    ("phpmyadmin", "phpMyAdmin"),
]


def fingerprint(url):
    """返回结构化结果（dict）"""
    result = {
        "module": "fingerprint",
        "target": url,
        "alive": False,
        "server": None,
        "language": None,
        "framework": None,
        "headers": {},
    }
    try:
        r = requests.get(url, timeout=5)
    except requests.RequestException as e:
        result["error"] = str(e)
        return result

    result["alive"] = True
    for key in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Frame-Options"):
        if key in r.headers:
            result["headers"][key] = r.headers[key]

    server = r.headers.get("Server", "").lower()
    xp = r.headers.get("X-Powered-By", "").lower()
    if "apache" in server:
        result["server"] = "Apache"
    elif "nginx" in server:
        result["server"] = "Nginx"
    elif "iis" in server:
        result["server"] = "IIS"
    if "php" in xp:
        result["language"] = "PHP"
    if "asp" in xp:
        result["language"] = "ASP.NET"

    body = r.text.lower()
    for kw, name in FRAMEWORK_MARKS:
        if kw in body:
            result["framework"] = name
            break
    return result
