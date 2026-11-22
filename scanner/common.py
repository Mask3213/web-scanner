# -*- coding: utf-8 -*-
"""通用工具：字典加载、目标存活探测、请求构造"""
import requests
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl


def load_wordlist(path):
    """读取字典文件，跳过空行和 # 开头的注释行"""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def target_alive(url):
    """扫描前先探测目标是否存活，返回 (是否可达, 状态码)"""
    try:
        r = requests.get(url, timeout=5)
        return True, r.status_code
    except requests.RequestException:
        return False, None


def parse_target(url, data=None):
    """解析目标 → (method, base_url, params)
    data 为 None → GET（参数在 URL query 里）
    data 为 "k=v&k2=v2" → POST（参数在 body 里）
    """
    if data is not None:
        return "POST", url, dict(parse_qsl(data, keep_blank_values=True))
    parts = urlparse(url)
    base = urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, "", parts.fragment))
    return "GET", base, dict(parse_qsl(parts.query, keep_blank_values=True))


def pick_param(params, param=None):
    """选择要注入的参数：优先用指定的，否则选第一个非 submit 的参数"""
    if param:
        return param
    for k in params:
        if k.lower() != "submit":
            return k
    return next(iter(params), None)


def send(method, url, params, timeout=5, session=None):
    """按方法发请求（GET 用 query，POST 用 body）；可传入带登录态的 Session"""
    req = session if session else requests
    if method == "POST":
        return req.post(url, data=params, timeout=timeout)
    return req.get(url, params=params, timeout=timeout)


def login(login_url, data):
    """登录并返回带 cookie 的 Session（用于需要登录的靶子）"""
    s = requests.Session()
    s.post(login_url, data=data, timeout=5)
    return s


def display(method, url, params):
    """构造可读的请求描述（用于报告展示）"""
    qs = urlencode(params)
    if method == "POST":
        return f"{url}  (POST body: {qs})"
    return f"{url}?{qs}"
