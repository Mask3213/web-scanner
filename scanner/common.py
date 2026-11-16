# -*- coding: utf-8 -*-
"""通用工具：字典加载、目标存活探测"""
import requests


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
