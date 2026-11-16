# -*- coding: utf-8 -*-
"""敏感文件检测：.git、.env、备份文件等配置泄露"""
import requests

SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config", ".svn/entries", ".env",
    "config.php.bak", "index.php.bak", "index.php~",
    "database.sql", "db.sql", "backup.zip", "www.zip",
    "phpinfo.php", "test.php",
]


def sensitive_check(url):
    """返回发现列表（list[dict]）"""
    findings = []
    for p in SENSITIVE_PATHS:
        u = url.rstrip("/") + "/" + p
        try:
            r = requests.get(u, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                findings.append({"module": "sensitive", "url": u, "size": len(r.content)})
        except requests.RequestException:
            pass
    return findings
