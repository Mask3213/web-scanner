# -*- coding: utf-8 -*-
"""Web 安全扫描器（入门版）
功能：1) 指纹识别  2) 敏感文件检测  3) 目录扫描  4) SQL 注入检测
"""
import argparse
import threading
import requests
from queue import Queue, Empty
from urllib.parse import quote_plus


# ============ 通用 ============
def load_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# ============ 模块 1：指纹识别 ============
def fingerprint(url):
    """读取响应头 + 页面关键词，识别 Web 服务器 / 语言 / 框架"""
    print("\n[*] 指纹识别")
    try:
        r = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"    [!] 连接失败: {e}")
        return

    h = r.headers
    for key in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Frame-Options"):
        if key in h:
            print(f"    {key}: {h[key]}")

    server = h.get("Server", "").lower()
    xp = h.get("X-Powered-By", "").lower()
    if "apache" in server:
        print("    → Web 服务器: Apache")
    elif "nginx" in server:
        print("    → Web 服务器: Nginx")
    elif "iis" in server:
        print("    → Web 服务器: IIS")
    if "php" in xp:
        print("    → 语言: PHP")
    if "asp" in xp:
        print("    → 语言: ASP.NET")

    body = r.text.lower()
    for kw, name in [("wordpress", "WordPress"), ("thinkphp", "ThinkPHP"),
                     ("laravel", "Laravel"), ("pikachu", "Pikachu"),
                     ("dvwa", "DVWA"), ("phpmyadmin", "phpMyAdmin")]:
        if kw in body:
            print(f"    → 识别到: {name}")


# ============ 模块 2：敏感文件检测 ============
SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config", ".svn/entries", ".env",
    "config.php.bak", "index.php.bak", "index.php~",
    "database.sql", "db.sql", "backup.zip", "www.zip",
    "phpinfo.php", "test.php",
]

def sensitive_check(url):
    """检测泄露的敏感文件 / 配置备份（高危项）"""
    print("\n[*] 敏感文件检测")
    found = 0
    for p in SENSITIVE_PATHS:
        u = url.rstrip("/") + "/" + p
        try:
            r = requests.get(u, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                found += 1
                print(f"    [高危] {u}  ({len(r.content)} 字节)")
        except requests.RequestException:
            pass
    if found == 0:
        print("    未发现敏感文件泄露")


# ============ 模块 3：目录扫描 ============
def dir_worker(base_url, q, lock):
    while True:
        try:
            path = q.get_nowait()
        except Empty:
            return
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                with lock:
                    print(f"    [{r.status_code}] {url}")
        except requests.RequestException:
            pass
        finally:
            q.task_done()


def dir_scan(url, wordlist, threads):
    print(f"\n[*] 目录扫描 | 字典 {len(wordlist)} 条 | 线程 {threads}")
    q = Queue()
    for p in wordlist:
        q.put(p)
    lock = threading.Lock()
    for _ in range(threads):
        t = threading.Thread(target=dir_worker, args=(url, q, lock))
        t.daemon = True
        t.start()
    q.join()


# ============ 模块 4：SQL 注入检测 ============
# 数据库报错时常见的错误关键字
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "warning: mysql",
    "mysql server",
    "syntax error",
    "unclosed quotation mark",
]

def inject(url, payload):
    """把 payload 追加到 URL 参数值后面（自动 URL 编码）"""
    return url + quote_plus(payload)

def sqli_check(url):
    """对带参数的 URL 做 SQL 注入检测（错误回显 + 布尔盲注）"""
    print(f"\n[*] SQL 注入检测: {url}")

    # 1) 基线请求（正常访问）
    try:
        base = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"    [!] 连接失败: {e}")
        return
    print(f"    基线: 状态码 {base.status_code} | 长度 {len(base.content)}")

    # 2) 错误回显测试：参数值后加一个单引号，看会不会报 SQL 语法错误
    inj = inject(url, "'")
    try:
        r = requests.get(inj, timeout=5)
    except requests.RequestException:
        r = None

    if r is not None:
        body = r.text.lower()
        for marker in SQL_ERRORS:
            if marker in body:
                print("    [高危] 错误回显型 SQL 注入")
                print(f"    命中特征: {marker}")
                print(f"    测试 URL: {inj}")
                return

    # 3) 布尔盲注测试：1=1 恒真 vs 1=2 恒假，比较两次响应长度
    true_url = inject(url, "' OR '1'='1")
    false_url = inject(url, "' AND '1'='2")
    try:
        r_true = requests.get(true_url, timeout=5)
        r_false = requests.get(false_url, timeout=5)
    except requests.RequestException:
        print("    布尔测试请求失败")
        return

    diff = abs(len(r_true.content) - len(r_false.content))
    print(f"    布尔测试: 真 {len(r_true.content)} 字节 | 假 {len(r_false.content)} 字节 | 差值 {diff}")
    if diff > 50:
        print("    [高危] 疑似布尔盲注（两次响应差异明显）")
    else:
        print("    未发现明显注入（可进一步用时间盲注检测）")


# ============ 主入口 ============
def main():
    parser = argparse.ArgumentParser(description="Web 安全扫描器（入门版）")
    parser.add_argument("-u", "--url", help="目标基地址，如 http://127.0.0.1/pikachu")
    parser.add_argument("-w", "--wordlist", default="dict.txt", help="目录字典路径")
    parser.add_argument("-t", "--threads", type=int, default=20, help="目录扫描线程数")
    parser.add_argument("--sqli", metavar="URL",
                        help="对指定带参数的 URL 做 SQL 注入检测，如 http://127.0.0.1/pikachu/vul/sqli/sqli_str.php?id=1")
    args = parser.parse_args()

    # SQL 注入模式：单独跑，不跑目录扫描
    if args.sqli:
        sqli_check(args.sqli)
        return

    if not args.url:
        parser.error("请提供 -u 目标地址，或用 --sqli 指定注入测试目标")

    fingerprint(args.url)
    sensitive_check(args.url)
    dir_scan(args.url, load_wordlist(args.wordlist), args.threads)
    print("\n[*] 扫描完成")


if __name__ == "__main__":
    main()
