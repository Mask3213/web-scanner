# -*- coding: utf-8 -*-
"""目录扫描：多线程 + 字典爆破"""
import threading
import requests
from queue import Queue, Empty


def dir_scan(url, wordlist, threads):
    """返回发现列表（list[dict]）"""
    findings = []
    q = Queue()
    for p in wordlist:
        q.put(p)
    lock = threading.Lock()

    def worker():
        while True:
            try:
                path = q.get_nowait()
            except Empty:
                return
            u = url.rstrip("/") + "/" + path.lstrip("/")
            try:
                r = requests.get(u, timeout=5, allow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    with lock:
                        findings.append({"module": "dir", "status": r.status_code, "url": u})
            except requests.RequestException:
                pass
            finally:
                q.task_done()

    ts = [threading.Thread(target=worker) for _ in range(threads)]
    for t in ts:
        t.daemon = True
        t.start()
    q.join()
    return findings
