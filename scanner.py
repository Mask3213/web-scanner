# -*- coding: utf-8 -*-
"""简易目录扫描器 —— 第 1 阶段（读字典版）"""
import argparse
import threading
import requests
from queue import Queue, Empty

def load_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        # 跳过空行和 # 开头的注释行
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def worker(base_url, q, lock):
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
                    print(f"[{r.status_code}] {url}")
        except requests.RequestException:
            pass
        finally:
            q.task_done()

def main():
    parser = argparse.ArgumentParser(description="简易目录扫描器")
    parser.add_argument("-u", "--url", required=True, help="目标，如 http://127.0.0.1/pikachu")
    parser.add_argument("-w", "--wordlist", default="dict.txt", help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=20, help="线程数")
    args = parser.parse_args()

    paths = load_wordlist(args.wordlist)
    print(f"[*] 目标 {args.url} | 字典 {len(paths)} 条 | 线程 {args.threads}")

    q = Queue()
    for p in paths:
        q.put(p)

    lock = threading.Lock()
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(args.url, q, lock))
        t.daemon = True
        t.start()

    q.join()
    print("[*] 扫描完成")

if __name__ == "__main__":
    main()
