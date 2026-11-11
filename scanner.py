import argparse
import threading
import requests

  # 常见敏感路径（后续改成读 dict.txt 字典文件）
DEFAULT_PATHS = [
      "admin", "login", "robots.txt", ".git/config",
      "index.php.bak", "config.php.bak", "backup.zip",
      "phpinfo.php", "upload", "test",
  ]

def scan(base_url, path):
      url = base_url.rstrip("/") + "/" + path.lstrip("/")
      try:
          r = requests.get(url, timeout=5, allow_redirects=False)
          # 有"内容"或"需要登录/跳转"的状态码才值得看
          if r.status_code in (200, 301, 302, 403):
              print(f"[{r.status_code}] {url}")
      except requests.RequestException:
          pass  # 超时/连不上，跳过

def main():
      parser = argparse.ArgumentParser(description="简易目录扫描器")
      parser.add_argument("-u", "--url", required=True, help="目标，如 http://127.0.0.1/dvwa")
      parser.add_argument("-t", "--threads", type=int, default=10, help="线程数")
      args = parser.parse_args()

      threads = []
      for path in DEFAULT_PATHS:
          t = threading.Thread(target=scan, args=(args.url, path))
          threads.append(t)
          t.start()
      for t in threads:
          t.join()

if __name__ == "__main__":
      main()