# -*- coding: utf-8 -*-
"""全局配置：集中管理所有可调参数（改这里，不用改业务代码）"""

# ---------- HTTP ----------
TIMEOUT = 5            # 单次请求超时（秒）

# ---------- 目录扫描 ----------
DEFAULT_WORDLIST = "dict.txt"
DEFAULT_THREADS = 20

# ---------- SQL 注入 ----------
SLEEP_SEC = 3                        # 时间盲注的 sleep 秒数
BOOLEAN_DIFF_THRESHOLD = 50          # 布尔盲注响应长度差阈值（字节）
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "warning: mysql",
    "mysql server",
    "syntax error",
    "unclosed quotation mark",
]

# ---------- 敏感文件 ----------
SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config", ".svn/entries", ".env",
    "config.php.bak", "index.php.bak", "index.php~",
    "database.sql", "db.sql", "backup.zip", "www.zip",
    "phpinfo.php", "test.php",
]

# ---------- 文件包含（LFI） ----------
# (目录穿越 payload, 成功包含时页面会出现的文件内容特征)
LFI_PAYLOADS = [
    ("../../../../../../windows/win.ini", ["[fonts]", "[extensions]"]),
    ("../../../../../../../../etc/passwd", ["root:"]),
    ("../../../../../../../../etc/hosts", ["localhost"]),
]

# ---------- 文件上传 ----------
UPLOAD_FILE_FIELD = "uploadfile"
UPLOAD_SUBMIT_FIELD = "submit"

# ---------- 服务 ----------
RATE_LIMIT = 60        # 每窗口最大请求数
RATE_WINDOW = 60       # 窗口秒数
MAX_LOGIN_FAILURES = 5      # 连续失败 N 次后锁定账号
LOCKOUT_SECONDS = 300       # 锁定时长（秒）
ADMIN_USERNAME = "Mask"
ADMIN_PASSWORD = "258456"   # 可通过环境变量 SCANNER_ADMIN_PASSWORD 覆盖
