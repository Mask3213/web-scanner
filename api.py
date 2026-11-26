# -*- coding: utf-8 -*-
"""Web 安全扫描器 REST API（FastAPI，异步任务 + SQLite 持久化）

启动：uvicorn api:app --reload --host 127.0.0.1 --port 8000
前端页面：http://127.0.0.1:8000/
接口文档：http://127.0.0.1:8000/docs

扫描流程：POST /scan 提交任务 → 得到 task_id → 轮询 GET /task/{task_id}
历史记录：GET /tasks 列表，DELETE /task/{task_id} 删除，数据存 SQLite（重启不丢）
"""
from collections import deque

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from urllib.parse import parse_qsl

from scanner import common, config, fingerprint, sensitive, dirscan, sqli, xss, rce, stored_xss, lfi, upload, report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DB_PATH = os.path.join(BASE_DIR, "tasks.db")

app = FastAPI(
    title="Web 安全扫描器",
    description="提供指纹识别、敏感文件检测、目录扫描、SQL 注入、XSS、命令注入、存储型 XSS 检测的 REST API（异步任务 + 持久化 + API Key 鉴权）",
    version="2.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- 限流（防滥用） ----------------
RATE_LIMIT = int(os.environ.get("SCANNER_RATE_LIMIT", str(config.RATE_LIMIT)))      # 每窗口最多请求数
RATE_WINDOW = float(os.environ.get("SCANNER_RATE_WINDOW", str(config.RATE_WINDOW)))  # 窗口秒数
_rate_records = {}     # ip -> deque[时间戳]
_rate_lock = threading.Lock()


@app.middleware("http")
async def rate_limit(request, call_next):
    """按 IP 滑动窗口限流：超过阈值返回 429"""
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    with _rate_lock:
        rec = _rate_records.setdefault(ip, deque())
        while rec and now - rec[0] > RATE_WINDOW:
            rec.popleft()
        if len(rec) >= RATE_LIMIT:
            return JSONResponse(status_code=429, content={"detail": "请求过于频繁，请稍后再试"})
        rec.append(now)
    return await call_next(request)


class ScanRequest(BaseModel):
    url: str = Field(..., description="目标地址，如 http://127.0.0.1/pikachu")
    wordlist: str = Field("dict.txt", description="目录字典路径")
    threads: int = Field(20, ge=1, le=200, description="目录扫描线程数")


class InjectRequest(BaseModel):
    url: str = Field(..., description="带参数的 URL")
    data: str | None = Field(None, description="POST 请求体，如 name=1")
    param: str | None = Field(None, description="指定参数名")
    login_url: str | None = Field(None, description="登录页地址（可选，需要登录的靶子用）")
    login_data: str | None = Field(None, description="登录表单数据，如 username=admin&password=123456&submit=1")


class LoginRequest(BaseModel):
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


# ---------------- SQLite 存储 ----------------
_db_lock = threading.Lock()


def _db():
    """返回一个新连接（每次操作独立连接，加锁避免并发写冲突）"""
    return sqlite3.connect(DB_PATH, timeout=10)


def _init_db():
    with _db_lock:
        conn = _db()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                mode TEXT,
                target TEXT,
                status TEXT,
                result TEXT,
                created REAL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                salt TEXT,
                api_key TEXT
            )
            """
        )
        conn.commit()
        conn.close()


def _insert_task(task_id, mode, target):
    with _db_lock:
        conn = _db()
        conn.execute(
            "INSERT INTO tasks VALUES (?,?,?,?,?,?)",
            (task_id, mode, target, "running", None, time.time()),
        )
        conn.commit()
        conn.close()


def _update_task(task_id, status, result):
    with _db_lock:
        conn = _db()
        conn.execute(
            "UPDATE tasks SET status=?, result=? WHERE id=?",
            (status, json.dumps(result, ensure_ascii=False), task_id),
        )
        conn.commit()
        conn.close()


def _row_to_task(row, with_result=False):
    task = {"task_id": row[0], "mode": row[1], "target": row[2], "status": row[3], "created": row[5]}
    if with_result:
        task["result"] = json.loads(row[4]) if row[4] else None
    return task


_init_db()


# ---------------- 鉴权 ----------------

def _hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100000).hex()


def _gen_api_key():
    return secrets.token_hex(24)


def _init_auth():
    """初始化用户表；没有用户时创建默认 admin 账号"""
    with _db_lock:
        conn = _db()
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        if row[0] == 0:
            salt = secrets.token_hex(16)
            default_pw = os.environ.get("SCANNER_ADMIN_PASSWORD", config.ADMIN_PASSWORD)
            conn.execute(
                "INSERT INTO users VALUES (?,?,?,?)",
                (config.ADMIN_USERNAME, _hash_password(default_pw, salt), salt, _gen_api_key()),
            )
            print(f"[*] 已创建默认管理员账号：{config.ADMIN_USERNAME} / {default_pw}")
        conn.commit()
        conn.close()


def _verify_user(username, password):
    with _db_lock:
        conn = _db()
        row = conn.execute("SELECT username, password_hash, salt, api_key FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
    if row and _hash_password(password, row[2]) == row[1]:
        return {"username": row[0], "api_key": row[3]}
    return None


def _valid_api_key(api_key):
    with _db_lock:
        conn = _db()
        row = conn.execute("SELECT username FROM users WHERE api_key=?", (api_key,)).fetchone()
        conn.close()
    return row is not None


# 登录失败锁定（防暴力破解）
_login_failures = {}   # username -> {"count": int, "locked_until": float}
_login_lock = threading.Lock()


def _check_locked(username):
    """返回 (是否锁定, 剩余秒数)"""
    with _login_lock:
        rec = _login_failures.get(username)
        if rec and rec["locked_until"] > time.time():
            return True, int(rec["locked_until"] - time.time())
        return False, 0


def _record_failure(username):
    with _login_lock:
        rec = _login_failures.setdefault(username, {"count": 0, "locked_until": 0})
        rec["count"] += 1
        if rec["count"] >= config.MAX_LOGIN_FAILURES:
            rec["locked_until"] = time.time() + config.LOCKOUT_SECONDS
            rec["count"] = 0


def _reset_failures(username):
    with _login_lock:
        _login_failures.pop(username, None)


def require_api_key(x_api_key: str = Header(None)):
    """FastAPI 依赖：校验请求头里的 X-API-Key"""
    if not x_api_key or not _valid_api_key(x_api_key):
        raise HTTPException(status_code=401, detail="无效或缺失的 API Key（请在请求头加 X-API-Key）")
    return x_api_key


_init_auth()


# ---------------- 扫描任务 ----------------

def _scan_job(req: ScanRequest):
    ok, code = common.target_alive(req.url)
    if not ok:
        return {"target": req.url, "alive": False, "error": "目标无法连接"}
    findings = [fingerprint.fingerprint(req.url)]
    findings.extend(sensitive.sensitive_check(req.url))
    findings.extend(dirscan.dir_scan(req.url, common.load_wordlist(req.wordlist), req.threads))
    return report.build_report(req.url, findings)


def _submit(mode, target, job):
    task_id = uuid.uuid4().hex[:12]
    _insert_task(task_id, mode, target)

    def wrapper():
        try:
            _update_task(task_id, "done", job())
        except Exception as e:  # noqa: BLE001
            _update_task(task_id, "error", {"error": str(e)})

    threading.Thread(target=wrapper, daemon=True).start()
    return task_id


def _login(req: InjectRequest):
    """如果请求里带了登录信息，就登录并返回 session"""
    if req.login_url:
        data = dict(parse_qsl(req.login_data or "", keep_blank_values=True))
        return common.login(req.login_url, data)
    return None


# ---------------- 页面 ----------------

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/info")
def info():
    return {"name": "Web 安全扫描器", "version": "2.3.0", "docs": "/docs"}


@app.post("/login")
def login(req: LoginRequest):
    """登录获取 API Key（用账号密码换 key）"""
    locked, remain = _check_locked(req.username)
    if locked:
        raise HTTPException(status_code=429, detail=f"失败次数过多，账号已锁定，请 {remain} 秒后再试")
    user = _verify_user(req.username, req.password)
    if not user:
        _record_failure(req.username)
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    _reset_failures(req.username)
    return {"username": user["username"], "api_key": user["api_key"]}


# ---------------- 提交任务（异步） ----------------

@app.post("/scan")
def do_scan(req: ScanRequest, api_key: str = Depends(require_api_key)):
    task_id = _submit("scan", req.url, lambda: _scan_job(req))
    return {"task_id": task_id, "status": "running"}


@app.post("/sqli")
def do_sqli(req: InjectRequest, api_key: str = Depends(require_api_key)):
    task_id = _submit("sqli", req.url, lambda: sqli.sqli_check(req.url, data=req.data, param=req.param))
    return {"task_id": task_id, "status": "running"}


@app.post("/xss")
def do_xss(req: InjectRequest, api_key: str = Depends(require_api_key)):
    session = _login(req)
    task_id = _submit("xss", req.url, lambda: xss.xss_check(req.url, data=req.data, param=req.param, session=session))
    return {"task_id": task_id, "status": "running"}


@app.post("/rce")
def do_rce(req: InjectRequest, api_key: str = Depends(require_api_key)):
    """命令注入检测：提交后返回 task_id"""
    task_id = _submit("rce", req.url, lambda: rce.rce_check(req.url, data=req.data, param=req.param))
    return {"task_id": task_id, "status": "running"}


@app.post("/stored-xss")
def do_stored_xss(req: InjectRequest, api_key: str = Depends(require_api_key)):
    """存储型 XSS 检测：提交后返回 task_id"""
    session = _login(req)
    task_id = _submit(
        "stored_xss",
        req.url,
        lambda: stored_xss.stored_xss_check(req.url, param=req.param or "message", session=session),
    )
    return {"task_id": task_id, "status": "running"}


@app.post("/lfi")
def do_lfi(req: InjectRequest, api_key: str = Depends(require_api_key)):
    """文件包含(LFI)检测：提交后返回 task_id"""
    task_id = _submit("lfi", req.url, lambda: lfi.lfi_check(req.url, data=req.data, param=req.param))
    return {"task_id": task_id, "status": "running"}


@app.post("/upload")
def do_upload(req: InjectRequest, api_key: str = Depends(require_api_key)):
    """任意文件上传检测：提交后返回 task_id"""
    session = _login(req)
    task_id = _submit("upload", req.url, lambda: upload.upload_check(req.url, session=session))
    return {"task_id": task_id, "status": "running"}


# ---------------- 查询 / 管理任务 ----------------

@app.get("/task/{task_id}")
def get_task(task_id: str, api_key: str = Depends(require_api_key)):
    with _db_lock:
        conn = _db()
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
    if not row:
        return {"error": "任务不存在"}
    return _row_to_task(row, with_result=True)


@app.get("/tasks")
def list_tasks(api_key: str = Depends(require_api_key)):
    with _db_lock:
        conn = _db()
        rows = conn.execute("SELECT * FROM tasks ORDER BY created DESC").fetchall()
        conn.close()
    return [_row_to_task(r) for r in rows]


@app.delete("/task/{task_id}")
def delete_task(task_id: str, api_key: str = Depends(require_api_key)):
    with _db_lock:
        conn = _db()
        conn.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        conn.commit()
        conn.close()
    return {"ok": True}
