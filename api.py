# -*- coding: utf-8 -*-
"""Web 安全扫描器 REST API（FastAPI，异步任务 + SQLite 持久化）

启动：uvicorn api:app --reload --host 127.0.0.1 --port 8000
前端页面：http://127.0.0.1:8000/
接口文档：http://127.0.0.1:8000/docs

扫描流程：POST /scan 提交任务 → 得到 task_id → 轮询 GET /task/{task_id}
历史记录：GET /tasks 列表，DELETE /task/{task_id} 删除，数据存 SQLite（重启不丢）
"""
import json
import os
import sqlite3
import threading
import time
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from urllib.parse import parse_qsl

from scanner import common, fingerprint, sensitive, dirscan, sqli, xss, rce, stored_xss, report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DB_PATH = os.path.join(BASE_DIR, "tasks.db")

app = FastAPI(
    title="Web 安全扫描器",
    description="提供指纹识别、敏感文件检测、目录扫描、SQL 注入、XSS 检测的 REST API（异步任务 + 持久化）",
    version="2.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    return {"name": "Web 安全扫描器", "version": "2.2.0", "docs": "/docs"}


# ---------------- 提交任务（异步） ----------------

@app.post("/scan")
def do_scan(req: ScanRequest):
    task_id = _submit("scan", req.url, lambda: _scan_job(req))
    return {"task_id": task_id, "status": "running"}


@app.post("/sqli")
def do_sqli(req: InjectRequest):
    task_id = _submit("sqli", req.url, lambda: sqli.sqli_check(req.url, data=req.data, param=req.param))
    return {"task_id": task_id, "status": "running"}


@app.post("/xss")
def do_xss(req: InjectRequest):
    session = _login(req)
    task_id = _submit("xss", req.url, lambda: xss.xss_check(req.url, data=req.data, param=req.param, session=session))
    return {"task_id": task_id, "status": "running"}


@app.post("/rce")
def do_rce(req: InjectRequest):
    """命令注入检测：提交后返回 task_id"""
    task_id = _submit("rce", req.url, lambda: rce.rce_check(req.url, data=req.data, param=req.param))
    return {"task_id": task_id, "status": "running"}


@app.post("/stored-xss")
def do_stored_xss(req: InjectRequest):
    """存储型 XSS 检测：提交后返回 task_id"""
    session = _login(req)
    task_id = _submit(
        "stored_xss",
        req.url,
        lambda: stored_xss.stored_xss_check(req.url, param=req.param or "message", session=session),
    )
    return {"task_id": task_id, "status": "running"}


# ---------------- 查询 / 管理任务 ----------------

@app.get("/task/{task_id}")
def get_task(task_id: str):
    with _db_lock:
        conn = _db()
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
    if not row:
        return {"error": "任务不存在"}
    return _row_to_task(row, with_result=True)


@app.get("/tasks")
def list_tasks():
    with _db_lock:
        conn = _db()
        rows = conn.execute("SELECT * FROM tasks ORDER BY created DESC").fetchall()
        conn.close()
    return [_row_to_task(r) for r in rows]


@app.delete("/task/{task_id}")
def delete_task(task_id: str):
    with _db_lock:
        conn = _db()
        conn.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        conn.commit()
        conn.close()
    return {"ok": True}
