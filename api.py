# -*- coding: utf-8 -*-
"""Web 安全扫描器 REST API（FastAPI，异步任务版）

启动：uvicorn api:app --reload --host 127.0.0.1 --port 8000
前端页面：http://127.0.0.1:8000/
接口文档：http://127.0.0.1:8000/docs

扫描流程（异步）：POST /scan 提交任务 → 得到 task_id → 轮询 GET /task/{task_id}
"""
import os
import threading
import time
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from scanner import common, fingerprint, sensitive, dirscan, sqli, xss, report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = FastAPI(
    title="Web 安全扫描器",
    description="提供指纹识别、敏感文件检测、目录扫描、SQL 注入、XSS 检测的 REST API（异步任务）",
    version="2.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 内存中的任务表：task_id -> {"status", "result", "created"}
# 注意：重启服务会清空（演示用）；生产环境应换成 Redis / 数据库
TASKS = {}


class ScanRequest(BaseModel):
    url: str = Field(..., description="目标地址，如 http://127.0.0.1/pikachu")
    wordlist: str = Field("dict.txt", description="目录字典路径")
    threads: int = Field(20, ge=1, le=200, description="目录扫描线程数")


class InjectRequest(BaseModel):
    url: str = Field(..., description="带参数的 URL")
    data: str | None = Field(None, description="POST 请求体，如 name=1")
    param: str | None = Field(None, description="指定参数名")


# ---------- 扫描任务逻辑 ----------

def _scan_job(req: ScanRequest):
    """完整扫描任务体"""
    ok, code = common.target_alive(req.url)
    if not ok:
        return {"target": req.url, "alive": False, "error": "目标无法连接"}
    findings = [fingerprint.fingerprint(req.url)]
    findings.extend(sensitive.sensitive_check(req.url))
    findings.extend(dirscan.dir_scan(req.url, common.load_wordlist(req.wordlist), req.threads))
    return report.build_report(req.url, findings)


def _submit(job):
    """提交一个后台任务，返回 task_id"""
    task_id = uuid.uuid4().hex[:12]
    TASKS[task_id] = {"status": "running", "result": None, "created": time.time()}

    def wrapper():
        try:
            TASKS[task_id]["result"] = job()
            TASKS[task_id]["status"] = "done"
        except Exception as e:  # noqa: BLE001
            TASKS[task_id]["status"] = "error"
            TASKS[task_id]["error"] = str(e)

    threading.Thread(target=wrapper, daemon=True).start()
    return task_id


# ---------- 页面 ----------

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/info")
def info():
    return {"name": "Web 安全扫描器", "version": "2.1.0", "docs": "/docs"}


# ---------- 提交任务（异步） ----------

@app.post("/scan")
def do_scan(req: ScanRequest):
    """完整扫描：提交后返回 task_id"""
    task_id = _submit(lambda: _scan_job(req))
    return {"task_id": task_id, "status": "running"}


@app.post("/sqli")
def do_sqli(req: InjectRequest):
    """SQL 注入检测：提交后返回 task_id"""
    task_id = _submit(lambda: sqli.sqli_check(req.url, data=req.data, param=req.param))
    return {"task_id": task_id, "status": "running"}


@app.post("/xss")
def do_xss(req: InjectRequest):
    """反射型 XSS 检测：提交后返回 task_id"""
    task_id = _submit(lambda: xss.xss_check(req.url, data=req.data, param=req.param))
    return {"task_id": task_id, "status": "running"}


# ---------- 查询任务 ----------

@app.get("/task/{task_id}")
def get_task(task_id: str):
    """查询任务状态与结果"""
    if task_id not in TASKS:
        return {"error": "任务不存在"}
    return TASKS[task_id]


@app.get("/tasks")
def list_tasks():
    """列出所有任务"""
    return [{"task_id": k, "status": v["status"]} for k, v in TASKS.items()]
