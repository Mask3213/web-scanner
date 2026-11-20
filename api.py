# -*- coding: utf-8 -*-
"""Web 安全扫描器 REST API（FastAPI）

启动：uvicorn api:app --reload --host 127.0.0.1 --port 8000
接口文档：http://127.0.0.1:8000/docs
"""
from fastapi import FastAPI
from pydantic import BaseModel, Field

from scanner import common, fingerprint, sensitive, dirscan, sqli, xss, report

app = FastAPI(
    title="Web 安全扫描器",
    description="提供指纹识别、敏感文件检测、目录扫描、SQL 注入、XSS 检测的 REST API",
    version="2.0.0",
)


class ScanRequest(BaseModel):
    url: str = Field(..., description="目标地址，如 http://127.0.0.1/pikachu")
    wordlist: str = Field("dict.txt", description="目录字典路径")
    threads: int = Field(20, ge=1, le=200, description="目录扫描线程数")


class InjectRequest(BaseModel):
    url: str = Field(..., description="带参数的 URL")
    data: str | None = Field(None, description="POST 请求体，如 name=1")
    param: str | None = Field(None, description="指定参数名")


@app.get("/")
def root():
    return {"name": "Web 安全扫描器", "docs": "/docs", "version": "2.0.0"}


@app.post("/scan")
def do_scan(req: ScanRequest):
    """完整扫描：指纹识别 + 敏感文件检测 + 目录扫描"""
    ok, code = common.target_alive(req.url)
    if not ok:
        return {"target": req.url, "alive": False, "error": "目标无法连接"}
    findings = []
    findings.append(fingerprint.fingerprint(req.url))
    findings.extend(sensitive.sensitive_check(req.url))
    findings.extend(dirscan.dir_scan(req.url, common.load_wordlist(req.wordlist), req.threads))
    return report.build_report(req.url, findings)


@app.post("/sqli")
def do_sqli(req: InjectRequest):
    """SQL 注入检测（错误回显 + 布尔盲注 + 时间盲注）"""
    return sqli.sqli_check(req.url, data=req.data, param=req.param)


@app.post("/xss")
def do_xss(req: InjectRequest):
    """反射型 XSS 检测"""
    return xss.xss_check(req.url, data=req.data, param=req.param)
