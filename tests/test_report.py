# -*- coding: utf-8 -*-
"""report 模块单元测试"""
import json
from scanner import report


def test_build_report():
    rep = report.build_report("http://x.com", [{"module": "dir", "status": 200, "url": "http://x.com/a"}])
    assert rep["target"] == "http://x.com"
    assert "time" in rep
    assert len(rep["findings"]) == 1


def test_save_json(tmp_path):
    rep = {"target": "x", "findings": []}
    p = tmp_path / "r.json"
    report.save_json(rep, str(p))
    assert json.loads(p.read_text(encoding="utf-8")) == rep


def test_save_html(tmp_path):
    rep = {
        "target": "x",
        "time": "t",
        "findings": [{"module": "sqli", "vulnerable": True, "technique": "错误回显", "payload": "1'"}],
    }
    p = tmp_path / "r.html"
    report.save_html(rep, str(p))
    html = p.read_text(encoding="utf-8")
    assert "Web 安全扫描报告" in html
    assert "存在漏洞" in html
