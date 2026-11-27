# -*- coding: utf-8 -*-
"""更多检测模块单元测试（mock HTTP，不需要靶场）"""
from unittest import mock

from scanner import rce, upload, stored_xss, sensitive, csrf, config


def _mk(content=b"", text=""):
    r = mock.Mock()
    r.content = content
    r.text = text
    r.status_code = 200
    return r


def test_rce():
    def fake_send(method, url, params, timeout=5, session=None):
        return _mk(text=next(iter(params.values())))  # 回显注入的命令输出

    with mock.patch("scanner.common.send", side_effect=fake_send):
        r = rce.rce_check("http://x.com/rce", data="ipaddress=127.0.0.1&submit=1")
    assert r["vulnerable"] is True


def test_upload():
    def fake_post(url, files=None, data=None, timeout=10):
        return _mk(text="文件上传成功，文件保存的路径为：uploads/x.php")

    with mock.patch("scanner.upload.requests.post", side_effect=fake_post):
        r = upload.upload_check("http://x.com/upload")
    assert r["vulnerable"] is True


def test_stored_xss():
    captured = {}

    def fake_send(method, url, params, timeout=5, session=None):
        if method == "POST":
            captured["payload"] = next(iter(params.values()))  # 提交时记下 payload
            return _mk(text="ok")
        return _mk(text=captured.get("payload", ""))  # 查看时回显

    with mock.patch("scanner.common.send", side_effect=fake_send):
        r = stored_xss.stored_xss_check("http://x.com/xss_stored.php")
    assert r["vulnerable"] is True


def test_sensitive_found():
    def fake_get(url, timeout=5, allow_redirects=False):
        return _mk(content=b"x")

    with mock.patch("scanner.sensitive.requests.get", side_effect=fake_get):
        res = sensitive.sensitive_check("http://x.com")
    assert len(res) == len(config.SENSITIVE_PATHS)
    assert all(f["module"] == "sensitive" for f in res)


def test_csrf_vulnerable():
    def fake_get(url, timeout=5):
        return _mk(text='<form method="get"><input type="text" name="sex"><input type="submit"></form>')

    with mock.patch("scanner.csrf.requests.get", side_effect=fake_get):
        r = csrf.csrf_check("http://x.com/edit")
    assert r["vulnerable"] is True


def test_csrf_protected():
    def fake_get(url, timeout=5):
        return _mk(text='<form method="post"><input type="hidden" name="csrf_token" value="x"><input type="submit"></form>')

    with mock.patch("scanner.csrf.requests.get", side_effect=fake_get):
        r = csrf.csrf_check("http://x.com/edit")
    assert r["vulnerable"] is False
