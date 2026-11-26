# -*- coding: utf-8 -*-
"""检测模块逻辑单元测试（mock HTTP，不需要靶场）"""
from unittest import mock

from scanner import sqli, xss, lfi


def _mk(content=b"", text=""):
    r = mock.Mock()
    r.content = content
    r.text = text
    r.status_code = 200
    return r


def test_sqli_error_based():
    baseline = _mk(content=b"ok")
    error = _mk(text="you have an error in your sql syntax near '1''")
    with mock.patch("scanner.common.send", side_effect=[baseline, error]):
        r = sqli.sqli_check("http://x.com/a?id=1")
    assert r["vulnerable"] is True
    assert r["technique"] == "错误回显"


def test_xss_reflected():
    def fake_send(method, url, params, timeout=5, session=None):
        return _mk(text=next(iter(params.values())))  # 原样回显 payload

    with mock.patch("scanner.common.send", side_effect=fake_send):
        r = xss.xss_check("http://x.com/a?msg=test")
    assert r["vulnerable"] is True


def test_xss_not_reflected():
    def fake_send(method, url, params, timeout=5, session=None):
        return _mk(text="normal page, nothing reflected")

    with mock.patch("scanner.common.send", side_effect=fake_send):
        r = xss.xss_check("http://x.com/a?msg=test")
    assert r["vulnerable"] is False


def test_lfi():
    def fake_send(method, url, params, timeout=5, session=None):
        return _mk(text="some content [fonts] more")

    with mock.patch("scanner.common.send", side_effect=fake_send):
        r = lfi.lfi_check("http://x.com/a?filename=file1.php&submit=1")
    assert r["vulnerable"] is True
