# -*- coding: utf-8 -*-
"""common 模块单元测试"""
from scanner import common


def test_load_wordlist(tmp_path):
    p = tmp_path / "dict.txt"
    p.write_text("# 注释\nadmin\n\nlogin\n", encoding="utf-8")
    assert common.load_wordlist(str(p)) == ["admin", "login"]


def test_parse_target_get():
    method, base, params = common.parse_target("http://x.com/a?id=1&submit=1")
    assert method == "GET"
    assert base == "http://x.com/a"
    assert params == {"id": "1", "submit": "1"}


def test_parse_target_post():
    method, base, params = common.parse_target("http://x.com/a", data="name=1&submit=1")
    assert method == "POST"
    assert base == "http://x.com/a"
    assert params == {"name": "1", "submit": "1"}


def test_pick_param_skips_submit():
    assert common.pick_param({"name": "1", "submit": "1"}) == "name"


def test_pick_param_explicit():
    assert common.pick_param({"a": "1", "b": "2"}, "b") == "b"


def test_display_get():
    assert common.display("GET", "http://x.com/a", {"id": "1"}) == "http://x.com/a?id=1"


def test_display_post():
    out = common.display("POST", "http://x.com/a", {"name": "x"})
    assert "POST body" in out
