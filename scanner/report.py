# -*- coding: utf-8 -*-
"""结果汇总与报告输出：人类可读打印 + JSON 报告"""
import json
import time


def build_report(target, findings):
    """把一次扫描的所有结果打包成一份结构化报告"""
    return {
        "target": target,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": findings,
    }


def render(findings):
    """把结果按模块打印成人类可读的文本"""
    for r in findings:
        m = r.get("module")
        if m == "fingerprint":
            _render_fingerprint(r)
        elif m == "sensitive":
            print(f"  [高危] {r['url']}  ({r['size']} 字节)")
        elif m == "dir":
            print(f"  [{r['status']}] {r['url']}")
        elif m == "sqli":
            _render_sqli(r)
        elif m == "xss":
            _render_xss(r)


def _render_fingerprint(r):
    print("  [*] 指纹识别")
    if not r.get("alive"):
        print(f"      [!] 连接失败: {r.get('error')}")
        return
    for k, v in r.get("headers", {}).items():
        print(f"      {k}: {v}")
    print(f"      → Web 服务器: {r.get('server') or '未知'}")
    print(f"      → 语言: {r.get('language') or '未知'}")
    print(f"      → 识别到: {r.get('framework') or '未知'}")


def _render_sqli(r):
    print(f"  [*] SQL 注入检测: {r.get('target')}  参数: {r.get('param')}")
    if r.get("error"):
        print(f"      [!] {r['error']}")
        return
    if r.get("vulnerable"):
        print(f"      [高危] {r['technique']}")
        print(f"      payload: {r.get('payload')}")
        if r.get("evidence"):
            print(f"      命中特征: {r['evidence']}")
    else:
        print("      未发现注入")
    if r.get("boolean"):
        b = r["boolean"]
        print(f"      布尔测试: 真 {b['true_len']} | 假 {b['false_len']} | 差 {b['diff']}")
    if r.get("timing"):
        print(f"      时间测试: 响应 {r['timing']['elapsed']} 秒")


def _render_xss(r):
    print(f"  [*] XSS 检测: {r.get('target')}")
    if r.get("error"):
        print(f"      [!] {r['error']}")
        return
    if r.get("vulnerable"):
        print("      [高危] 反射型 XSS")
        print(f"      payload: {r.get('payload')}")
    else:
        print(f"      {r.get('detail') or '未发现'}")


def save_json(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
