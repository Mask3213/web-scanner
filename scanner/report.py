# -*- coding: utf-8 -*-
"""结果汇总与报告输出：人类可读打印 + JSON / HTML 报告"""
import html
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
        elif m == "rce":
            _render_rce(r)
        elif m == "stored_xss":
            _render_stored_xss(r)
        elif m == "lfi":
            _render_lfi(r)


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


def _render_rce(r):
    print(f"  [*] 命令注入检测: {r.get('target')}  参数: {r.get('param')}")
    if r.get("error"):
        print(f"      [!] {r['error']}")
        return
    if r.get("vulnerable"):
        print("      [高危] 命令注入")
        print(f"      payload: {r.get('payload')}")
    else:
        print(f"      {r.get('detail') or '未发现'}")


def _render_stored_xss(r):
    print(f"  [*] 存储型 XSS 检测: {r.get('target')}  参数: {r.get('param')}")
    if r.get("error"):
        print(f"      [!] {r['error']}")
        return
    if r.get("vulnerable"):
        print("      [高危] 存储型 XSS")
        print(f"      payload: {r.get('payload')}")
    else:
        print(f"      {r.get('detail') or '未发现'}")


def _render_lfi(r):
    print(f"  [*] 文件包含(LFI)检测: {r.get('target')}  参数: {r.get('param')}")
    if r.get("error"):
        print(f"      [!] {r['error']}")
        return
    if r.get("vulnerable"):
        print("      [高危] 文件包含（LFI）")
        print(f"      payload: {r.get('payload')}")
    else:
        print(f"      {r.get('detail') or '未发现'}")


def save_json(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


# ---------------- HTML 报告 ----------------

def _esc(s):
    return html.escape(str(s if s is not None else ""))


def _vuln_html(title, f):
    """注入类漏洞的统一 HTML 块"""
    if f.get("error"):
        return f'<div class="block"><h3>{title}</h3><p class="danger">错误：{_esc(f["error"])}</p></div>'
    if f.get("vulnerable"):
        body = f'<p><span class="danger">⚠ 存在漏洞</span>　{_esc(f.get("technique") or f.get("detail") or "")}</p>'
        if f.get("payload"):
            body += f'<p class="muted">payload：<code>{_esc(f["payload"])}</code></p>'
    else:
        body = f'<p class="ok">未发现漏洞　{_esc(f.get("detail") or "")}</p>'
    return f'<div class="block"><h3>{title}　<span class="muted">参数：{_esc(f.get("param") or "-")}</span></h3>{body}</div>'


def _finding_html(f):
    m = f.get("module")
    if m == "fingerprint":
        if not f.get("alive"):
            return f'<div class="block"><h3>🔍 指纹识别</h3><p class="danger">{_esc(f.get("error"))}</p></div>'
        return (f'<div class="block"><h3>🔍 指纹识别</h3>'
                f'<p>Web 服务器：{_esc(f.get("server")) or "未知"}</p>'
                f'<p>语言：{_esc(f.get("language")) or "未知"}</p>'
                f'<p>框架/系统：{_esc(f.get("framework")) or "未知"}</p></div>')
    if m == "sqli":
        return _vuln_html("💉 SQL 注入", f)
    if m == "xss":
        return _vuln_html("⚡ 反射型 XSS", f)
    if m == "rce":
        return _vuln_html("💻 命令注入", f)
    if m == "stored_xss":
        return _vuln_html("💾 存储型 XSS", f)
    if m == "lfi":
        return _vuln_html("📂 文件包含（LFI）", f)
    return ""


_HTML_CSS = """
body { font-family:"Segoe UI","Microsoft YaHei",sans-serif; background:#0f172a; color:#e2e8f0; padding:32px; }
.wrap { max-width:900px; margin:0 auto; }
h1 { color:#3b82f6; }
.meta { color:#94a3b8; font-size:14px; margin-bottom:20px; }
.summary { display:flex; gap:16px; margin-bottom:24px; }
.stat { background:#1e293b; border:1px solid #334155; border-radius:10px; padding:14px 20px; }
.stat b { display:block; font-size:22px; color:#f59e0b; }
.stat span { color:#94a3b8; font-size:13px; }
.block { background:#1e293b; border:1px solid #334155; border-radius:10px; padding:16px 20px; margin-bottom:14px; }
.block h3 { color:#3b82f6; margin:0 0 10px; font-size:16px; }
.block p { margin:4px 0; }
.item { padding:5px 0; border-bottom:1px dashed #334155; font-size:14px; }
.item:last-child { border-bottom:none; }
code { color:#7dd3fc; word-break:break-all; }
.danger { color:#fca5a5; font-weight:600; }
.ok { color:#86efac; }
.muted { color:#94a3b8; }
"""


def save_html(report, path):
    """生成 HTML 格式的扫描报告"""
    findings = report.get("findings", [])
    target = report.get("target", "")
    ts = report.get("time", "")

    vuln_count = sum(1 for f in findings if f.get("vulnerable"))
    dir_fs = [f for f in findings if f.get("module") == "dir"]
    sens_fs = [f for f in findings if f.get("module") == "sensitive"]

    # 指纹 + 注入类检测（各自成块）
    blocks = "".join(_finding_html(f) for f in findings if f.get("module") not in ("dir", "sensitive"))
    # 目录 + 敏感文件（分组展示）
    if dir_fs:
        items = "".join(f'<div class="item"><code>{f["status"]}</code> <code>{_esc(f["url"])}</code></div>' for f in dir_fs)
        blocks += f'<div class="block"><h3>📁 目录（{len(dir_fs)}）</h3>{items}</div>'
    if sens_fs:
        items = "".join(
            f'<div class="item"><span class="danger">[高危]</span> <code>{_esc(f["url"])}</code> <span class="muted">（{f["size"]} 字节）</span></div>'
            for f in sens_fs
        )
        blocks += f'<div class="block"><h3>🚨 敏感文件（{len(sens_fs)}）</h3>{items}</div>'

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Web 安全扫描报告</title>
<style>{_HTML_CSS}</style>
</head>
<body><div class="wrap">
<h1>🛡️ Web 安全扫描报告</h1>
<div class="meta">目标：<code>{_esc(target)}</code>　·　时间：{_esc(ts)}</div>
<div class="summary">
  <div class="stat"><b>{vuln_count}</b><span>漏洞</span></div>
  <div class="stat"><b>{len(dir_fs)}</b><span>目录</span></div>
  <div class="stat"><b>{len(sens_fs)}</b><span>敏感文件</span></div>
</div>
{blocks}
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)

