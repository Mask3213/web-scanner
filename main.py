# -*- coding: utf-8 -*-
"""Web 安全扫描器 —— 命令行入口

用法：
  python main.py -u http://127.0.0.1/pikachu -w dict.txt
  python main.py --sqli "http://127.0.0.1/pikachu/vul/sqli/sqli_str.php?id=1"
  python main.py --xss  "http://127.0.0.1/pikachu/vul/xss/xss_reflected_get.php?message=test"
  python main.py -u http://127.0.0.1/pikachu -o report.html  # 输出 HTML 报告（.json 则输出 JSON）
"""
import argparse

from urllib.parse import parse_qsl

from scanner import common, config, fingerprint, sensitive, dirscan, sqli, xss, rce, stored_xss, lfi, upload, csrf, report


def main():
    parser = argparse.ArgumentParser(description="Web 安全扫描器")
    parser.add_argument("-u", "--url", help="目标基地址，如 http://127.0.0.1/pikachu")
    parser.add_argument("-w", "--wordlist", default=config.DEFAULT_WORDLIST, help="目录字典路径")
    parser.add_argument("-t", "--threads", type=int, default=config.DEFAULT_THREADS, help="目录扫描线程数")
    parser.add_argument("--sqli", metavar="URL", help="SQL 注入检测目标（带参数的 URL）")
    parser.add_argument("--xss", metavar="URL", help="反射型 XSS 检测目标（带参数的 URL）")
    parser.add_argument("--rce", metavar="URL", help="命令注入检测目标（带参数的 URL）")
    parser.add_argument("--stored-xss", metavar="URL", help="存储型 XSS 检测目标（留言/评论类页面）")
    parser.add_argument("--lfi", metavar="URL", help="文件包含(LFI)检测目标（带参数的 URL）")
    parser.add_argument("--upload", metavar="URL", help="文件上传检测目标（上传接口地址）")
    parser.add_argument("--csrf", metavar="URL", help="CSRF 检测目标（含表单的页面）")
    parser.add_argument("--data", metavar="k=v", help="POST 请求体（配合 --sqli / --xss / --rce），如 name=1")
    parser.add_argument("--login", metavar="URL", help="登录页地址（需要登录的靶子用）")
    parser.add_argument("--login-data", metavar="k=v", help="登录表单数据，如 username=admin&password=123456&submit=1")
    parser.add_argument("--login-method", default="POST", choices=["GET", "POST"], help="登录请求方法（默认 POST）")
    parser.add_argument("--param", metavar="NAME", help="指定要检测的参数名（默认自动选第一个非 submit 参数）")
    parser.add_argument("-o", "--output", metavar="FILE", help="保存报告到文件（.html 生成网页报告，否则生成 JSON）")
    args = parser.parse_args()

    findings = []

    # 需要登录的靶子：先登录拿到带 cookie 的 session
    session = None
    if args.login:
        login_data = dict(parse_qsl(args.login_data or "", keep_blank_values=True))
        session = common.login(args.login, login_data, method=args.login_method)
        print(f"[*] 已登录 {args.login}")

    if args.sqli:
        findings.append(sqli.sqli_check(args.sqli, data=args.data, param=args.param))
    elif args.xss:
        findings.append(xss.xss_check(args.xss, data=args.data, param=args.param, session=session))
    elif args.rce:
        findings.append(rce.rce_check(args.rce, data=args.data, param=args.param))
    elif args.stored_xss:
        findings.append(stored_xss.stored_xss_check(args.stored_xss, session=session))
    elif args.lfi:
        findings.append(lfi.lfi_check(args.lfi))
    elif args.upload:
        findings.append(upload.upload_check(args.upload))
    elif args.csrf:
        findings.append(csrf.csrf_check(args.csrf, session=session))
    else:
        if not args.url:
            parser.error("请提供 -u 目标地址，或用 --sqli / --xss / --rce / --stored-xss / --lfi / --upload / --csrf 指定单点检测目标")

        ok, code = common.target_alive(args.url)
        if not ok:
            print(f"[!] 目标 {args.url} 无法连接，请确认服务（Apache）已启动")
            return
        print(f"[*] 目标可达，状态码 {code}")

        findings.append(fingerprint.fingerprint(args.url))
        findings.extend(sensitive.sensitive_check(args.url))
        findings.extend(dirscan.dir_scan(args.url, common.load_wordlist(args.wordlist), args.threads))

    report.render(findings)

    if args.output:
        target = args.url or args.sqli or args.xss or args.rce or args.stored_xss
        rep = report.build_report(target, findings)
        if args.output.lower().endswith(".html"):
            report.save_html(rep, args.output)
            print(f"[*] HTML 报告已保存: {args.output}")
        else:
            report.save_json(rep, args.output)
            print(f"[*] JSON 报告已保存: {args.output}")

    print("\n[*] 扫描完成")


if __name__ == "__main__":
    main()
