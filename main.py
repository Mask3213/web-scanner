# -*- coding: utf-8 -*-
"""Web 安全扫描器 —— 命令行入口

用法：
  python main.py -u http://127.0.0.1/pikachu -w dict.txt
  python main.py --sqli "http://127.0.0.1/pikachu/vul/sqli/sqli_str.php?id=1"
  python main.py --xss  "http://127.0.0.1/pikachu/vul/xss/xss_reflected_get.php?message=test"
  python main.py -u http://127.0.0.1/pikachu -o report.json   # 输出 JSON 报告
"""
import argparse

from scanner import common, fingerprint, sensitive, dirscan, sqli, xss, report


def main():
    parser = argparse.ArgumentParser(description="Web 安全扫描器")
    parser.add_argument("-u", "--url", help="目标基地址，如 http://127.0.0.1/pikachu")
    parser.add_argument("-w", "--wordlist", default="dict.txt", help="目录字典路径")
    parser.add_argument("-t", "--threads", type=int, default=20, help="目录扫描线程数")
    parser.add_argument("--sqli", metavar="URL", help="SQL 注入检测目标（带参数的 URL）")
    parser.add_argument("--xss", metavar="URL", help="反射型 XSS 检测目标（带参数的 URL）")
    parser.add_argument("-o", "--output", metavar="FILE", help="保存 JSON 报告到文件")
    args = parser.parse_args()

    findings = []

    if args.sqli:
        findings.append(sqli.sqli_check(args.sqli))
    elif args.xss:
        findings.append(xss.xss_check(args.xss))
    else:
        if not args.url:
            parser.error("请提供 -u 目标地址，或用 --sqli / --xss 指定单点检测目标")

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
        rep = report.build_report(args.url or args.sqli or args.xss, findings)
        report.save_json(rep, args.output)
        print(f"[*] JSON 报告已保存: {args.output}")

    print("\n[*] 扫描完成")


if __name__ == "__main__":
    main()
