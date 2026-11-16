# Web 安全扫描器（入门版）

一个用 Python 从零搭建的轻量级 Web 安全扫描器，用于学习渗透测试基础。包含指纹识别、敏感文件检测、目录扫描、SQL 注入检测、反射型 XSS 检测五大功能。

> ⚠️ 仅供学习和授权测试使用，请勿对未授权的目标进行扫描。

## 功能

- **指纹识别**：识别 Web 服务器、语言（PHP / ASP.NET）、常见框架与系统
- **敏感文件检测**：检测 `.git`、`.env`、备份文件等配置泄露
- **目录扫描**：多线程 + 字典爆破目录
- **SQL 注入检测**：错误回显 + 布尔盲注
- **反射型 XSS 检测**：payload 回显检测

## 环境

- Python 3.7+
- 依赖：`requests`

## 安装

```bash
pip install -r requirements.txt
```

## 使用

```bash
# 完整扫描（目标存活探测 + 指纹识别 + 敏感文件检测 + 目录扫描）
python scanner.py -u http://127.0.0.1/pikachu -w dict.txt

# 用大字典扫目录
python scanner.py -u http://127.0.0.1/pikachu -w D:/path/to/common.txt -t 50

# SQL 注入检测（错误回显 + 布尔盲注）
python scanner.py --sqli "http://127.0.0.1/pikachu/vul/sqli/sqli_str.php?id=1"

# 反射型 XSS 检测
python scanner.py --xss "http://127.0.0.1/pikachu/vul/xss/xss_reflected_get.php?message=test"
```

## 项目结构

```
scanner.py         主程序
dict.txt           目录字典（小）
requirements.txt   依赖
```

## 实现思路

1. 目录扫描：requests + 多线程 + 字典文件
2. 信息收集：响应头指纹识别 + 敏感文件探测
3. SQL 注入：单引号触发错误回显；恒真/恒假条件比较响应长度（布尔盲注）
4. XSS：注入带随机标记的 payload，检测是否原样回显

## 后续可扩展

时间盲注、POST 参数注入、存储型 XSS、扫描报告导出、插件化。

## 免责声明

本项目仅供安全学习与授权测试使用。请遵守当地法律法规，对未授权目标进行扫描产生的一切后果由使用者自行承担。
