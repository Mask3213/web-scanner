# Web 安全扫描器

一个用 Python 从零搭建的轻量级 Web 安全扫描器，用于学习渗透测试基础。包含指纹识别、敏感文件检测、目录扫描、SQL 注入检测、反射型 XSS 检测五大功能，结果支持结构化 JSON 输出。

> ⚠️ 仅供学习和授权测试使用，请勿对未授权的目标进行扫描。

## 功能

- **指纹识别**：识别 Web 服务器、语言（PHP / ASP.NET）、常见框架与系统
- **敏感文件检测**：检测 `.git`、`.env`、备份文件等配置泄露
- **目录扫描**：多线程 + 字典爆破目录
- **SQL 注入检测**：错误回显 + 布尔盲注
- **反射型 XSS 检测**：payload 回显检测
- **JSON 报告**：结果结构化输出，便于后续接入 API / 前端

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
python main.py -u http://127.0.0.1/pikachu -w dict.txt

# 用大字典扫目录
python main.py -u http://127.0.0.1/pikachu -w D:/path/to/common.txt -t 50

# SQL 注入检测（错误回显 + 布尔盲注）
python main.py --sqli "http://127.0.0.1/pikachu/vul/sqli/sqli_str.php?id=1"

# 反射型 XSS 检测
python main.py --xss "http://127.0.0.1/pikachu/vul/xss/xss_reflected_get.php?message=test"

# 输出 JSON 报告（结构化结果）
python main.py -u http://127.0.0.1/pikachu -o report.json
```

## 项目结构

```
main.py              命令行入口
scanner/             扫描引擎包
  ├─ __init__.py
  ├─ common.py       通用工具（字典加载、存活探测）
  ├─ fingerprint.py  指纹识别
  ├─ sensitive.py    敏感文件检测
  ├─ dirscan.py      目录扫描
  ├─ sqli.py         SQL 注入检测
  ├─ xss.py          XSS 检测
  └─ report.py       结果汇总 + JSON 报告
dict.txt             目录字典（小）
requirements.txt     依赖
```

## 实现思路

1. 目录扫描：requests + 多线程 + 字典文件
2. 信息收集：响应头指纹识别 + 敏感文件探测
3. SQL 注入：单引号触发错误回显；恒真/恒假条件比较响应长度（布尔盲注）
4. XSS：注入带随机标记的 payload，检测是否原样回显
5. 结果：各模块返回结构化 dict，由 report 统一打印 / 导出 JSON

## 后续路线

- 阶段 A：夯实引擎（时间盲注、POST 注入、存储型 XSS、配置化）
- 阶段 B：FastAPI 后端服务化（REST API + 任务队列）
- 阶段 C：网页版前端
- 阶段 D：小程序 / App（复用同一套 API）

## 免责声明

本项目仅供安全学习与授权测试使用。请遵守当地法律法规，对未授权目标进行扫描产生的一切后果由使用者自行承担。
