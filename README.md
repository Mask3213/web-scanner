# Web 安全扫描器

一个用 Python 从零搭建的轻量级 Web 安全扫描器，用于学习渗透测试基础。包含指纹识别、敏感文件检测、目录扫描、SQL 注入检测、反射型 XSS 检测，并提供命令行工具 + REST API 两种使用方式。

> ⚠️ 仅供学习和授权测试使用，请勿对未授权的目标进行扫描。

## 功能

- **指纹识别**：识别 Web 服务器、语言（PHP / ASP.NET）、常见框架与系统
- **敏感文件检测**：检测 `.git`、`.env`、备份文件等配置泄露
- **目录扫描**：多线程 + 字典爆破目录
- **SQL 注入检测**：错误回显 + 布尔盲注 + 时间盲注
- **反射型 XSS 检测**：payload 回显检测（支持 GET / POST）
- **命令注入检测**：注入额外系统命令，检测输出回显
- **存储型 XSS 检测**：提交 payload 后检测是否持久化回显
- **文件包含（LFI）检测**：目录穿越读取敏感文件
- **任意文件上传检测**：上传危险扩展名文件，检测是否被接受
- **会话登录**：支持需要登录的靶子（自动登录 + cookie）
- **限流**：按 IP 滑动窗口限流，防止滥用（默认 60 次/分钟，可用 `SCANNER_RATE_LIMIT` / `SCANNER_RATE_WINDOW` 环境变量调整）
- **登录失败锁定**：连续失败 5 次锁定账号 5 分钟，防暴力破解
- **API Key 鉴权**：登录获取 API Key，所有扫描 / 查询接口需携带 X-API-Key
- **结果结构化**：dict 结果 + JSON / HTML 报告，便于接入 API / 前端

## 环境

- Python 3.10+
- 依赖：`requests`、`fastapi`、`uvicorn`

## 安装

```bash
pip install -r requirements.txt
```

## 命令行使用

```bash
# 完整扫描（目标存活探测 + 指纹识别 + 敏感文件检测 + 目录扫描）
python main.py -u http://127.0.0.1/pikachu -w dict.txt

# 用大字典扫目录
python main.py -u http://127.0.0.1/pikachu -w D:/path/to/common.txt -t 50

# SQL 注入检测（自动选择参数）
python main.py --sqli "http://127.0.0.1/pikachu/vul/sqli/sqli_blind_t.php?name=1&submit=1"

# 反射型 XSS 检测
python main.py --xss "http://127.0.0.1/pikachu/vul/xss/xss_reflected_get.php?message=test"

# 命令注入检测（POST 靶子，用 --data）
python main.py --rce "http://127.0.0.1/pikachu/vul/rce/rce_ping.php" --data "ipaddress=127.0.0.1&submit=1"

# 存储型 XSS 检测（无需登录）
python main.py --stored-xss "http://127.0.0.1/pikachu/vul/xss/xss_stored.php"

# 文件包含(LFI)检测
python main.py --lfi "http://127.0.0.1/pikachu/vul/fileinclude/fi_local.php?filename=file1.php&submit=1"

# 文件上传检测
python main.py --upload "http://127.0.0.1/pikachu/vul/unsafeupload/clientcheck.php"

# 需要登录的 POST XSS（先登录再测）
python main.py --xss "http://127.0.0.1/pikachu/vul/xss/xsspost/xss_reflected_post.php" --data "message=test&submit=1" --login "http://127.0.0.1/pikachu/vul/xss/xsspost/post_login.php" --login-data "username=admin&password=123456&submit=1"

# 输出报告（.html 生成网页报告，.json 生成 JSON）
python main.py -u http://127.0.0.1/pikachu -o report.html
```

## REST API 使用

启动服务：

```bash
uvicorn api:app --reload --host 127.0.0.1 --port 8000
```

- 前端页面：http://127.0.0.1:8000/
- 交互式接口文档：http://127.0.0.1:8000/docs

**异步任务流程**：先提交任务拿到 `task_id`，再轮询取结果。

- `POST /scan`、`POST /sqli`、`POST /xss`、`POST /rce`、`POST /stored-xss`、`POST /lfi`、`POST /upload`：提交任务，返回 `{"task_id": "...", "status": "running"}`
- `GET /task/{task_id}`：查询任务状态与结果（`running` / `done` / `error`）
- `GET /tasks`：任务列表（历史记录）
- `DELETE /task/{task_id}`：删除一条历史记录

任务与结果存 SQLite（`tasks.db`），**重启服务不丢失**。

**鉴权**：所有扫描 / 查询接口都需要 `X-API-Key` 请求头。先登录获取 key（默认账号 `admin` / `admin123`，可通过环境变量 `SCANNER_ADMIN_PASSWORD` 修改密码）：

```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
# 返回 {"username":"admin","api_key":"..."}
```

之后请求带上 key：`-H "X-API-Key: 你的key"`

示例：

```bash
# 提交扫描任务
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1/pikachu", "wordlist": "dict.txt"}'
# 返回 {"task_id":"abc123","status":"running"}

# 轮询结果
curl http://127.0.0.1:8000/task/abc123
```

## 项目结构

```
main.py              命令行入口
api.py               REST API 服务（FastAPI）
scanner/             扫描引擎包
  ├─ config.py       全局配置（超时 / 字典 / 阈值 / payload）
  ├─ common.py       通用工具（字典加载、存活探测、请求构造）
  ├─ fingerprint.py  指纹识别
  ├─ sensitive.py    敏感文件检测
  ├─ dirscan.py      目录扫描
  ├─ sqli.py         SQL 注入检测
  ├─ xss.py          XSS 检测（反射型）
  ├─ rce.py          命令注入检测
  ├─ stored_xss.py   存储型 XSS 检测
  ├─ lfi.py          文件包含(LFI)检测
  ├─ upload.py       任意文件上传检测
  └─ report.py       结果汇总 + JSON 报告
dict.txt             目录字典（小）
requirements.txt     依赖
```

## 实现思路

1. 目录扫描：requests + 多线程 + 字典文件
2. 信息收集：响应头指纹识别 + 敏感文件探测
3. SQL 注入：错误回显 + 布尔盲注 + 时间盲注
4. XSS：注入带随机标记的 payload，检测是否原样回显
5. 结果：各模块返回结构化 dict，CLI / API 复用同一套引擎

## 后续路线

- 阶段 A：夯实引擎 ✅（待做：存储型 XSS、会话/登录处理、配置化）
- 阶段 B：FastAPI 后端服务化 ✅（异步任务队列、SQLite 持久化已完成；待做：鉴权）
- 阶段 C：网页版前端 ✅（基础版 + 历史记录已完成；待做：Vue3/React 升级、图表）
- 阶段 D：小程序 / App（复用同一套 API）

## 测试

```bash
pip install pytest
python -m pytest
```

测试覆盖：通用工具、报告生成、SQL 注入 / XSS / 命令注入 / 文件包含 / 文件上传 / 存储型 XSS / 敏感文件等检测逻辑（无需靶场，全部 mock HTTP）。

## 免责声明

本项目仅供安全学习与授权测试使用。请遵守当地法律法规，对未授权目标进行扫描产生的一切后果由使用者自行承担。
