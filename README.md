# wecom-reader

企业微信（WeCom）本地聊天记录读取工具。从 WXWork.exe 进程内存提取密钥，解密本地 SQLite 数据库，提供 CLI / Python 库 / Web UI（deprecated） 三种访问方式。

## 原理

企业微信使用 wxSQLite3 AES-128-CBC 加密本地数据库：

- 密钥长度：16 字节（128 bit）
- 密钥数量：**一个全局密钥**解密所有数据库（比个人微信简单得多）
- 加密方式：每页独立派生 key/IV，无 HMAC，无 PBKDF2
- 密钥提取：Windows 通过 Windows API，Linux/Wine 通过 `/proc/<pid>/mem` 只读扫描 WXWork.exe 进程内存

## 安装与使用

安装 [uv](https://docs.astral.sh/uv/getting-started/installation/) 和 Git 后，可以直接从 GitHub 运行，无需预先克隆仓库、手动创建 venv 或安装依赖。

```bash
# GitHub
uvx --from "git+https://github.com/yankuangxindaL4/wecom-reader.git@main" wecom-reader --help

```

`@main` 指定默认分支，也可替换为 tag 或完整 commit SHA 来固定版本。

下列示例在本地源码根目录使用 `--from .`；从远程运行时，将 `.` 替换为上面的 GitHub `git+...` 地址即可。`--db-dir` 和 `--decrypted-dir` 是全局参数，放在子命令前。快照默认保存在当前工作目录的 `wxwork_decrypted`；跨目录使用时请显式指定同一个绝对路径，例如 `--decrypted-dir "/path/to/snapshot"`。

```bash
# 查看命令帮助
uvx --from . wecom-reader --help

# 初始化：Windows（WXWork.exe 运行中，需要内存读取权限）
uvx --from . wecom-reader --db-dir "E:\WXWork\<account_id>\Data" init

# 初始化：Linux/Wine（使用本机 Python，无需 Windows Python）
uvx --from . wecom-reader --db-dir "/path/to/WXWork/account/Data" init

# 查看状态
uvx --from . wecom-reader status

# 列出会话
uvx --from . wecom-reader sessions --limit 20

# 查看消息
uvx --from . wecom-reader messages R:12345 --limit 50

# 搜索消息
uvx --from . wecom-reader search "关键词"

# 查看联系人
uvx --from . wecom-reader contacts --keyword "张三"

# 导出消息（最多最近 10,000 条，超出时提示截断）
uvx --from . wecom-reader export R:12345 --output messages.json
```

### Python 库

```python
from wecom_reader import WeComReader

reader = WeComReader(db_dir="E:/WXWork/<account_id>/Data")
reader.init()  # 提取密钥 + 解密

sessions = reader.list_sessions(limit=10)
msgs = reader.get_messages("R:12345", limit=50)
results = reader.search_messages("关键词")
contacts = reader.contacts(keyword="张三")
```

### Web UI（deprecated）

Web 服务已弃用，保留旧入口但不再维护或修复；请使用 CLI。

```bash
python -m wecom_reader.web --db-dir "E:\WXWork\<account_id>\Data"
# 浏览器打开 http://127.0.0.1:8765
```

## 数据库结构

| 数据库 | 内容 | 大小 |
|--------|------|------|
| message.db | 聊天消息（130万+条） | ~770MB |
| session.db | 会话列表（5800+个） | ~22MB |
| user.db | 联系人/用户信息 | ~8MB |
| file.db | 文件传输记录 | ~158MB |
| calendar_r7.db | 日程信息 | ~2.5MB |
| crm.db | CRM 数据 | ~424KB |

## 会话 ID 格式

| 前缀 | 类型 |
|------|------|
| `R:<数字>` | 群聊 |
| `S:<数字>_<数字>` | 单聊 |
| `M:<数字>` | 微信联系人 |
| `O:<数字>` | 应用/公众号 |
| `Y:<数字>` | 系统会话 |

## 依赖

- Python >= 3.10
- pycryptodomex >= 3.20（AES 解密）
- click >= 8.0（CLI 框架）
- flask >= 3.0（Web UI，可选）

## 致谢

- [wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) — 企微解密参考实现
- [CipherTalk (密语)](https://github.com/ILoveBingLu/miyu) — WCDB 架构参考

## 免责声明

本工具仅供个人数据备份和学习研究使用。请遵守企业微信服务条款和当地法律法规。
