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

下列示例在本地源码根目录使用 `--from .`；从远程运行时，将 `.` 替换为上面的 GitHub `git+...` 地址即可。`--db-dir` 和 `--decrypted-dir` 是全局参数，放在子命令前。快照默认保存在用户数据目录中并按账号隔离，不随工作目录变化；可用 `--decrypted-dir "/path/to/snapshot"` 或 `WXWORK_DECRYPTED_DIR` 指定已有快照，命令行参数优先。

```bash
# 查看命令帮助
uvx --from . wecom-reader --help

# 提取并缓存密钥：Windows（WXWork.exe 运行中，需要内存读取权限）
uvx --from . wecom-reader --db-dir "E:\WXWork\<account_id>\Data" init

# 提取并缓存密钥：Linux/Wine（使用本机 Python，无需 Windows Python）
uvx --from . wecom-reader --db-dir "/path/to/WXWork/account/Data" init

# 立即检查并刷新快照（使用缓存密钥，不扫描进程）
uvx --from . wecom-reader refresh

# 查看状态（不会提取密钥或解密）
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

### 密钥、账号与自动刷新

- `init` 只从进程提取并验证密钥，不生成快照；成功后使该账号已有快照过期，失败不会覆盖已有密钥缓存。
- `search`、`sessions`、`messages`、`contacts`、`group-members`、`export` 及对应 Python 查询首次使用时自动解密；之后 **5 分钟内直接读取快照**，超过间隔才检查源数据库及 WAL 的修改时间和大小，仅更新有变化的数据库。
- `refresh` 跳过 5 分钟间隔，立即检查更新；源数据未变化时无需重新解密，缺失的快照文件会重新生成。
- 查询和 `refresh` 都不会读取进程内存；缓存密钥缺失或失效时会提示运行 `init`，因此企微关闭后仍可使用已缓存密钥解密。
- 快照更新先在临时目录完成解密、WAL 合并和 SQLite 校验；源文件在构建期间发生变化或校验失败会报错并保留旧快照，不把失败记为刷新成功。
- 唯一校验例外：仅当 `crm.db` 报错恰为 `no such tokenizer: fts5word` 时，跳过该库的整库校验，向 stderr 输出未完整校验的警告并继续发布快照；不修改表或索引，其他数据库、其他异常及校验返回的损坏信息仍按失败处理。
- 源目录不可用时可查询已有离线快照，但 `refresh` 会明确报错；指定未带元数据的旧快照目录时保持只读使用，不自动关联其他账号。

账号默认从 `Documents/WXWork/*/Data` 和已经 `init` 过的源目录中选择：只有一个账号时直接使用，多个账号时以 `session.db` / `session.db-wal` 最近修改时间选择（缺失时使用其他主数据库时间）；这表示本地数据活跃程度，并非精确的登录时间。

`status` 展示账号 ID、账号列表、源目录、实际快照路径、缓存是否存在以及快照更新/检查时间，不显示密钥；使用 `--account <ID>` 可固定账号，或用 `--db-dir` / `WXWORK_DB_DIR` 明确选择源目录，两者同时指定时必须一致。

| 项目 | Linux 默认路径 | 覆盖方式 |
|---|---|---|
| 密钥缓存 | `${XDG_CACHE_HOME:-$HOME/.cache}/wecom-reader/keys/<account-id>.json` | `--key-dir` > `WXWORK_KEY_DIR` |
| 解密快照 | `${XDG_DATA_HOME:-$HOME/.local/share}/wecom-reader/decrypted/<account-id>/` | `--decrypted-dir` > `WXWORK_DECRYPTED_DIR` |

Windows 使用 `%LOCALAPPDATA%/wecom-reader/cache/keys/` 和 `%LOCALAPPDATA%/wecom-reader/data/decrypted/<account-id>/`；未设置相关目录变量的其他平台使用 HOME 下目录。

显式指定的快照路径就是最终目录，不会再添加账号子目录；已经记录来源的快照拒绝被其他账号覆盖，源目录与输出目录也不能相互包含。没有可用源目录时，默认使用最近成功更新的默认快照。

密钥以明文 JSON 保存，和聊天快照分开存放；Linux 下缓存目录权限为 `0700`、密钥文件为 `0600`，Windows 为目录设置当前用户 ACL，文件采用原子替换。不要分享密钥缓存；删除缓存后需重新运行 `init`，已有快照仍可离线使用。Linux 经 `sudo` 提取时默认目录及生成文件归原调用用户所有，后续查询无需提权。

旧的 `./wxwork_decrypted` 不自动迁移，可通过以下配置继续使用：

```bash
export WXWORK_DECRYPTED_DIR="/absolute/path/to/wxwork_decrypted"
```

WAL 合并遵循 [SQLite WAL 格式](https://www.sqlite.org/fileformat2.html#walformat)，只应用校验通过且已提交的帧；加密 WAL 支持当前 wxSQLite3 AES-128 页格式及基于密文的校验和，不支持旧版基于明文校验和的 WAL 加密模式（参见 [SQLite3 Multiple Ciphers 说明](https://utelle.github.io/SQLite3MultipleCiphers/docs/architecture/arch_vfs/)）。未通过支持格式校验的加密 WAL 会报错，避免静默忽略新增消息。

### Python 库

```python
from wecom_reader import WeComReader

reader = WeComReader(db_dir="E:/WXWork/<account_id>/Data")
reader.init()  # 仅提取、验证并缓存密钥
# reader.refresh()  # 可选：立即刷新；查询也会按需刷新

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
