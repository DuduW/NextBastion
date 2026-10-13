# NextBastion 堡垒机

> 轻量级开源堡垒机 · Python 3.11 + FastAPI + MySQL 8 + 原生 HTML5
> 浏览器内真实 SSH 终端 · 全程录像审计 · 高危命令实时拦截与 Webhook 告警 · TOTP 双因子 · LDAP 目录认证

一个 **单文件前端 + FastAPI 后端** 的轻量堡垒机，专为中小团队内网运维设计：
无需 Java 中间件（SSH 通道原生 asyncssh），10 分钟完成部署，开箱即用。

---

## ✨ 功能特性

| 模块 | 功能 |
|------|------|
| **认证** | 账号密码 + TOTP 双因子（Google Authenticator），登录失败留痕 |
| **资产** | 资产 / 节点树 / 托管账号（AES-256-GCM 加密，接口不回显），分组标签、字段选项字典化（数据库可维护） |
| **授权** | 五维授权：用户/用户组 × 资产/节点 × 托管账号 × 时段 × 命令过滤策略 |
| **接入** | 浏览器 Web SSH 终端（WebSocket + asyncssh），全程 asciinema cast 录像 |
| **接入** | RDP 图形通道（guacd 承载，可选安装） |
| **审计** | 在线会话实时监控 / 一键强断；会话历史 + 终端录像回放；命令审计 + 高危命令**阻断/告警**（rm -rf /、DROP DATABASE 等） |
| **告警** | 高危命令实时 Webhook 推送（钉钉/企微机器人兼容），一键测试连通性 |
| **目录认证** | OpenLDAP 对接：用户/组全量同步、LDAP 直接登录 |
| **审计日志** | 服务端分页（每页 20/50/100 可选），支持筛选与 CSV 导出 |

## 🧱 技术栈

- **后端**：Python 3.11 · FastAPI · asyncssh · PyMySQL · PyJWT · pyotp · ldap3
- **前端**：原生 SPA（零构建，单 index.html）· xterm.js · asciinema-player · guacamole-common.js
- **存储**：MySQL 8（12 张业务表）
- **部署**：一键 Shell 脚本（systemd + Nginx 反代 + firewalld）

## 📦 目录结构

```
NextBastion/
├── app/                  # 应用源码
│   ├── main.py           # FastAPI 路由（全部 API）
│   ├── config.py         # 配置（环境变量驱动）
│   ├── utils.py          # DB/加密/审计公共库
│   ├── db_init.py        # 建库建表 + 种子数据
│   ├── seed.py           # 初始账号/演示资产生成
│   ├── ldap_auth.py      # LDAP 同步与认证
│   ├── guac_bridge.py    # RDP-guacd 桥接
│   ├── requirements.txt
│   └── web/              # 前端 SPA（index.html + 播放器 + vendor JS）
├── scripts/              # 运维脚本（LDAP 同步 / 日志清理，部署时自动装成 systemd timer）
├── migrations/           # 增量 SQL
├── prd/                  # 产品需求文档（完整 PRD）
├── docs/                 # 角色权限矩阵等
├── deploy.sh             # ★ 一键部署脚本
└── README.md
```

---

## 🚀 安装（一键部署）

### 环境要求

- Rocky Linux 9 / CentOS 9 / RHEL 9（其他 EL9 系发行版亦可）
- root 权限，可访问外网（dnf + pip）

### 三步部署

```bash
# 1. 解压（或 git clone）
tar xzf NextBastion-v1.0.3.tar.gz && cd NextBastion

# 2. 一键部署
bash deploy.sh

# 3. 需要 RDP 图形通道的话（可选，编译 guacd 约 5-10 分钟）
NB_WITH_RDP=1 bash deploy.sh
```

部署脚本自动完成：系统依赖 → MySQL 初始化 → venv → 密钥生成 → 建库建表 → 种子数据 → systemd 服务 → Nginx 反代 → 防火墙 → 运维定时器 → 健康检查。

完成后终端会打印初始账号与 TOTP 绑定信息（也存于服务器 `/opt/nextbastion/INITIAL_CREDENTIALS.txt`）。

### 自定义口令（可选）

```bash
NB_MYSQL_ROOT_PASS='你的root密码' \
NB_DB_PASS='你的应用库密码' \
NB_ADMIN_PASS='你的admin密码' \
bash deploy.sh
```

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `NB_MYSQL_ROOT_PASS` | ChangeRoot@2026 | MySQL root 密码（首次部署设置） |
| `NB_DB_PASS` | ChangeMe@2026 | 应用库 nextbastion 密码 |
| `NB_ADMIN_PASS` | Admin@2026 | admin 初始密码 |
| `NB_SELF_SSH_PASS` | SelfHost@2026 | 演示资产 self-bastion 的 root 密码 |
| `NB_PORT` | 8000 | 后端监听端口 |
| `NB_WITH_RDP` | 0 | 1 = 安装 guacd（RDP） |
| `NB_NO_MFA` | 0 | 1 = 跳过 TOTP 初始化（不推荐） |

### 首次登录

1. 浏览器访问 `http://<服务器IP>`（Nginx 80，等同 `:8000` 直连）
2. 手机安装 **Google Authenticator**（或任意 TOTP App）→ 添加账号 → 输入部署输出中的 Secret
3. 登录：`admin` + 初始密码 + 6 位动态码
4. **立即修改初始密码**（用户管理 → 编辑 admin）

---

## 📖 使用说明

### 快速上手（管理员）

```
添加资产 → 配置授权 → 用户连接 → 审计回放
```

1. **资产管理** → 新建资产（主机名/IP/协议 SSH 或 RDP/端口/系统下拉选择/分组标签）→ 添加托管账号（用户名+密码，加密存储）
2. **授权管理** → 新建策略（用户/组 × 资产/节点 × 账号 × 生效时段 × 命令过滤）
3. **用户管理** → 创建运维用户（角色：user 运维 / auditor 审计 / admin 管理员），用户首次登录自行绑定 TOTP
4. 用户在 **我的资产** 看到被授权的资产（支持主机名/IP/系统/分组搜索 + 协议筛选），点「连接」→ 新标签页打开 Web 终端

### 高危命令防护

- 用户在 SSH 会话中敲 `rm -rf /`、`shutdown`、`DROP DATABASE` 等 → **命令直接阻断**，不执行
- `chmod 777`、`iptables -F`、`TRUNCATE TABLE` 等 → 放行但**实时告警**
- 规则在数据库 `command_filters` 表，管理页可维护

### Webhook 告警（钉钉/企微）

系统设置 → 高危命令告警 Webhook → 填入机器人地址 → 点「📡 发送测试」→ 绿卡即配置成功（测试消息会真实推送到群里）。触发高危命令时实时推送。

### 审计

| 页面 | 功能 |
|------|------|
| 在线会话 | 实时监控 + 一键强断 |
| 会话审计 | 历史会话列表（分页 20/50/100 条/页）+ **终端录像回放** + CSV 导出 |
| 命令审计 | 全量命令检索（关键字/动作筛选，分页）+ CSV 导出 |

### LDAP 目录认证（可选）

系统设置 → 目录认证（OpenLDAP）→ 填 URL / Base DN / Bind DN / Bind 密码 → 「⚡ 测试连接」→ 「🔄 立即全量同步」。之后 LDAP 用户可直接用目录密码登录；部署包已自带每日 02:30 自动同步定时器。

> 密码框留空保存 = 保留旧密码（不回显字段的标准语义）。

### 字段选项字典（资产系统/分组）

系统设置 → 资产字段选项：操作系统与分组标签的候选值存在数据库 `field_options` 表，界面增删即时生效，无需改代码重启。

---

## 🌐 API 概览（前缀 `/api/v1`，JWT Bearer）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /auth/login | 登录（username/password/totp） |
| POST | /auth/refresh | 刷新 token（7 天有效） |
| GET | /auth/me | 当前用户 |
| GET/POST | /assets · /nodes · /users · /policies | 资产/节点/用户/策略管理 |
| GET | /my/assets | 我的授权资产 |
| GET | /assets/field-options | 字段选项字典 |
| GET | /sessions?page=&page_size= | 会话历史（分页） |
| GET | /sessions/active · POST /sessions/{id}/kill | 在线会话 / 强断 |
| GET | /sessions/{id}/cast | 会话录像 |
| GET | /commands?q=&action=&page= | 命令审计（分页） |
| POST | /rdp/tokens | RDP 一次性 token |
| WS | /ws/terminal/{asset}/{account}?token= | SSH Web 终端 |
| WS | /ws/rdp/{token} | RDP 通道 |
| GET | /health | 健康检查 |

完整交互文档：部署后访问 `http://<服务器IP>:8000/docs`（FastAPI Swagger）。

**调用示例**：

```bash
# 登录取 token
curl -sk -X POST http://<IP>/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"***","totp":"123456"}'

# 带 token 查资产
curl -sk http://<IP>/api/v1/assets -H "Authorization: Bearer <access_token>"
```

## 🔧 常用运维命令

```bash
systemctl status nextbastion        # 服务状态
systemctl restart nextbastion       # 重启
journalctl -u nextbastion -f        # 实时日志
systemctl list-timers 'nb-*'        # LDAP 同步/清理定时器

# 源码更新后重新部署（幂等，不影响已有数据）
cd <源码目录> && bash deploy.sh
```

### 数据目录

```
/opt/nextbastion/
├── app/                        # 应用代码
├── venv/                       # Python 虚拟环境
├── records/                    # SSH 会话录像（按会话 ID）
├── logs/                       # 运维脚本日志
├── .secrets                    # JWT/凭据加密密钥（600 权限，⚠️ 勿删勿泄，请异地备份）
├── .db.env                     # 数据库密码（运维脚本用）
└── INITIAL_CREDENTIALS.txt     # 初始凭据 + TOTP Secret
```

## ⚠️ 安全须知

1. `.secrets` 是凭据加密根密钥，**删除后所有托管密码不可恢复**，请异地备份。
2. 上线前必做：修改 admin 初始密码、更换 MySQL 默认口令、Nginx 挂 HTTPS 证书。
3. 最小权限原则：普通运维用户只授 `user` 角色；审计人员授 `auditor`（只读+强断）；管理界面仅 `admin`。
4. guacd 仅监听 `127.0.0.1:4822`，请勿对外暴露。

## 🗺️ 路线图

- [x] V1.0 核心功能（认证/资产/授权/SSH 终端/录像/审计/高危拦截）
- [x] V1.0.2 Webhook 告警 + 测试按钮、分组搜索、字段字典落库、审计分页
- [ ] V1.1 RDP 录像导出、策略到期自动失效、多节点部署
- [ ] V2 数据库分片、开放 API 生态

## 📄 文档

- [PRD-NextBastion堡垒机.md](prd/PRD-NextBastion堡垒机.md) —— 完整产品需求（架构/数据模型/API/防 Bug 规范）
- [PRD-LDAP对接.md](prd/PRD-LDAP对接.md) —— LDAP 对接设计
- [角色权限矩阵](docs/角色权限矩阵.md)

---

© 2026 DuduW · NextBastion
