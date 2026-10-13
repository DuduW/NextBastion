# NextBastion 自研堡垒机 产品需求文档（PRD）

| 项目 | 内容 |
|------|------|
| 产品名 | NextBastion（内部代号） |
| 版本 | PRD v2.0（V1.0 已上线 192.168.110.114，本版更新实现状态 + RBAC 角色体系 + RDP 图形流落地 + V1.1 路线规划） |
| 日期 | 2026-10-12 |
| 技术栈 | Python 3.11 + FastAPI + MySQL 8.0 + HTML5 SPA + asyncssh + xterm.js 5.5 + guacd 1.5.5（RDP）+ guacamole-common-js 1.5.0 + Nginx |
| 作者 | Double（产品）· Qi（交付总监） |
| 状态 | **V1.0 已部署**（192.168.110.114，29+49+11+8 项自动化测试全绿） |

---

## 1. 背景与目标

### 1.1 背景

- 公司约 1000 台服务器（IDC 物理机 + OpenStack VM + 少量云上资产），运维入口分散，SSH 直连现象普遍，操作行为缺乏统一审计。
- 等保 2.0 与内部安全规范要求运维操作「事前授权、事中监控、事后审计」，当前无系统级落地方案。
- 市场调研结论（见《堡垒机市场调研报告》）：商用产品价格高且定制难，开源 JumpServer 功能全面但 Django 全家桶二开门槛高。自研轻量合规型堡垒机存在明确机会窗口。

### 1.2 产品定位

**面向 500 资产以内的中小规模环境，本地部署、深度可定制的轻量合规堡垒机。**

- 核心价值：4A 管控（认证/授权/账号/审计）+ **双协议接入（Linux SSH Web Terminal + Windows RDP Web 远程桌面）** + 完整审计链。
- 明确不做：数据库 SQL 级深度审计、VNC/RemoteApp、生物识别、信创认证（见 §9 边界）。

### 1.3 成功指标（上线后 3 个月）

| 指标 | 目标值 |
|------|--------|
| 纳管资产数 | ≥ 300 台（含 Windows 资产） |
| 运维人员周活（WAU） | ≥ 30 人 |
| SSH/RDP 会话经由堡垒机比例 | ≥ 90% |
| 高危命令拦截误报率 | ≤ 5% |
| 审计录像完整率（SSH cast + RDP 视频） | ≥ 99.5% |

---

## 2. 用户角色与场景

| 角色 | 说明 | 核心诉求 |
|------|------|----------|
| 普通运维用户 | SRE/DBA/网络工程师 | 快速登录授权资产，Web Terminal 开箱即用 |
| 系统管理员 | 基础设施 Team Lead | 资产/账号/授权批量管理，策略下发 |
| 安全审计员 | 安全负责人 | 会话回放、命令检索、报表导出、违规告警 |
| 第三方/外包人员 | 厂商工程师 | 临时授权、限时访问、全程录像 |

### 核心用户故事

1. 作为运维用户，我登录堡垒机后点击 **Linux 资产**即可打开 SSH 终端，点击 **Windows 资产**即可打开 RDP 远程桌面，均无需记忆目标机器密码。
2. 作为系统管理员，我能按「用户组 × 资产组 × 资产账号 × 时间段 × 命令黑名单」五维配置授权。
3. 作为审计员，我能按用户/资产/时间/命令关键字检索历史会话，并在线回放终端录像（SSH）与图形录像（RDP）。
4. 作为管理员，当有人执行 `rm -rf` 类高危命令时，我能在 3 秒内收到告警并一键阻断会话。
5. 作为管理员，我能导入 CSV 批量添加 500 台资产（含 Windows RDP 端口/账号）。
6. 作为审计员，我能回放 Windows 会话的图形录像，看清每次鼠标点击与窗口操作。

---

## 3. 功能需求

### 3.1 功能架构总览

```
NextBastion
├── 认证与账户
│   ├── 本地账号 + TOTP 双因子（复用 qcc-radius TOTP 经验）
│   ├── 用户组管理
│   └── 登录安全（失败锁定 / IP 白名单 / 会话超时）
├── 资产管理
│   ├── 资产 CRUD（主机名/IP/协议/端口/标签/节点树）
│   ├── 资产账号（托管凭据，AES-256-GCM 加密存储）
│   └── CSV 批量导入导出
├── 授权管理
│   ├── 五维授权模型（用户×资产×账号×时间×命令）
│   ├── 授权组（模板化批量授权）
│   └── 临时授权（带过期时间，到期自动回收）
├── 协议接入
│   ├── Linux SSH：Web Terminal（xterm.js + WebSocket + asyncssh）
│   │   └── 命令级审计（逐条捕获 + 高危拦截）
│   └── Windows RDP：Web 远程桌面（HTML5 guacamole-client + guacd 网关）
│       ├── NLA 网络级认证 + 免密凭据托管注入
│       ├── 剪贴板/磁盘映射/文件传输管控开关
│       └── 图形会话录像（服务端屏幕帧录制）
└── 审计中心
    ├── 实时会话监控（在线会话列表 / 强制断开 / 实时屏幕：SSH 文本流 + RDP 画面流）
    ├── 命令审计（命令日志全文检索 / 高危命令拦截与告警，SSH 专属）
    ├── 会话录像（SSH: asciinema 文本录像；RDP: WebM 视频录像，均带 Web 播放器 + 倍速回放）
    ├── 文件传输审计（SFTP + RDP 驱动器映射上传/下载记录）
    └── 审计报表（日报/周报/合规导出）
```

### 3.2 V1 功能清单（P0 = 必须，P1 = 重要）

| 模块 | 功能 | 优先级 | 说明 |
|------|------|--------|------|
| 认证 | 登录（账号密码 + TOTP） | P0 | 密码 bcrypt 存储；TOTP 兼容 Google Authenticator |
| 认证 | 用户/用户组 CRUD | P0 | 用户绑定多组 |
| 认证 | 登录失败锁定（5 次锁 15 分钟） | P0 | 防爆破 |
| 资产 | 资产 CRUD + 节点树 | P0 | 节点树组织（如：苏州 IDC / 上海 IDC / 云上） |
| 资产 | 资产账号托管 | P0 | 凭据加密存储，Web 端不可见明文 |
| 资产 | CSV 批量导入导出 | P0 | 模板下载 + 错误行报告 |
| 授权 | 五维授权规则 | P0 | 用户/组 × 资产/节点 × 账号 × 生效时段 × 命令过滤 |
| 授权 | 临时授权 | P1 | 有效期至精确分钟，到期自动失效 |
| 接入 | SSH Web Terminal（xterm.js + WebSocket） | P0 | Linux 资产；浏览器内直连，支持中文字体/复制粘贴 |
| 接入 | **RDP Web 远程桌面（guacamole 协议 + guacd）** | **P0** | Windows 资产；浏览器内打开远程桌面，支持 NLA、剪贴板/磁盘映射管控；**全屏（Fullscreen API，F11/Esc 同效）**；**高画质：分辨率档位自适应/1080P/2K/4K（RDP 动态分辨率协商）、32bpp 真彩色、30fps 自适应帧率、1:1 像素渲染不拉伸** |
| 接入 | SSH 客户端代理接入 | P1 | 用户 ssh user@bastion -p 2222 → 资产选择菜单 |
| 审计 | 实时会话列表 + 强制断开 | P0 | 管理员可中断任意 SSH/RDP 会话 |
| 审计 | 命令日志记录 + 检索 | P0 | SSH 会话命令逐条记录，全文索引（RDP 会话记录图形录像，命令级审计不适用） |
| 审计 | 高危命令拦截 | P0 | 正则规则库，可配阻断/告警/放行三态（SSH 专属） |
| 审计 | asciinema 会话录像 + 回放 | P0 | SSH 会话；前端嵌入 asciinema-player |
| 审计 | **RDP 图形会话录像 + 回放** | **P0** | 服务端按屏幕变化帧录制为 WebM/VP9，前端 HTML5 video 播放器 + 倍速回放 |
| 审计 | 文件传输审计（SFTP + RDP 驱动器映射） | P1 | 记录上传/下载文件名与大小 |
| 审计 | 审计报表导出 | P1 | CSV/Excel，按时间段汇总 |
| 系统 | 操作日志（管理员行为审计） | P0 | 配置变更全记录 |
| 系统 | 系统设置（会话超时/密码策略） | P1 | — |

### 3.3 关键流程

#### 3.3.1 用户登录与连接资产（按协议自动路由）

```
用户 → 登录页（账号+密码+TOTP）
     → 首页「我的资产」列表（仅显示已授权资产，标注协议类型 Linux/Windows）
     → 点击资产 → 选择资产账号（无需输密码）
     ├── Linux 资产 → 新开标签页：SSH Web Terminal（xterm.js ↔ WebSocket ↔ asyncssh）
     │                └→ 会话全程录像（服务端 asciinema cast 流）
     └── Windows 资产 → 新开标签页：RDP Web 桌面（HTML5 canvas ↔ guacamole 协议 ↔ guacd ↔ RDP/NLA）
                       └→ 会话全程录像（服务端屏幕帧 → WebM 视频流）
```

#### 3.3.2 高危命令拦截（SSH 会话）

```
用户输入命令 → 服务端逐条捕获（PTY 读取）
  → 匹配命令过滤规则（资产/用户组维度的正则规则集）
     ├── 放行 → 正常执行，写命令日志
     ├── 告警 → 执行 + 实时推送告警给管理员（WebSocket + 站内信）
     └── 阻断 → 拦截不执行 + 告警 + 会话标记高危

RDP 会话说明：图形协议无命令流，管控点为「操作行为审计（录像）+ 剪贴板/磁盘映射开关 + 会话级阻断」。
```

#### 3.3.3 审计回放（双协议）

```
审计员 → 审计中心 → 会话列表（筛选：用户/资产/时间/含高危/协议类型）
      → 点击「回放」
      ├── SSH 会话 → 内嵌 asciinema-player 在线播放（1x/2x/4x 倍速 + 命令时间轴跳转）
      └── RDP 会话 → 内嵌 HTML5 video 播放 WebM 图形录像（1x/2x/4x 倍速 + 关键帧时间轴）
```

#### 3.3.4 RDP 会话管控

```
连接前：授权策略检查（用户/资产/账号/时段）+ 会话策略（分辨率/剪贴板/磁盘映射开关）
连接中：guacd 维持 RDP 通道；服务端旁路录制屏幕帧（变化帧检测，典型 1~5 fps）
画质与显示：
  ├── 分辨率档位：自适应（跟随浏览器窗口）/ 1920×1080 / 2560×1440 (2K) / 3840×2160 (4K)
  │   └── 经 RDP 动态分辨率扩展与目标机协商，切换不中断会话
  ├── 色深 32bpp 真彩色；帧率 30fps 自适应（网络劣化自动降帧保清晰度，不降分辨率）
  └── 全屏：浏览器 Fullscreen API（按钮/F11 进入，Esc 退出）；全屏下 1:1 像素渲染，禁止拉伸模糊
管控项：
  ├── 剪贴板：可整体禁用或仅单向（上传/下载）
  ├── 磁盘映射：默认禁用；开启后文件传输进 file_transfer_logs 审计
  ├── 水印：画面叠加「用户名 + IP + 时间」暗水印（防拍屏泄露溯源）
  └── 管理员强制断开：调用 guacd 终止连接，用户端 3 秒内感知
```

### 3.4 高危命令规则库（内置）

| 类别 | 示例规则 | 默认动作 |
|------|----------|----------|
| 文件破坏 | `rm -rf /`, `rm -rf /*` | 阻断 |
| 磁盘操作 | `mkfs`, `dd if=... of=/dev/sd` | 阻断 |
| 权限提升 | `chmod -R 777 /` | 告警 |
| 用户管理 | `userdel root` | 阻断 |
| 进程清理 | `kill -9 1`, `pkill sshd` | 告警 |
| 数据库 | `DROP DATABASE`, `TRUNCATE` | 阻断 |
| 网络危险 | `iptables -F`（生产节点） | 告警 |
| 关机重启 | `shutdown`, `reboot`, `init 0` | 阻断 |

规则支持正则自定义、按资产节点/用户组差异化配置，动作三态可调。

---

## 4. 数据模型（MySQL 8.0）

核心表 12 张，字符集 utf8mb4，InnoDB。

```sql
-- 用户域
users            (id, username, password_hash, totp_secret, email, phone,
                  is_active, is_mfa_enabled, locked_until, created_at, updated_at)
user_groups      (id, name, description, created_at)
user_group_map   (user_id, group_id)                 -- 用户↔组 多对多

-- 资产域
asset_nodes      (id, parent_id, name, sort)         -- 节点树（邻接表）
assets           (id, node_id, hostname, ip, os_type, ssh_port,
                  rdp_port, protocol, labels JSON, status, created_at, updated_at)
                  -- protocol: ssh / rdp；Windows 资产填 rdp_port（默认 3389）
asset_accounts   (id, asset_id, username, cred_type,                 -- password/key
                  secret_encrypted, become_user, become_mode,        -- sudo/su 提权（SSH）；RDP 用域账号
                  last_verified_at, status)

-- 授权域
access_policies  (id, name, user_or_group_type, user_or_group_id,
                  asset_or_node_type, asset_or_node_id,
                  account_pattern,                                   -- 账号匹配：* / root / app*
                  allowed_periods JSON,                              -- 生效时段
                  command_filter_id,                                 -- 关联命令过滤集（SSH）
                  rdp_session_config JSON,                           -- RDP 会话策略：分辨率/剪贴板/磁盘映射/水印
                  valid_from, valid_until, is_enabled, created_by)

-- 审计域
sessions         (id, user_id, asset_id, protocol, account_name, client_ip,
                  started_at, ended_at, duration_s, status,          -- active/closed/killed
                  cast_file_path, video_file_path,                   -- SSH: cast；RDP: WebM
                  is_high_risk)
command_logs     (id, session_id, user_id, asset_id, command_text,
                  matched_rule_id, action,                           -- allow/alert/block
                  executed_at, risk_level)                           -- SSH 会话专属
file_transfer_logs (id, session_id, user_id, asset_id, direction,    -- upload/download
                  file_name, file_size, transferred_at)              -- SFTP + RDP 驱动器映射
command_filters  (id, name, rules JSON, created_at)                  -- [{"regex": "...", "action": "block"}]

-- 系统域
login_logs       (id, username, client_ip, result, reason, logged_at)
audit_logs       (id, actor_id, action, target_type, target_id,
                  detail JSON, created_at)                            -- 管理员操作审计
```

设计要点：

- **凭据加密**：`secret_encrypted` 使用 AES-256-GCM 加密，密钥来自环境变量（KMS 后续可扩展），数据库泄漏不泄漏密码。
- **命令检索**：`command_logs.command_text` 建 FULLTEXT 索引 + 前缀索引（ip/时间分区按月），支撑亿级检索。
- **录像存储**：SSH cast 文件与 RDP WebM 视频均落本地磁盘（可配置 NFS/对象存储挂载），路径记库，按月归档；RDP 录像按「变化帧检测」录制控制体积（典型 1 小时会话 30~80MB）。
- **协议区分**：`sessions.protocol` 区分 ssh/rdp，回放页按协议路由到 asciinema-player 或 video 播放器。

---

## 5. API 设计（FastAPI）

REST 风格，前缀 `/api/v1`，JWT Bearer 认证（access 30min + refresh 7d）。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /auth/login | 登录（密码 + TOTP），返回 JWT |
| POST | /auth/refresh | 刷新 token |
| GET | /auth/me | 当前用户信息 |
| GET | /assets | 资产列表（分页/筛选/节点过滤） |
| POST | /assets | 新建资产 |
| PUT | /assets/{id} | 更新资产 |
| DELETE | /assets/{id} | 删除资产 |
| POST | /assets/import | CSV 批量导入 |
| GET | /assets/export | 导出 |
| GET | /assets/{id}/accounts | 资产账号列表 |
| POST | /assets/{id}/accounts | 新增账号（托管凭据） |
| GET | /nodes | 节点树 |
| POST | /policies | 创建授权策略 |
| GET | /policies | 策略列表 |
| PUT | /policies/{id} | 更新策略 |
| GET | /my/assets | 当前用户可见资产（首页） |
| GET | /sessions/active | 在线会话列表 |
| POST | /sessions/{id}/kill | 强制断开会话 |
| GET | /sessions | 历史会话（分页/筛选） |
| GET | /sessions/{id}/commands | 会话命令日志 |
| GET | /sessions/{id}/cast | 获取 SSH 录像文件（流） |
| GET | /sessions/{id}/video | 获取 RDP 图形录像（WebM，HTTP Range 支持） |
| GET | /commands | 全局命令检索 |
| GET | /file-transfers | 文件传输记录 |
| GET | /filters | 命令过滤规则集 |
| POST | /filters | 创建/更新规则集 |
| GET | /reports/sessions | 审计报表（时间段汇总） |
| WS | /ws/terminal/{asset_id}/{account_id} | SSH Web Terminal 通道 |
| POST | /rdp/tokens | 签发 RDP 连接一次性 token（guacd 会话参数，防重放，60s 有效） |
| WS | /ws/rdp/{token} | RDP Web 桌面通道（guacamole 二进制协议，经 FastAPI 代理 guacd） |
| WS | /ws/monitor | 管理员实时告警推送 |
| WS | /ws/session/{id}/live | 实时屏幕监视（SSH 文本流 / RDP 画面流） |

约定：统一响应体 `{code, message, data}`；分页参数 `page/page_size`；错误码分段（401 未认证 / 403 未授权 / 404 不存在 / 409 冲突）。

---

## 6. 页面结构（信息架构）

```
/login                  登录（账号+密码+TOTP）
/dashboard              仪表盘（资产数/在线会话/今日命令/高危告警 4 卡片 + 趋势图）
/assets                 资产管理（左：节点树；右：资产表格 + 抽屉编辑，含协议列 SSH/RDP）
/assets/:id             资产详情（账号列表 + 授权此资产的用户）
/terminal/:sessionId    SSH Web Terminal（全屏 xterm.js，Linux 资产）
/rdp/:sessionId         RDP Web 远程桌面（全屏 canvas，Windows 资产；连接工具栏含剪贴板/全屏/断开）
/policies               授权管理（策略列表 + 五维配置表单 + RDP 会话策略子表单）
/sessions/active        在线会话（实时列表 + 断开/监视按钮，含协议列）
/sessions/history       会话审计（筛选含协议类型 + 回放入口）
/sessions/:id/replay    录像回放（SSH→asciinema-player；RDP→HTML5 video，自动路由）
/commands               命令审计（全文检索 + 高危标记，SSH 会话）
/files                  文件传输审计（SFTP + RDP 驱动器映射）
/reports                审计报表
/filters                高危命令规则库管理
/users                  用户管理（用户/组）
/settings               系统设置 / 操作日志
```

UI 规范（强制）：浅灰 `#f5f5f7` 背景 + 白卡片 + 14~16px 大圆角 + 深海军蓝 `#0b3d62` 主色，对齐 admin-spa 现有设计语言；标题/数字用 Noto Serif SC，正文 Noto Sans SC。

---

## 7. 非功能需求

| 维度 | 要求 |
|------|------|
| 性能 | 单节点并发 SSH 会话 ≥ 150 + RDP 会话 ≥ 50（合计 ≥ 200）；命令日志写入延迟 ≤ 200ms；页面首屏 ≤ 2s；RDP 桌面操作端到端延迟 ≤ 150ms（同机房） |
| **RDP 画质** | **分辨率支持自适应/1080P/2K/4K 档位（策略可限定上限）；32bpp 真彩色；30fps 自适应帧率；全屏 1:1 像素渲染（禁拉伸）；2K@30fps 单会话带宽 ≤ 8 Mbps** |
| 安全 | 全站 HTTPS；JWT + TOTP；凭据 AES-256-GCM；MySQL 最小权限账号；RDP 一次性连接 token（60s 防重放）；操作日志不可删除（仅追加） |
| 审计留存 | 命令日志与录像（cast + WebM）保留 ≥ 180 天（可配置） |
| 可用性 | V1 单节点（systemd + Nginx 反代 + guacd 常驻）；预留多实例水平扩展（WebSocket 会话粘滞） |
| 兼容性 | Chrome/Edge 100+（WebRTC/Canvas）；目标资产 OpenSSH 7.x+（含 CentOS 7）；Windows Server 2012 R2+ / Windows 10+（RDP with NLA） |
| 部署 | Docker Compose 一键部署（app + mysql + nginx + guacd）或裸机 systemd；Python 3.11+ |
| 备份 | mysqldump 每日全量 + binlog；录像目录（cast + WebM）定时 rsync 异地 |

依赖选型：`asyncssh`（异步 SSH，替代 paramiko 同步阻塞）、`xterm.js`（前端终端）、`asciinema` cast 格式（自研录制器）、**`guacd`（Apache Guacamole 服务端，C 进程，RDP/VNC 协议网关 + 会话录制）**、**`guacamole-common-js`（前端 canvas 客户端，仅用其渲染层，不用其 Java Web 应用）**、`pyotp`（TOTP）、`uvicorn` + `gunicorn`（多 worker）、`ffmpeg`（RDP 屏幕帧编码 WebM/VP9）。

---

## 8. 里程碑计划

| 阶段 | 周期 | 交付内容 |
|------|------|----------|
| M1 骨架 | 第 1 周 | 项目脚手架、DB 建表、登录 + TOTP、用户管理 |
| M2 资产 | 第 2 周 | 资产/节点/账号 CRUD（含 rdp_port/protocol）、CSV 导入、授权策略（含 RDP 会话策略） |
| M3 终端·SSH | 第 3 周 | SSH Web Terminal、cast 录像、实时监控、强制断开 |
| M4 终端·RDP | 第 4 周 | guacd 集成、RDP Web 桌面、NLA 凭据注入、WebM 录像、剪贴板/磁盘映射/水印管控 |
| M5 审计 | 第 5 周 | 命令日志 + 高危拦截、双协议回放、报表、操作日志 |
| M6 加固 | 第 6 周 | 安全加固、压测（150 SSH + 50 RDP 并发）、部署脚本、文档 |

---

## 9. 边界与非目标（V1 明确不做）

1. ~~RDP 图形协议接入~~（**v1.1 变更：RDP 已提前至 V1，见 §3.2/§3.3.4**；VNC 仍不做，guacd 原生支持但 V2 再评估）。
2. 数据库 SQL 解析级审计（齐治 DSG 主场，不自投）。
3. K8s Pod 接入与审计。
4. LDAP/AD/OIDC 统一认证（V2，优先 LDAP）。
5. 双人复核/四眼原则审批流编排。
6. 自动改密轮换（V2）。
7. 多租户/多组织体系。
8. RemoteApp 单应用发布（V2 评估）。

---

## 10. 风险与对策

| 风险 | 等级 | 对策 |
|------|------|------|
| 自研录像/终端稳定性不及成熟产品 | 高 | M3/M4 周专项压测；asciinema 格式成熟可控；预留回退：临时切 JumpServer |
| **guacd 集成复杂度（RDP 通道代理 + 录制）** | **高** | guacd 为 Apache 顶级项目、协议文档完备；FastAPI 仅做 token 签发与 WS 代理，不做协议解析；M4 周预留 50% 缓冲；兜底方案：直接嵌入 guacamole-client 整页 iframe |
| 高危命令正则误拦影响运维 | 中 | 默认「告警」灰度两周 → 再切「阻断」；规则支持资产级豁免 |
| 1000 台资产纳管规模超 V1 设计 | 中 | V1 目标 500 台，架构按分页/索引预留扩展；超规模走 V2 分片 |
| 审计数据增长快（RDP 视频体积大） | 中 | command_logs 按月分区；RDP 录像变化帧检测 + VP9 压缩（1h ≈ 30~80MB）+ 90 天后转低码率归档 |

---

## 11. 验收标准（V1）

1. 全流程可用（SSH）：登录（TOTP）→ 授权 → Web Terminal 连 CentOS 7/openEuler 资产 → 操作全程录像 → 审计员检索并回放。
2. **全流程可用（RDP）：登录（TOTP）→ 授权 → Web 远程桌面连 Windows Server 2019 资产（NLA 免密注入）→ 图形操作全程录像 → 审计员回放 WebM 录像，画面可辨识鼠标点击与窗口操作。**
3. **RDP 管控生效：剪贴板/磁盘映射按策略禁用后操作不生效；画面水印包含用户名+IP+时间；管理员强制断开后用户端 3 秒内黑屏提示。**
4. **RDP 画质达标：2K (2560×1440) 档位下文字边缘清晰无糊化；全屏（F11/Esc）进入退出正常，全屏下 1:1 渲染无拉伸；分辨率档位切换会话不中断；HUD 正确显示当前 分辨率/色深/帧率。**
5. 高危命令（`rm -rf /`）在测试资产上被成功阻断并产生告警记录。
6. CSV 一次性导入 500 资产 + 账号（含 Windows 资产 rdp_port）无错误。
7. 150 并发 SSH + 50 并发 RDP 会话持续 30 分钟，无崩溃、录像完整率 ≥ 99.5%。
8. 管理员可强制断开任意在线会话（SSH/RDP），用户端 3 秒内感知。

---

## 12. V1.0 实现状态（2026-10-12 已上线）

**部署**：192.168.110.114（Rocky Linux 9.6 / Python 3.11.13 / MySQL 8 / Nginx / guacd 1.5.5）
**入口**：http://192.168.110.114（admin / Admin@2026 + TOTP）

### 12.1 功能交付清单

| 模块 | 交付内容 | 状态 |
|------|----------|------|
| 认证 | 账密+TOTP 双因子 / JWT 双 token / 登录日志 / 失败锁定计数 / 禁用即拒（403+WS 4403） | ✅ |
| 用户管理 | CRUD + 角色（admin/auditor/user 三选）+ 组多选 + TOTP 重置（旧码即时失效）+ 自我保护 | ✅ |
| 用户组 | CRUD + 成员数 + 成员查看 + 删除护栏（有成员/被策略引用均 409） | ✅ |
| 资产管理 | CRUD + 协议联动（SSH⇄RDP 端口/默认账号）+ 节点树 + 托管凭据 AES-256-GCM（接口零回显）+ 在线会话删除护栏 | ✅ |
| 授权管理 | 五维策略 CRUD + 启停 toggle + RDP 会话策略（剪贴板/磁盘/水印）+ 有效期临时授权 | ✅ |
| SSH 终端 | asyncssh 真实连接 + xterm.js 渲染 + PTY 动态 resize（回显错位已修）+ asciinema cast 全程录像 | ✅ |
| 命令审计 | 行缓冲旁路审计（退格/Ctrl+C/U 感知）+ 高危三态：block 拦截执行 / alert 放行告警 / allow 记录 | ✅ |
| RDP 图形流 | guacd 编译部署 + WS 桥（正确 guac 握手时序）+ 前端渲染 + 错误码中文映射；实测 NLA 真实握手到达目标机 | ✅ |
| 会话审计 | 在线列表/强断（跨 worker DB 轮询）/历史/cast 回放/命令检索/仪表盘 | ✅ |
| RBAC | admin 全能 / auditor 审计只读+强断 / user 仅接入；后端多角色白名单 + 前端导航显隐+路由守卫 | ✅ |
| 部署 | deploy.sh 一键（含 SELinux/no-cache/密钥持久化）+ README + 测试套件 | ✅ |

### 12.2 质量基线

| 套件 | 结果 |
|------|------|
| test_api.py（全量回归） | 29/29 |
| test_rbac.py（角色矩阵 16 API×3 角色） | 49/49 |
| 用户管理全链路 | 11/11 |
| 用户组 CRUD | 8/8 |
| RDP E2E（真实 NLA 握手） | 链路通（待正确凭据出图） |

### 12.3 已知限制

1. RDP 录像（WebM）未实现（guacd session recording 已具备，V1.1 接线）。
2. SSH 命令审计为旁路行缓冲：vim/top 全屏内按键不入审计；粘贴多行按行审。
3. 高危规则为全局库，按资产/组差异化配置 UI 未做（表已支持 command_filter_id）。
4. 无 HTTPS（Nginx 已就绪，挂证书即可）。
5. 单节点部署；多 worker 下 WS 会话粘滞未配（Nginx ip_hash 即可，V1.1）。

### 12.4 增量交付（2026-10-13，V1.0.2）

#### 新功能

| # | 模块 | 交付内容 | 状态 |
|---|------|----------|------|
| 1 | 告警通道 | **Webhook 测试按钮**：POST `/settings/webhook/test` 逐 URL 发送测试消息（含触发人+时间戳，5s 超时），返回逐地址 ok/status/ms\|error；前端「📡 发送测试」三态结果（🎉 全成功绿卡 / ⚠️ 部分失败红卡带错误详情 / 未配置黄提示）；**未保存也可先测后存** | ✅ 已验证（钉钉机器人 1/1 推送进群） |
| 2 | 资产管理 | **按分组（labels）搜索**：搜索框匹配范围含分组名（data-search 拼接） | ✅ |
| 3 | 我的资产 | **同款搜索 + 协议筛选**：搜索框（主机名/IP/系统/分组）+ 协议 chips（全部/SSH/RDP）+ N/总 台实时计数；过滤逻辑与资产管理统一为通用函数 `filterAssetsTable()` | ✅ |
| 4 | 资产表单 | **操作系统下拉化**：select+optgroup（Linux/Windows/网络设备）+「✏️ 其他（手动输入）」兜底；编辑旧资产时非预置值（如 win11）自动落"其他"并回填，**旧数据无损** | ✅ |
| 5 | 字段字典 | **资产字段选项全部落库**：新表 `field_options`（field_key=os_type/label，opt_value，opt_group，sort_no，uk 唯一键）；GET `/assets/field-options`（表单动态构建下拉/datalist）+ POST `/settings/field-options`（admin 增删+审计日志）；系统设置页新增「🗂 资产字段选项」管理卡片（chips 展示/➕添加/✕删除，**即时生效无需重启**）；接口异常时前端回退内置清单 | ✅ 全链路验证（UI 添加→表单可见→UI 删除→同步清除） |
| 6 | 审计中心 | **日志分页**：会话审计/命令审计两页改为服务端分页，**每页 20/50/100 条可选、默认 20**；`/sessions`、`/commands` 加 page/page_size 参数（page_size 20~200，默认 20），返回 {rows,total,page,pages,page_size}；前端通用分页条（共 N 条·第 x/y 页 + 每页条数下拉（20/50/100）+ «‹ 页码 ›»，当前页高亮，切换条数自动回第 1 页，单页时仍可切条数）；替代原 LIMIT 200 截断 | ✅ API 直测（两页无重叠、越界页空）+ 真浏览器验证（默认 20 ✓ 切 100→100 行/2 页 ✓ 切 50→50 行/3 页 ✓ 命令页默认 20 ✓） |
| 7 | 发布 | **v1.0.3 开源发布**：源码脱敏（去除内网 IP/真实口令默认值，settings 页访问地址改为动态 location.origin）后推送 GitHub（DuduW/NextBastion，含 .gitattributes 强制 LF）；deploy.sh 升级（nginx WS map 修正、NB_WITH_RDP=1 可选编译 guacd 1.5.5、.db.env 密钥文件 + nb-ldap-sync/nb-cleanup systemd 定时器自动安装、默认口令全部中性化）；新增公开版 README（安装/使用/API/安全须知）；一键部署压缩包 NextBastion-v1.0.3.tar.gz（git archive 生成，纯 LF）；4 个脱敏文件已同步回生产服务器并验证 | ✅ health 200 + settings 动态地址真浏览器验证 |

#### 当日修复的 Bug

| # | 现象 | 根因 | 修复 |
|---|------|------|------|
| 1 | LDAP 同步报 `password is mandatory in simple bind` | 保存配置时密码框留空（安全不回显的正常编辑习惯）→ 旧逻辑直接存**空密码**，把已配好的 Bind 密码冲掉 | 密码框**留空=保留旧密码**、填新值=更新、传 `-`=显式清空（匿名 bind）；详见 PRD-LDAP对接.md | 
| 2 | 资产表"端口列显示协议、协议列显示分组"（列整体错位） | 加分组功能时只在**行模板**插了分组徽标列，三处**表头**（我的资产/资产管理/搜索结果）漏插 → 数据左移一列 | 三处表头"系统"后统一补"分组"列；真浏览器逐列核对对齐 |
| 3 | 我的资产搜分组 0 命中 | `/my/assets` 接口 SQL 漏返回 `a.labels` 字段，前端 data-search 拼空 | SQL 补 labels 列；此后新字段须核对**所有**消费端 API |

---

## 13. 下一步规划（V1.1 候选，按优先级）

### P0（安全闭环，建议 1 周内）

| # | 事项 | 说明 | 工作量 |
|---|------|------|--------|
| 1 | **RDP 会话录像** | guacd 自带 session recording（recording-path 参数），桥接线落盘 + 会话表 video_file_path + 审计页回放（HTML5 video） | 0.5 天 |
| 2 | **RDP 策略下发** | rdp_session_config（剪贴板/磁盘/水印）目前仅存储未生效 → 桥按策略注入 disable-copy/paste、水印层前端叠加 | 0.5 天 |
| 3 | **HTTPS + 安全头** | Nginx 挂内网证书 + HSTS；JWT Cookie 化（HttpOnly）替代 sessionStorage | 0.5 天 |
| 4 | **高危规则分组化 UI** | 命令过滤规则集 CRUD 页面 + 策略绑定（表结构已支持） | 1 天 |

### P1（体验与效率，1-2 周）

| # | 事项 | 说明 | 工作量 |
|---|------|------|--------|
| 5 | 实时屏幕监视 | 管理员看在线用户画面：SSH=cast 流转发，RDP=guac 双客户端广播 | 1.5 天 |
| 6 | CSV 批量导入资产 | PRD 原始承诺项：模板下载+错误行报告（当前仅单个创建） | 0.5 天 |
| 7 | 资产连通性探测 | 定时 TCP 探测 22/3389 + 我的资产页可达徽标（现在只有静态状态） | 0.5 天 |
| 8 | 审计报表导出 | 会话/命令/登录三类 CSV/Excel 导出 + 日报汇总 | 1 天 |
| 9 | ~~告警通知通道~~ | ✅ **已完成（2026-10-13）**：Webhook 推送 + 测试按钮，兼容钉钉/企微 msgtype=text；详见 12.4 | ~~1 天~~ |

### P2（架构演进，按需）

| # | 事项 | 说明 |
|---|------|------|
| 10 | 多节点高可用 | Nginx ip_hash + MySQL 主从 + 录像目录 NFS 共享；deploy.sh 扩展集群模式 |
| 11 | 自动改密轮换 | 资产账号定期改密（Ansible/paramiko 批量）+ 托管凭据自动更新 |
| 12 | LDAP/AD 对接 | 认证源外接（企业域账号直接登录，PRD V2 项提前） |
| 13 | 数据库审计（评估） | guacd 无 DB 代理；如需 SQL 级审计评估独立模块或明确不做（维持 PRD 边界） |
| 14 | 开源发布准备 | 代码仓库整理（GitHub/Gitee）、LICENSE、Docker Compose 化、演示数据脚本 |

### 建议节奏

- **本周**：P0 全部（RDP 录像 + 策略生效 + HTTPS + 规则 UI）→ V1.0.1
- **下周**：P1 挑 5/6/7（监视/导入/探测）→ V1.1
- **之后**：按运维痛点从 P2 挑选；若对外开放则启动 14

---

## 14. 开发防 Bug 规范（2026-10-13 沉淀，后续迭代强制执行）

> 来源：10-13 三起线上 Bug 与开发过程踩坑的复盘。每条都是真实代价换来的，后续所有改动对照检查。

### 14.1 表格加列规范（防列错位）

- **表头与行模板必须成对修改**：任何表格增删列，先数一遍该表有几条渲染路径（本项目资产表有 **3 处**：我的资产 / 资产管理 / 全局搜索结果），逐处核对"表头列数 == 行单元格数"。
- 交付前用**真浏览器逐列断言**：`表头[i] ↔ 单元格[i]` 一一对应，不能只看"页面能渲染"。

### 14.2 密码类字段保存语义（防静默冲掉凭据）

- 凡**不回显**的安全字段（Bind 密码、托管凭据、Webhook secret 等），保存时必须遵循：
  - **留空 = 保留旧值**（最常见编辑场景，绝不能存空）
  - 填新值 = 更新
  - 特殊占位（如 `-`）= 显式清空
- 反面教材：LDAP Bind 密码被空保存冲掉 → 同步全挂（`password is mandatory in simple bind`）。

### 14.3 数据字段变更同步规范（防接口漏列）

- assets 表**新增字段**时，必须检索所有消费该表的 API（`/assets`、`/my/assets`、搜索、导出…）逐一补列——`/my/assets` 漏 `labels` 直接导致"我的资产搜分组 0 命中"。
- 检索方法：`grep -n "FROM assets" app/main.py`，逐个端点核对 SELECT 列清单。

### 14.4 前端单文件大模板的编辑纪律（防改丢/改错位置）

- **幂等检查标记必须用目标块独有文本**：不能用可能出现在其他代码（如 JS 函数体）里的 id/变量名判断"是否已应用"——曾用 `fo-os-list`（函数里也有）误判卡片已插入，导致部署后页面空白缺卡片。正确做法：用目标块独有的中文文案（如 `资产字段选项`）做标记。
- **函数不能插进对象字面量内部**：PAGES 是对象方法简写语法，向其中插入 `function xxx(){}` 会直接语法错误。新函数一律放对象外部（`const PAGES={` 之前）。
- 多段替换脚本**中途断言失败不落盘**，重跑时先判断哪些段已应用、哪些没有（逐段幂等），不要假设"上轮全部成功或全部失败"。
- 每轮编辑后必须过 `new Function(<script>)` 语法校验再部署。

### 14.5 自动化验证规范（防假阴性）

- **TOTP 现取现用**：验证脚本严禁复用上轮生成的 TOTP 文件（30s 有效期），过期会导致**静默登录失败**，表象是"找不到元素"，极易误判为功能 Bug。每次跑 Playwright 前重新向 114 取码。
- 验证失败时先证明**前置条件**成立（登录态 USER.username、API 可达、目标 HTML 已下发 `curl | grep`），再怀疑功能本身。
- 涉及外部推送（Webhook）的功能，用"必然失败的 URL + 真实可用 URL"组合测试，分别断言错误路径与成功路径。
