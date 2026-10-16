"""NextBastion - FastAPI 主应用
路由：认证 / 用户 / 资产 / 节点 / 授权 / 会话 / 命令审计 / RDP token / WS 终端
"""
import asyncio, json, os, re, time, uuid
from datetime import datetime
from typing import Optional

import pyotp, pymysql
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketState

import utils
from config import DEFAULT_FILTER_RULES, RDP_TOKEN_TTL, RECORD_DIR

app = FastAPI(title="NextBastion", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

RDP_TOKENS = {}      # token -> {asset_id, account_id, user_id, exp}
ACTIVE_KILL = set()  # 被管理员强断的会话 id

# ============================================================
# 中间件：全局异常 -> 统一响应体
# ============================================================
@app.middleware("http")
async def unify_response(request: Request, call_next):
    try:
        resp = await call_next(request)
        # 静态资源不缓存（前端迭代频繁，杜绝浏览器强缓存旧页面）
        if not request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-cache, must-revalidate"
        return resp
    except HTTPException as e:
        return JSONResponse(utils.err(e.status_code, e.detail), status_code=e.status_code)
    except Exception:
        # 安全修复：不回显异常原文（信息泄露）；记日志内部排查
        import traceback
        traceback.print_exc()
        return JSONResponse(utils.err(500, "internal error"), status_code=500)

# ============================================================
# 认证依赖
# ============================================================
async def auth(request: Request = None, token: str = None):
    t = token or (request.headers.get('Authorization', '').replace('Bearer ', '') if request else '')
    if not t:
        raise HTTPException(401, "not authenticated")
    try:
        payload = utils.decode_token(t)
        if payload.get('kind') != 'access':
            raise HTTPException(401, "wrong token kind")
        return payload
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(401, "invalid or expired token")

def require_role(*roles):
    """多角色白名单：require_role('admin') / require_role('admin','auditor')"""
    def dep(payload=Depends(auth)):
        if payload['role'] not in roles:
            raise HTTPException(403, "forbidden")
        return payload
    return dep

def client_ip(request: Request) -> str:
    """安全取客户端 IP：仅当 TCP 对端属于可信代理（nginx 本机/回环）时才采信代理头，
    且要求头值是单个合法 IP；其余（公网直连 8000、伪造头）一律用 socket 对端地址——防 XFF 绕过限流。"""
    import ipaddress
    peer = request.client.host if request.client else ''
    def _valid_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False
    try:
        p = ipaddress.ip_address(peer) if peer else None
        # 可信代理：回环（nginx 同机反代）；分离部署时在 config.py 定义 TRUSTED_PROXIES=[...]
        try:
            import config as _cfg
            _trusted_list = list(getattr(_cfg, 'TRUSTED_PROXIES', []))
        except Exception:
            _trusted_list = []
        trusted = bool(p and (p.is_loopback or peer in _trusted_list))
    except ValueError:
        trusted = False
    if trusted:
        for h in ('X-Real-IP', 'X-Forwarded-For'):
            v = request.headers.get(h, '')
            first = v.split(',')[0].strip() if h == 'X-Forwarded-For' else v.strip()
            if first and _valid_ip(first):
                return first
    return peer or 'unknown'

# R6: 审计异步落库（内存队列 + 后台线程批量写，同步路径零 DB 等待）
_AUDIT_Q = __import__("queue").Queue(maxsize=5000)
_AUDIT_STATS = {"written": 0, "dropped": 0}

def _audit_worker():
    while True:
        sql, args = _AUDIT_Q.get()
        try:
            utils.execute(sql, args)
            _AUDIT_STATS["written"] += 1
        except Exception:
            pass
        _AUDIT_Q.task_done()

def _audit_enqueue(sql, args):
    try:
        _AUDIT_Q.put_nowait((sql, args))
    except Exception:
        _AUDIT_STATS["dropped"] += 1

def write_login_log(username, ip, result, reason=''):
    # R6: 异步入队（登录高频路径不再同步写库）
    _audit_enqueue("INSERT INTO login_logs (username, client_ip, result, reason) VALUES (%s,%s,%s,%s)",
                   (username, ip, result, reason))
    # F5: Syslog 埋点（登录事件）
    try:
        import syslog_fwd
        ev = "login" if result == "success" else ("lock" if "lock" in (reason or "") else "login_fail")
        syslog_fwd.emit(ev, f"登录{'成功' if result=='success' else '失败'}: {username} ({reason or 'ok'})",
                        {"actor": username, "ip": ip, "result": result, "reason": reason})
    except Exception:
        pass

def write_audit(actor, action, target_type='', target_id='', detail=None):
    # R6: 异步入队
    _audit_enqueue("INSERT INTO audit_logs (actor, action, target_type, target_id, detail) VALUES (%s,%s,%s,%s,%s)",
                   (actor, action, target_type, str(target_id), json.dumps(detail or {}, ensure_ascii=False)))

import threading as _th
_th.Thread(target=_audit_worker, daemon=True, name="nb-audit").start()

# ============================================================
# 1. 认证 API
# ============================================================
@app.post("/api/v1/auth/login")
async def login(request: Request):
    body = await request.json()
    username, password, totp = body.get('username'), body.get('password'), body.get('totp', '')
    ip = client_ip(request)
    # IM-04: IP 级限流——近 10 分钟同 IP 真实失败 >20 次 → 拒绝（防跨账号喷洒；被拒请求不计数避免封禁续期）
    try:
        _ipf = utils.query(
            "SELECT COUNT(*) c FROM login_logs WHERE client_ip=%s AND result='fail' "
            "AND reason<>'ip throttled' AND logged_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)",
            (ip,), one=True)
        if _ipf and _ipf['c'] > 20:
            write_login_log(username or '-', ip, 'fail', 'ip throttled')
            raise HTTPException(423, "该 IP 登录失败次数过多，请 10 分钟后再试")
    except HTTPException:
        raise
    except Exception:
        pass  # 限流查询异常不阻断登录主流程
    u = utils.query("SELECT * FROM users WHERE username=%s", (username,), one=True)

    # ---------- 第一因子：本地密码 或 LDAP 目录 ----------
    import ldap_auth as _la
    ldap_cfg_on = bool(_la.get_config().get("enabled"))
    if u and u.get('auth_source') == 'ldap':
        # 目录用户：LDAP Bind 校验（密码零落地）
        if not ldap_cfg_on:
            write_login_log(username, ip, 'fail', 'ldap disabled')
            raise HTTPException(401, "目录认证未启用，请联系管理员")
        info = _la.authenticate(username, password)
        if not info:
            utils.execute("UPDATE users SET fail_count=fail_count+1 WHERE id=%s", (u['id'],))
            write_login_log(username, ip, 'fail', 'ldap bind failed')
            raise HTTPException(401, "目录账号或密码错误")
        u, _touched = _la.jit_provision(info)
    elif u and utils.verify_password(password, u['password_hash']):
        pass  # 本地密码正确
    elif not u and ldap_cfg_on:
        # 本地无此用户，目录启用 → JIT
        info = _la.authenticate(username, password)
        if not info:
            write_login_log(username, ip, 'fail', 'ldap bind failed')
            raise HTTPException(401, "目录账号或密码错误")
        u, _touched = _la.jit_provision(info)
    else:
        if u:
            utils.execute("UPDATE users SET fail_count=fail_count+1 WHERE id=%s", (u['id'],))
        write_login_log(username, ip, 'fail', 'bad credentials')
        raise HTTPException(401, "用户名或密码错误")

    if not u['is_active']:
        write_login_log(username, ip, 'fail', 'disabled')
        raise HTTPException(403, "账号已被禁用，请联系管理员")
    # I2：连续失败 5 次锁定 15 分钟
    if u['fail_count'] and u['fail_count'] >= 5:
        utils.execute("UPDATE users SET locked_until=DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE id=%s", (u['id'],))
        write_login_log(username, ip, 'fail', 'locked(auto)')
        raise HTTPException(423, "失败次数过多，账号已锁定 15 分钟")
    if u['locked_until'] and u['locked_until'] > datetime.now():
        write_login_log(username, ip, 'fail', 'locked')
        raise HTTPException(423, f"账号已锁定至 {u['locked_until']}")
    if u['is_mfa_enabled'] and u['totp_secret']:
        if not u.get('totp_bound'):
            # F8：目录用户首登未绑 TOTP —— 允许空码进入绑定流（返回 setup 数据，无正式 token）
            if totp:
                # 用户输入了码：尝试验证并完成绑定
                if not pyotp.TOTP(u['totp_secret']).verify(totp, valid_window=1):
                    raise HTTPException(401, "动态口令错误，请扫码后重试")
                utils.execute("UPDATE users SET totp_bound=1 WHERE id=%s", (u['id'],))
                write_login_log(username, ip, 'success', 'totp bound')
            else:
                write_login_log(username, ip, 'success', 'totp setup pending')
                return utils.ok({
                    "need_totp_setup": True,
                    "totp_secret": u['totp_secret'],
                    "otpauth_url": pyotp.totp.TOTP(u['totp_secret']).provisioning_uri(
                        name=username, issuer_name="NextBastion"),
                    "user": {"id": u['id'], "username": u['username'], "display_name": u['display_name']}
                })
        if not pyotp.TOTP(u['totp_secret']).verify(totp, valid_window=1):
            utils.execute("UPDATE users SET fail_count=fail_count+1 WHERE id=%s", (u['id'],))
            write_login_log(username, ip, 'fail', 'bad totp')
            raise HTTPException(401, "动态口令错误")
        # I1：TOTP 防重放——同时间片二次使用拒绝（IM-06: 独立表，不依赖 audit_logs）
        used = utils.query("SELECT ts_slot FROM totp_used_logs WHERE uid=%s ORDER BY id DESC LIMIT 1", (u['id'],), one=True)
        last_ts = used['ts_slot'] if used else 0
        now_ts = int(time.time()) // 30
        if now_ts == last_ts:
            write_login_log(username, ip, 'fail', 'totp replay')
            raise HTTPException(401, "动态口令已使用，请等待下一码")
        try:
            utils.execute("INSERT INTO totp_used_logs (uid, ts_slot) VALUES (%s,%s)", (u['id'], now_ts))
        except Exception:
            # 并发同窗口竞态（uk 冲突）：视为重放，拒绝
            write_login_log(username, ip, 'fail', 'totp replay')
            raise HTTPException(401, "动态口令已使用，请等待下一码")
    utils.execute("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=%s", (u['id'],))
    write_login_log(username, ip, 'success')
    return utils.ok({
        "access_token": utils.make_token(u['id'], u['username'], u['role']),
        "refresh_token": utils.make_token(u['id'], u['username'], u['role'], kind='refresh'),
        "user": {"id": u['id'], "username": u['username'], "role": u['role'], "display_name": u['display_name']}
    })

@app.post("/api/v1/auth/refresh")
async def refresh(request: Request):
    # 安全修复：body 缺失/畸形 JSON 一律 401（不进 json 解析、不回显异常原文）
    try:
        raw = await request.body()
        body = json.loads(raw) if raw else {}
        if not isinstance(body, dict):
            raise ValueError
    except Exception:
        raise HTTPException(401, "invalid refresh token")
    try:
        payload = utils.decode_token(body.get('refresh_token') or '')
        assert payload.get('kind') == 'refresh'
    except Exception:
        raise HTTPException(401, "invalid refresh token")
    u = utils.query("SELECT * FROM users WHERE id=%s", (payload['sub'],), one=True)
    if not u or not u['is_active']:
        raise HTTPException(401, "user disabled")
    return utils.ok({"access_token": utils.make_token(u['id'], u['username'], u['role'])})

@app.get("/api/v1/auth/me")
async def me(payload=Depends(auth)):
    u = utils.query("SELECT id, username, display_name, role, is_mfa_enabled FROM users WHERE id=%s",
                    (payload['sub'],), one=True)
    return utils.ok(u)

# ============================================================
# 2. 用户管理
# ============================================================
# IM-03: 密码强度策略
WEAK_PASSWORDS = {
    'password', 'password1', '12345678', '123456789', '1234567890',
    'qwertyuiop', 'abcdefghij', 'aaaaaaaaaa', 'changeme@2026', 'selfhost@2026',
    'letmein123', 'admin123456', 'p@ssw0rd12', '1qaz2wsx3e',
}

def password_policy_error(pw: str) -> Optional[str]:
    """返回 None=通过；否则返回错误消息。规则：≥10 位 + 大写/小写/数字/符号至少三类 + 非常见弱口令"""
    if not pw or not isinstance(pw, str):
        return "必须设置初始密码"
    if len(pw) < 10:
        return "密码长度至少 10 位"
    if pw.lower() in WEAK_PASSWORDS:
        return "密码过于常见，请更换"
    kinds = sum([
        any(c.isupper() for c in pw),
        any(c.islower() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    if kinds < 3:
        return "密码需至少包含大写/小写/数字/符号中的三类"
    return None

@app.get("/api/v1/users")
async def list_users(p=Depends(require_role('admin'))):
    rows = utils.query("""SELECT u.id, u.username, u.display_name, u.role, u.is_mfa_enabled, u.is_active,
                          u.auth_source, u.email,
                          (SELECT GROUP_CONCAT(g.name) FROM user_group_map m
                           JOIN user_groups g ON m.group_id=g.id WHERE m.user_id=u.id) AS group_names
                          FROM users u ORDER BY u.id""")
    return utils.ok(rows)

@app.post("/api/v1/users")
async def create_user(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    if utils.query("SELECT id FROM users WHERE username=%s", (b['username'],), one=True):
        raise HTTPException(409, f"用户名 {b['username']} 已存在")
    # IM-03: 密码必填 + 强度校验（不再使用任何默认口令）
    pw_err = password_policy_error(b.get('password'))
    if pw_err:
        raise HTTPException(400, pw_err)
    secret = pyotp.random_base32()
    uid = utils.execute(
        "INSERT INTO users (username, password_hash, totp_secret, display_name, role, is_mfa_enabled) VALUES (%s,%s,%s,%s,%s,%s)",
        (b['username'], utils.hash_password(b['password']), secret,
         b.get('display_name', ''), b.get('role', 'user'), 1))
    for gid in b.get('groups', []):
        utils.execute("INSERT IGNORE INTO user_group_map (user_id, group_id) VALUES (%s,%s)", (uid, gid))
    write_audit(p['username'], 'create_user', 'user', uid, {'username': b['username']})
    return utils.ok({"id": uid, "totp_secret": secret,
                     "otpauth_url": pyotp.totp.TOTP(secret).provisioning_uri(name=b['username'], issuer_name='NextBastion')})

@app.get("/api/v1/users/groups")
async def list_groups(p=Depends(auth)):
    rows = utils.query("""SELECT g.*, (SELECT COUNT(*) FROM user_group_map m WHERE m.group_id=g.id) AS member_count
                          FROM user_groups g ORDER BY g.id""")
    return utils.ok(rows)

@app.post("/api/v1/users/groups")
async def create_group(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    if not (b.get('name') or '').strip():
        raise HTTPException(400, "组名必填")
    if utils.query("SELECT id FROM user_groups WHERE name=%s", (b['name'],), one=True):
        raise HTTPException(409, f"用户组 {b['name']} 已存在")
    gid = utils.execute("INSERT INTO user_groups (name, description) VALUES (%s,%s)",
                        (b['name'].strip(), b.get('description', '')))
    write_audit(p['username'], 'create_group', 'group', gid, {'name': b['name']})
    return utils.ok({"id": gid})

@app.put("/api/v1/users/groups/{gid}")
async def update_group(gid: int, request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    row = utils.query("SELECT * FROM user_groups WHERE id=%s", (gid,), one=True)
    if not row:
        raise HTTPException(404, "group not found")
    if b.get('name') and b['name'] != row['name']:
        if utils.query("SELECT id FROM user_groups WHERE name=%s AND id<>%s", (b['name'], gid), one=True):
            raise HTTPException(409, f"用户组 {b['name']} 已存在")
    utils.execute("UPDATE user_groups SET name=%s, description=%s WHERE id=%s",
                  (b.get('name', row['name']), b.get('description', row['description']), gid))
    write_audit(p['username'], 'update_group', 'group', gid, {'name': b.get('name')})
    return utils.ok(message="updated")

@app.delete("/api/v1/users/groups/{gid}")
async def delete_group(gid: int, p=Depends(require_role('admin'))):
    row = utils.query("SELECT * FROM user_groups WHERE id=%s", (gid,), one=True)
    if not row:
        raise HTTPException(404, "group not found")
    members = utils.query("SELECT COUNT(*) c FROM user_group_map WHERE group_id=%s", (gid,), one=True)
    if members and members['c']:
        raise HTTPException(409, f"组内仍有 {members['c']} 名成员，请先移出再删除")
    in_use = utils.query("SELECT COUNT(*) c FROM access_policies WHERE user_or_group_type='group' AND user_or_group_id=%s", (gid,), one=True)
    if in_use and in_use['c']:
        raise HTTPException(409, f"有 {in_use['c']} 条授权策略引用该组，请先调整策略")
    utils.execute("DELETE FROM user_groups WHERE id=%s", (gid,))
    write_audit(p['username'], 'delete_group', 'group', gid, {'name': row['name']})
    return utils.ok(message="deleted")

@app.get("/api/v1/users/groups/{gid}/members")
async def group_members(gid: int, p=Depends(require_role('admin'))):
    rows = utils.query("""SELECT u.id, u.username, u.display_name, u.role, u.is_active
                          FROM user_group_map m JOIN users u ON m.user_id=u.id
                          WHERE m.group_id=%s ORDER BY u.id""", (gid,))
    return utils.ok(rows)

@app.put("/api/v1/users/{uid}")
async def update_user(uid: int, request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    row = utils.query("SELECT * FROM users WHERE id=%s", (uid,), one=True)
    if not row:
        raise HTTPException(404, "user not found")
    sets, args = ["display_name=%s", "role=%s", "is_active=%s"], [
        b.get('display_name', row['display_name']),
        b.get('role', row['role']),
        1 if b.get('is_active', row['is_active']) else 0,
    ]
    if b.get('password'):
        # IM-03: 修改密码同样走强度校验
        pw_err = password_policy_error(b['password'])
        if pw_err:
            raise HTTPException(400, pw_err)
        sets.append("password_hash=%s"); args.append(utils.hash_password(b['password']))
    if b.get('reset_totp'):
        new_secret = pyotp.random_base32()
        sets.append("totp_secret=%s"); args.append(new_secret)
    if 'is_mfa_enabled' in b:
        sets.append("is_mfa_enabled=%s"); args.append(1 if b['is_mfa_enabled'] else 0)
    args.append(uid)
    utils.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=%s", args)
    if 'groups' in b:
        utils.execute("DELETE FROM user_group_map WHERE user_id=%s", (uid,))
        for gid in b['groups']:
            utils.execute("INSERT IGNORE INTO user_group_map (user_id, group_id) VALUES (%s,%s)", (uid, gid))
    write_audit(p['username'], 'update_user', 'user', uid, {'fields': list(b.keys())})
    data = {"totp_secret": new_secret,
            "otpauth_url": pyotp.totp.TOTP(new_secret).provisioning_uri(name=row['username'], issuer_name='NextBastion')
           } if b.get('reset_totp') else None
    return utils.ok(data)

@app.post("/api/v1/users/{uid}/toggle")
async def toggle_user(uid: int, p=Depends(require_role('admin'))):
    row = utils.query("SELECT is_active FROM users WHERE id=%s", (uid,), one=True)
    if not row:
        raise HTTPException(404, "user not found")
    if str(uid) == str(p['sub']):
        raise HTTPException(409, "不能禁用自己的账号")
    utils.execute("UPDATE users SET is_active=%s WHERE id=%s", (0 if row['is_active'] else 1, uid))
    write_audit(p['username'], 'toggle_user', 'user', uid, {'to': 0 if row['is_active'] else 1})
    return utils.ok({"is_active": 0 if row['is_active'] else 1})

@app.delete("/api/v1/users/{uid}")
async def delete_user(uid: int, p=Depends(require_role('admin'))):
    if str(uid) == str(p['sub']):
        raise HTTPException(409, "不能删除自己的账号")
    row = utils.query("SELECT username FROM users WHERE id=%s", (uid,), one=True)
    if not row:
        raise HTTPException(404, "user not found")
    sess = utils.query("SELECT COUNT(*) c FROM sessions WHERE user_id=%s AND status='active'", (uid,), one=True)
    if sess and sess['c']:
        raise HTTPException(409, "该用户存在在线会话，请先断开")
    utils.execute("DELETE FROM user_group_map WHERE user_id=%s", (uid,))
    utils.execute("DELETE FROM users WHERE id=%s", (uid,))
    write_audit(p['username'], 'delete_user', 'user', uid, {'username': row['username']})
    return utils.ok(message="deleted")

# ============================================================
# 3. 资产管理
# ============================================================
@app.get("/api/v1/nodes")
async def nodes(p=Depends(auth)):
    return utils.ok(utils.query("SELECT * FROM asset_nodes ORDER BY sort"))

# ===== 节点管理 CRUD（所属节点管理）=====
@app.post("/api/v1/nodes")
async def node_create(request: Request, p=Depends(require_role('admin'))):
    """新建节点 {name, parent_id}"""
    b = await request.json()
    name = (b.get('name') or '').strip()
    parent_id = b.get('parent_id')
    if not name:
        raise HTTPException(400, "节点名称必填")
    if len(name) > 128:
        raise HTTPException(400, "节点名称过长")
    if parent_id is not None:
        if not utils.query("SELECT id FROM asset_nodes WHERE id=%s", (parent_id,), one=True):
            raise HTTPException(404, "父节点不存在")
    nid = utils.execute("INSERT INTO asset_nodes (parent_id, name) VALUES (%s,%s)", (parent_id, name))
    write_audit(p['username'], 'node_create', 'node', nid, {'name': name, 'parent': parent_id})
    return utils.ok({"id": nid})

@app.put("/api/v1/nodes/{nid}")
async def node_update(nid: int, request: Request, p=Depends(require_role('admin'))):
    """改名 / 移动父节点 {name?, parent_id?}（防环：新父不能是自己或自己的子孙）"""
    row = utils.query("SELECT * FROM asset_nodes WHERE id=%s", (nid,), one=True)
    if not row:
        raise HTTPException(404, "node not found")
    b = await request.json()
    name = (b.get('name') or '').strip() or row['name']
    parent_id = row['parent_id']
    if 'parent_id' in b:
        parent_id = b.get('parent_id')
        if parent_id is not None:
            if parent_id == nid:
                raise HTTPException(400, "父节点不能是自己")
            if not utils.query("SELECT id FROM asset_nodes WHERE id=%s", (parent_id,), one=True):
                raise HTTPException(404, "父节点不存在")
            # 防环：沿新父向上找，若遇到自己则拒绝
            cur, hops = parent_id, 0
            while cur is not None and hops < 100:
                if cur == nid:
                    raise HTTPException(400, "不能移动到自己的子孙节点下")
                nxt = utils.query("SELECT parent_id FROM asset_nodes WHERE id=%s", (cur,), one=True)
                cur = nxt['parent_id'] if nxt else None
                hops += 1
    utils.execute("UPDATE asset_nodes SET name=%s, parent_id=%s WHERE id=%s", (name, parent_id, nid))
    write_audit(p['username'], 'node_update', 'node', nid, {'name': name, 'parent': parent_id})
    return utils.ok(message="updated")

@app.delete("/api/v1/nodes/{nid}")
async def node_delete(nid: int, p=Depends(require_role('admin'))):
    """删除节点：需无子节点且无资产挂着（防孤儿）"""
    row = utils.query("SELECT * FROM asset_nodes WHERE id=%s", (nid,), one=True)
    if not row:
        raise HTTPException(404, "node not found")
    if row.get('name') == '全部资产' or nid == 1:
        raise HTTPException(400, "根节点「全部资产」不可删除")
    if utils.query("SELECT COUNT(*) c FROM asset_nodes WHERE parent_id=%s", (nid,), one=True)['c']:
        raise HTTPException(400, "存在子节点，请先移走或删除子节点")
    if utils.query("SELECT COUNT(*) c FROM assets WHERE node_id=%s", (nid,), one=True)['c']:
        raise HTTPException(400, "节点下仍有资产，请先移走资产")
    utils.execute("DELETE FROM asset_nodes WHERE id=%s", (nid,))
    write_audit(p['username'], 'node_delete', 'node', nid, {'name': row['name']})
    return utils.ok(message="deleted")

# ===== 资产字段选项字典（数据库存储） =====
@app.get("/api/v1/assets/field-options")
async def get_field_options(p=Depends(auth)):
    rows = utils.query("SELECT field_key, opt_value, opt_group FROM field_options "
                       "WHERE enabled=1 ORDER BY sort_no, id")
    d = {"os_type": [], "label": []}
    for r in rows:
        d.setdefault(r["field_key"], []).append({"value": r["opt_value"], "group": r["opt_group"] or ""})
    return utils.ok(d)

@app.post("/api/v1/settings/field-options")
async def manage_field_options(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    act, fk = b.get("action"), b.get("field_key", "")
    val = (b.get("opt_value") or "").strip()
    grp = (b.get("opt_group") or "").strip()
    if fk not in ("os_type", "label"):
        return utils.err(400, "无效字段类型")
    if act == "add":
        if not val:
            return utils.err(400, "选项值不能为空")
        utils.execute("INSERT IGNORE INTO field_options (field_key, opt_value, opt_group, sort_no) "
                      "VALUES (%s,%s,%s,%s)", (fk, val, grp, int(b.get("sort_no") or 99)))
        write_audit(p["username"], "field_option_add", "system", 0,
                    {"field": fk, "value": val, "group": grp})
    elif act == "del":
        utils.execute("DELETE FROM field_options WHERE field_key=%s AND opt_value=%s", (fk, val))
        write_audit(p["username"], "field_option_del", "system", 0, {"field": fk, "value": val})
    else:
        return utils.err(400, "无效操作")
    return utils.ok(None)

@app.get("/api/v1/assets")
async def list_assets(request: Request, p=Depends(auth)):
    q = request.query_params.get('q', '').strip()
    node = request.query_params.get('node', '')
    sql = """SELECT a.id, a.hostname, a.ip, a.os_type, a.protocol, a.ssh_port, a.rdp_port,
             a.status, a.node_id, n.name AS node_name,
             (SELECT acc.username FROM asset_accounts acc WHERE acc.asset_id=a.id AND acc.status='active' LIMIT 1) AS account,
             (SELECT COUNT(*) FROM asset_accounts acc2 WHERE acc2.asset_id=a.id AND acc2.status='active') AS account_count,
             a.labels
             FROM assets a LEFT JOIN asset_nodes n ON a.node_id=n.id WHERE 1=1"""
    args = []
    # IM-02: 普通用户仅可见授权资产（与 /my/assets 同款授权过滤），admin/auditor 全量
    if p['role'] not in ('admin', 'auditor'):
        user = utils.query("SELECT * FROM users WHERE id=%s", (p['sub'],), one=True)
        gids = user_group_ids(user['id'])
        conds = "(p.user_or_group_type='user' AND p.user_or_group_id=%s)"
        args.append(user['id'])
        if gids:
            conds += f" OR (p.user_or_group_type='group' AND p.user_or_group_id IN ({','.join(['%s']*len(gids))}))"
            args += gids
        sql += f""" AND EXISTS (SELECT 1 FROM access_policies p WHERE p.is_enabled=1 AND ({conds})
                    AND ((p.asset_or_node_type='asset' AND p.asset_or_node_id=a.id)
                      OR (p.asset_or_node_type='node' AND p.asset_or_node_id=a.node_id)))"""
    if q:
        # 搜索同时匹配：主机名 / IP / 分组（labels JSON 数组文本）
        sql += " AND (a.hostname LIKE %s OR a.ip LIKE %s OR a.labels LIKE %s)"
        args += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if node:
        sql += " AND a.node_id=%s"
        args.append(node)
    sql += " ORDER BY a.id LIMIT 500"
    return utils.ok(utils.query(sql, args))

@app.post("/api/v1/assets")
async def create_asset(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    import json as _json
    labels = _json.dumps([s.strip() for s in (b.get('labels') or '').split(',') if s.strip()], ensure_ascii=False)
    aid = utils.execute(
        "INSERT INTO assets (node_id, hostname, ip, os_type, ssh_port, rdp_port, protocol, labels) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (b.get('node_id', 1), b['hostname'], b['ip'], b.get('os_type', 'Linux'),
         b.get('ssh_port', 22), b.get('rdp_port', 3389), b.get('protocol', 'ssh'), labels))
    if b.get('password'):
        utils.execute("INSERT INTO asset_accounts (asset_id, username, cred_type, secret_encrypted) VALUES (%s,%s,'password',%s)",
                      (aid, b.get('account', 'root'), utils.encrypt_secret(b['password'])))
    write_audit(p['username'], 'create_asset', 'asset', aid, {'hostname': b['hostname'], 'ip': b['ip']})
    return utils.ok({"id": aid})

@app.put("/api/v1/assets/{aid}")
async def update_asset(aid: int, request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    row = utils.query("SELECT * FROM assets WHERE id=%s", (aid,), one=True)
    if not row:
        raise HTTPException(404, "asset not found")
    import json as _json
    labels = _json.dumps([s.strip() for s in (b.get('labels') or '').split(',') if s.strip()], ensure_ascii=False)
    utils.execute("""UPDATE assets SET node_id=%s, hostname=%s, ip=%s, os_type=%s, protocol=%s,
                     ssh_port=%s, rdp_port=%s, status=%s, labels=%s WHERE id=%s""",
                  (b.get('node_id', row['node_id']), b.get('hostname', row['hostname']),
                   b.get('ip', row['ip']), b.get('os_type', row['os_type']),
                   b.get('protocol', row['protocol']), b.get('ssh_port', row['ssh_port']),
                   b.get('rdp_port', row['rdp_port']), b.get('status', row['status']), labels, aid))
    # 可选：更新托管账号密码
    if b.get('password'):
        acct = b.get('account', 'root')
        exist = utils.query("SELECT id FROM asset_accounts WHERE asset_id=%s AND username=%s", (aid, acct), one=True)
        if exist:
            utils.execute("UPDATE asset_accounts SET secret_encrypted=%s, status='active' WHERE id=%s",
                          (utils.encrypt_secret(b['password']), exist['id']))
        else:
            utils.execute("INSERT INTO asset_accounts (asset_id, username, cred_type, secret_encrypted) VALUES (%s,%s,'password',%s)",
                          (aid, acct, utils.encrypt_secret(b['password'])))
    write_audit(p['username'], 'update_asset', 'asset', aid, {'hostname': b.get('hostname')})
    return utils.ok(message="updated")

@app.delete("/api/v1/assets/{aid}/accounts/{account_id}")
async def remove_account(aid: int, account_id: int, p=Depends(require_role('admin'))):
    """取消托管账号：删除凭据托管记录（历史会话/审计保留；活跃会话不拦截，仅凭据失效影响新连接）"""
    acc = utils.query("SELECT * FROM asset_accounts WHERE id=%s AND asset_id=%s", (account_id, aid), one=True)
    if not acc:
        raise HTTPException(404, "account not found")
    live = utils.query(
        "SELECT COUNT(*) c FROM sessions WHERE asset_id=%s AND account_name=%s AND status='active'",
        (aid, acc['username']), one=True)
    utils.execute("DELETE FROM asset_accounts WHERE id=%s", (account_id,))
    write_audit(p['username'], 'remove_account', 'asset', aid,
                {'account': acc['username'], 'live_sessions': live['c'] if live else 0})
    return utils.ok(message="removed")

@app.delete("/api/v1/assets/{aid}")
async def delete_asset(aid: int, p=Depends(require_role('admin'))):
    row = utils.query("SELECT * FROM assets WHERE id=%s", (aid,), one=True)
    if not row:
        raise HTTPException(404, "asset not found")
    in_use = utils.query("SELECT COUNT(*) c FROM sessions WHERE asset_id=%s AND status='active'", (aid,), one=True)
    if in_use and in_use['c']:
        raise HTTPException(409, "该资产存在在线会话，请先断开")
    utils.execute("DELETE FROM asset_accounts WHERE asset_id=%s", (aid,))
    utils.execute("DELETE FROM assets WHERE id=%s", (aid,))
    write_audit(p['username'], 'delete_asset', 'asset', aid, {'hostname': row['hostname']})
    return utils.ok(message="deleted")

@app.get("/api/v1/assets/{aid}/accounts")
async def asset_accounts(aid: int, p=Depends(auth)):
    # R1: 资产不存在返回 404（语义统一：不存在=404/无权=403/失效=410）
    if not utils.query("SELECT id FROM assets WHERE id=%s", (aid,), one=True):
        raise HTTPException(404, "asset not found")
    # IM-02: 账号清单仅对授权用户/角色开放（admin/auditor 或命中授权策略）
    if p['role'] not in ('admin', 'auditor'):
        user = utils.query("SELECT * FROM users WHERE id=%s", (p['sub'],), one=True)
        if not user or not check_access(user, aid, '*'):
            raise HTTPException(403, "无授权访问该资产")
    rows = utils.query("SELECT id, asset_id, username, cred_type, status FROM asset_accounts WHERE asset_id=%s", (aid,))
    return utils.ok(rows)

# ============================================================
# 4. 授权管理
# ============================================================
@app.get("/api/v1/policies")
async def list_policies(p=Depends(require_role('admin','auditor'))):
    rows = utils.query("""
        SELECT p.*, CASE p.user_or_group_type WHEN 'user' THEN u.username ELSE g.name END AS user_or_group_name,
               CASE p.asset_or_node_type WHEN 'asset' THEN a.hostname ELSE n.name END AS asset_or_node_name,
               f.name AS filter_name
        FROM access_policies p
        LEFT JOIN users u ON p.user_or_group_type='user' AND u.id=p.user_or_group_id
        LEFT JOIN user_groups g ON p.user_or_group_type='group' AND g.id=p.user_or_group_id
        LEFT JOIN assets a ON p.asset_or_node_type='asset' AND a.id=p.asset_or_node_id
        LEFT JOIN asset_nodes n ON p.asset_or_node_type='node' AND n.id=p.asset_or_node_id
        LEFT JOIN command_filters f ON p.command_filter_id=f.id
        ORDER BY p.id""")
    return utils.ok(rows)

@app.post("/api/v1/policies")
async def create_policy(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    pid = utils.execute("""INSERT INTO access_policies
        (name, user_or_group_type, user_or_group_id, asset_or_node_type, asset_or_node_id,
         account_pattern, allowed_periods, command_filter_id, rdp_session_config, valid_until, created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (b['name'], b.get('user_type', 'group'), b['user_id'], b.get('asset_type', 'node'),
         b['asset_id'], b.get('account_pattern', '*'),
         json.dumps(b.get('allowed_periods')), b.get('command_filter_id'),
         json.dumps(b.get('rdp_session_config')), b.get('valid_until') or None, p['username']))
    write_audit(p['username'], 'create_policy', 'policy', pid, {'name': b['name']})
    return utils.ok({"id": pid})

@app.put("/api/v1/policies/{pid}")
async def update_policy(pid: int, request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    row = utils.query("SELECT * FROM access_policies WHERE id=%s", (pid,), one=True)
    if not row:
        raise HTTPException(404, "policy not found")
    utils.execute("""UPDATE access_policies SET name=%s, user_or_group_type=%s, user_or_group_id=%s,
                     asset_or_node_type=%s, asset_or_node_id=%s, account_pattern=%s, allowed_periods=%s,
                     command_filter_id=%s, rdp_session_config=%s, valid_until=%s, is_enabled=%s WHERE id=%s""",
                  (b.get('name', row['name']), b.get('user_type', row['user_or_group_type']),
                   b.get('user_id', row['user_or_group_id']), b.get('asset_type', row['asset_or_node_type']),
                   b.get('asset_id', row['asset_or_node_id']), b.get('account_pattern', row['account_pattern']),
                   json.dumps(b.get('allowed_periods')) if 'allowed_periods' in b else row['allowed_periods'],
                   b.get('command_filter_id', row['command_filter_id']),
                   json.dumps(b.get('rdp_session_config')) if 'rdp_session_config' in b else row['rdp_session_config'],
                   b.get('valid_until') or row['valid_until'], b.get('is_enabled', row['is_enabled']), pid))
    write_audit(p['username'], 'update_policy', 'policy', pid, {'name': b.get('name')})
    # R12: 字段级 diff 审计（before/after 摘要，不含凭据）
    try:
        _diff = {}
        for f_old, f_new, label in [
            (row['name'], b.get('name'), 'name'),
            (row['account_pattern'], b.get('account_pattern'), 'account_pattern'),
            (row['asset_or_node_type'] + ':' + str(row['asset_or_node_id']),
             (b.get('asset_type') or row['asset_or_node_type']) + ':' + str(b.get('asset_id') or row['asset_or_node_id']), 'target'),
            (str(row['is_enabled']), str(b.get('is_enabled', row['is_enabled'])), 'enabled')]:
            if f_new is not None and str(f_old) != str(f_new):
                _diff[label] = {'from': str(f_old)[:60], 'to': str(f_new)[:60]}
        for k in ('sftp', 'clipboard', 'drive', 'watermark'):
            try:
                _old_cfg = json.loads(row['rdp_session_config'] or '{}') or {}
                _new_cfg = json.loads(b.get('rdp_session_config') or '{}') if 'rdp_session_config' in b else _old_cfg
                if str(_old_cfg.get(k)) != str(_new_cfg.get(k)):
                    _diff[f'cap.{k}'] = {'from': _old_cfg.get(k), 'to': _new_cfg.get(k)}
            except Exception:
                pass
        if _diff:
            write_audit(p['username'], 'policy_diff', 'policy', pid, _diff)
    except Exception:
        pass
    return utils.ok(message="updated")

@app.post("/api/v1/policies/{pid}/toggle")
async def toggle_policy(pid: int, p=Depends(require_role('admin'))):
    row = utils.query("SELECT is_enabled FROM access_policies WHERE id=%s", (pid,), one=True)
    if not row:
        raise HTTPException(404, "policy not found")
    utils.execute("UPDATE access_policies SET is_enabled=%s WHERE id=%s", (0 if row['is_enabled'] else 1, pid))
    write_audit(p['username'], 'toggle_policy', 'policy', pid, {'to': 0 if row['is_enabled'] else 1})
    return utils.ok({"is_enabled": 0 if row['is_enabled'] else 1})

@app.delete("/api/v1/policies/{pid}")
async def delete_policy(pid: int, p=Depends(require_role('admin'))):
    row = utils.query("SELECT name FROM access_policies WHERE id=%s", (pid,), one=True)
    if not row:
        raise HTTPException(404, "policy not found")
    utils.execute("DELETE FROM access_policies WHERE id=%s", (pid,))
    write_audit(p['username'], 'delete_policy', 'policy', pid, {'name': row['name']})
    return utils.ok(message="deleted")

@app.get("/api/v1/filters")
async def list_filters(p=Depends(require_role('admin','auditor'))):
    rows = utils.query("SELECT * FROM command_filters ORDER BY id")
    return utils.ok(rows)

# ---------- P0-4：高危规则集 CRUD（按策略差异化生效） ----------
@app.post("/api/v1/filters")
async def create_filter(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    if not (b.get('name') or '').strip():
        raise HTTPException(400, "名称必填")
    rules = b.get('rules', [])
    for r in rules:
        try:
            re.compile(r.get('regex', ''))
        except re.error as e:
            raise HTTPException(400, f"正则无效: {r.get('name','')} ({e})")
    fid = utils.execute("INSERT INTO command_filters (name, rules) VALUES (%s,%s)",
                        (b['name'].strip(), json.dumps(rules, ensure_ascii=False)))
    write_audit(p['username'], 'create_filter', 'filter', fid, {'name': b['name']})
    return utils.ok({"id": fid})

@app.put("/api/v1/filters/{fid}")
async def update_filter(fid: int, request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    row = utils.query("SELECT * FROM command_filters WHERE id=%s", (fid,), one=True)
    if not row:
        raise HTTPException(404, "filter not found")
    rules = b.get('rules', [])
    for r in rules:
        try:
            re.compile(r.get('regex', ''))
        except re.error as e:
            raise HTTPException(400, f"正则无效: {r.get('name','')} ({e})")
    utils.execute("UPDATE command_filters SET name=%s, rules=%s WHERE id=%s",
                  (b.get('name', row['name']), json.dumps(rules, ensure_ascii=False), fid))
    write_audit(p['username'], 'update_filter', 'filter', fid, {})
    return utils.ok(message="updated")

@app.delete("/api/v1/filters/{fid}")
async def delete_filter(fid: int, p=Depends(require_role('admin'))):
    if fid == 1:
        raise HTTPException(409, "默认规则集不可删除")
    in_use = utils.query("SELECT COUNT(*) c FROM access_policies WHERE command_filter_id=%s", (fid,), one=True)
    if in_use and in_use['c']:
        raise HTTPException(409, f"有 {in_use['c']} 条策略引用该规则集")
    utils.execute("DELETE FROM command_filters WHERE id=%s", (fid,))
    return utils.ok(message="deleted")

def get_filter_rules(filter_id):
    """按策略取规则集；无绑定或绑定不存在时回落默认库"""
    if filter_id:
        row = utils.query("SELECT rules FROM command_filters WHERE id=%s", (filter_id,), one=True)
        if row and row['rules']:
            try:
                rules = json.loads(row['rules'])
                if rules:
                    return rules
            except Exception:
                pass
    return DEFAULT_FILTER_RULES

def user_group_ids(user_id: int):
    rows = utils.query("SELECT group_id FROM user_group_map WHERE user_id=%s", (user_id,))
    return [r['group_id'] for r in rows]

def check_access(user: dict, asset_id: int, account: str) -> Optional[dict]:
    """五维授权判定：用户/组 × 资产/节点（含父节点继承） × 账号 × 时段。返回命中的策略或 None"""
    asset = utils.query("SELECT * FROM assets WHERE id=%s", (asset_id,), one=True)
    if not asset:
        return None
    # 资产所在节点及其全部祖先（父节点授权对子节点资产生效）
    node_ids = [asset['node_id']]
    cur = asset['node_id']
    seen = set()
    while cur is not None and cur not in seen:
        seen.add(cur)
        parent = utils.query("SELECT parent_id FROM asset_nodes WHERE id=%s", (cur,), one=True)
        if not parent or parent['parent_id'] is None:
            break
        cur = parent['parent_id']
        node_ids.append(cur)
    gids = user_group_ids(user['id'])
    conds_user = "(user_or_group_type='user' AND user_or_group_id=%s)"
    args = [user['id']]
    if gids:
        conds_user += f" OR (user_or_group_type='group' AND user_or_group_id IN ({','.join(['%s']*len(gids))}))"
        args += gids
    now = datetime.now()
    ph_nodes = ','.join(['%s'] * len(node_ids))
    sql = f"""SELECT * FROM access_policies WHERE is_enabled=1
        AND ({conds_user})
        AND ((asset_or_node_type='asset' AND asset_or_node_id=%s)
             OR (asset_or_node_type='node' AND asset_or_node_id IN ({ph_nodes})))
        AND (valid_until IS NULL OR valid_until > NOW())
        AND (valid_from IS NULL OR valid_from < NOW())"""
    args += [asset_id] + node_ids
    for pol in utils.query(sql, args):
        pat = pol['account_pattern'] or '*'
        if pat != '*' and not re.match(f"^{pat.replace('*', '.*')}$", account or ''):
            continue
        ok_time = True
        try:
            periods = json.loads(pol['allowed_periods']) if pol['allowed_periods'] else []
            if periods:
                ok_time = any(
                    (not p.get('dow') or now.weekday() + 1 in p['dow'])
                    and (not p.get('start') or p['start'] <= now.strftime('%H:%M'))
                    and (not p.get('end') or now.strftime('%H:%M') <= p['end'])
                    for p in periods)
        except Exception:
            ok_time = True
        if ok_time:
            return pol
    return None

def check_access_all(user: dict, asset_id: int, account: str) -> list:
    """返回全部命中的启用策略（能力合并用：任一策略开启的能力即生效）"""
    asset = utils.query("SELECT * FROM assets WHERE id=%s", (asset_id,), one=True)
    if not asset:
        return []
    node_ids = [asset['node_id']]
    cur = asset['node_id']
    seen = set()
    while cur is not None and cur not in seen:
        seen.add(cur)
        parent = utils.query("SELECT parent_id FROM asset_nodes WHERE id=%s", (cur,), one=True)
        if not parent or parent['parent_id'] is None:
            break
        cur = parent['parent_id']
        node_ids.append(cur)
    gids = user_group_ids(user['id'])
    conds_user = "(user_or_group_type='user' AND user_or_group_id=%s)"
    args = [user['id']]
    if gids:
        conds_user += f" OR (user_or_group_type='group' AND user_or_group_id IN ({','.join(['%s']*len(gids))}))"
        args += gids
    now = datetime.now()
    ph_nodes = ','.join(['%s'] * len(node_ids))
    sql = f"""SELECT * FROM access_policies WHERE is_enabled=1
        AND ({conds_user})
        AND ((asset_or_node_type='asset' AND asset_or_node_id=%s)
             OR (asset_or_node_type='node' AND asset_or_node_id IN ({ph_nodes})))
        AND (valid_until IS NULL OR valid_until > NOW())
        AND (valid_from IS NULL OR valid_from < NOW())"""
    args += [asset_id] + node_ids
    out = []
    for pol in utils.query(sql, args):
        pat = pol['account_pattern'] or '*'
        if pat != '*' and not re.match(f"^{pat.replace('*', '.*')}$", account or ''):
            continue
        ok_time = True
        try:
            periods = json.loads(pol['allowed_periods']) if pol['allowed_periods'] else []
            if periods:
                ok_time = any(
                    (not p.get('dow') or now.weekday() + 1 in p['dow'])
                    and (not p.get('start') or p['start'] <= now.strftime('%H:%M'))
                    and (not p.get('end') or now.strftime('%H:%M') <= p['end'])
                    for p in periods)
        except Exception:
            ok_time = True
        if ok_time:
            out.append(pol)
    return out

def merged_session_config(user: dict, asset_id: int, account: str) -> dict:
    """合并全部命中策略的 rdp_session_config（能力并集：任一开启即开）"""
    merged = {}
    for pol in check_access_all(user, asset_id, account):
        try:
            cfg = json.loads(pol.get("rdp_session_config") or "{}") or {}
        except Exception:
            cfg = {}
        for k, v in cfg.items():
            if isinstance(v, bool):
                merged[k] = merged.get(k, False) or v
            else:
                merged.setdefault(k, v)
    return merged

# ============================================================
# 5. 我的资产 / 会话 / 审计
# ============================================================
@app.get("/api/v1/my/assets")
async def my_assets(payload=Depends(auth)):
    user = utils.query("SELECT * FROM users WHERE id=%s", (payload['sub'],), one=True)
    gids = user_group_ids(user['id'])
    conds, args = "(p.user_or_group_type='user' AND p.user_or_group_id=%s)", [user['id']]
    if gids:
        conds += f" OR (p.user_or_group_type='group' AND p.user_or_group_id IN ({','.join(['%s']*len(gids))}))"
        args += gids
    # 节点继承：资产直接节点或其任意祖先节点上的策略都生效（与 check_access 一致）
    sql = f"""SELECT DISTINCT a.id, a.hostname, a.ip, a.os_type, a.protocol, a.labels, n.name AS node_name
              FROM assets a
              JOIN asset_nodes n ON a.node_id=n.id
              WHERE EXISTS (SELECT 1 FROM access_policies p WHERE p.is_enabled=1 AND ({conds})
                            AND ((p.asset_or_node_type='asset' AND p.asset_or_node_id=a.id)
                              OR (p.asset_or_node_type='node' AND p.asset_or_node_id IN (
                                    SELECT n2.id FROM asset_nodes n2
                                    WHERE n2.id=a.node_id
                                       OR n2.id IN (WITH RECURSIVE up(id) AS (
                                             SELECT n1.parent_id FROM asset_nodes n1 WHERE n1.id=a.node_id
                                             UNION ALL
                                             SELECT n3.parent_id FROM asset_nodes n3 JOIN up ON n3.id=up.id WHERE n3.parent_id IS NOT NULL)
                                           SELECT id FROM up)))))
              ORDER BY a.id LIMIT 300"""
    return utils.ok(utils.query(sql, args))

@app.get("/api/v1/sessions/active")
async def active_sessions(p=Depends(require_role('admin','auditor'))):
    rows = utils.query("""SELECT s.id, s.protocol, s.status, s.started_at, s.client_ip, s.is_high_risk,
                          u.username, a.hostname
                          FROM sessions s JOIN users u ON s.user_id=u.id JOIN assets a ON s.asset_id=a.id
                          WHERE s.status='active' ORDER BY s.started_at DESC""")
    return utils.ok(rows)

@app.post("/api/v1/sessions/{sid}/kill")
async def kill_session(sid: str, p=Depends(require_role('admin','auditor'))):
    row = utils.query("SELECT * FROM sessions WHERE id=%s", (sid,), one=True)
    if not row:
        raise HTTPException(404, "session not found")
    utils.execute("UPDATE sessions SET status='killed', ended_at=NOW(), duration_s=TIMESTAMPDIFF(SECOND,started_at,NOW()) WHERE id=%s", (sid,))
    ACTIVE_KILL.add(sid)
    write_audit(p['username'], 'kill_session', 'session', sid, {'asset': row['asset_id']})
    return utils.ok(message=f"session {sid} killed")

@app.get("/api/v1/sessions")
async def history_sessions(request: Request, p=Depends(require_role('admin','auditor'))):
    user = request.query_params.get('user', '')
    proto = request.query_params.get('protocol', '')
    risk = request.query_params.get('risk', '')
    try:
        page = max(1, int(request.query_params.get('page', 1) or 1))
    except ValueError:
        page = 1
    try:
        ps = min(200, max(20, int(request.query_params.get('page_size', 20) or 20)))
    except ValueError:
        ps = 20
    where = """ FROM sessions s JOIN users u ON s.user_id=u.id JOIN assets a ON s.asset_id=a.id WHERE 1=1"""
    args = []
    if user:
        where += " AND u.username LIKE %s"; args.append(f"%{user}%")
    if proto:
        where += " AND s.protocol=%s"; args.append(proto)
    if risk == '1':
        where += " AND s.is_high_risk=1"
    total = utils.query("SELECT COUNT(*) AS n" + where, args, one=True)['n']
    rows = utils.query("""SELECT s.id, s.protocol, s.started_at, s.ended_at, s.duration_s, s.status, s.is_high_risk,
             u.username, a.hostname, (SELECT COUNT(*) FROM command_logs c WHERE c.session_id=s.id) AS cmd_count"""
             + where + " ORDER BY s.started_at DESC LIMIT %s OFFSET %s",
             args + [ps, (page - 1) * ps])
    return utils.ok({"rows": rows, "total": total, "page": page,
                     "pages": max(1, (total + ps - 1) // ps), "page_size": ps})

@app.get("/api/v1/sessions/{sid}/commands")
async def session_commands(sid: str, p=Depends(require_role('admin','auditor'))):
    rows = utils.query("""SELECT c.command_text, c.action, c.matched_rule, c.executed_at, c.risk_level
                          FROM command_logs c WHERE c.session_id=%s ORDER BY c.id""", (sid,))
    return utils.ok(rows)

@app.get("/api/v1/sessions/{sid}/cast")
async def session_cast(sid: str, p=Depends(require_role('admin','auditor'))):
    row = utils.query("SELECT protocol, cast_file_path, video_file_path FROM sessions WHERE id=%s", (sid,), one=True)
    if not row:
        raise HTTPException(404, "session not found")
    # RDP：.mkb guac 录制流（前端 SessionRecording 回放）
    path = row['video_file_path'] if row['protocol'] == 'rdp' else row['cast_file_path']
    if not path or not os.path.exists(path):
        raise HTTPException(404, "recording not found")
    return FileResponse(path, media_type='application/octet-stream', filename=f"{sid}.mkb" if row['protocol'] == 'rdp' else f"{sid}.cast")

@app.get("/api/v1/commands")
async def search_commands(request: Request, p=Depends(require_role('admin','auditor'))):
    q = request.query_params.get('q', '').strip()
    action = request.query_params.get('action', '')
    try:
        page = max(1, int(request.query_params.get('page', 1) or 1))
    except ValueError:
        page = 1
    try:
        ps = min(200, max(20, int(request.query_params.get('page_size', 20) or 20)))
    except ValueError:
        ps = 20
    where = """ FROM command_logs c JOIN users u ON c.user_id=u.id JOIN assets a ON c.asset_id=a.id WHERE 1=1"""
    args = []
    if q:
        # R11: 优先 FULLTEXT（ft_idx 命中时快 10x+），布尔模式语法错误自动回退 LIKE
        try:
            utils.query("SELECT id FROM command_logs WHERE MATCH(command_text) AGAINST(%s IN BOOLEAN MODE) LIMIT 1", (q,))
            where += " AND MATCH(c.command_text) AGAINST(%s IN BOOLEAN MODE)"
        except Exception:
            where += " AND c.command_text LIKE %s"
        args.append(q)
    if action:
        where += " AND c.action=%s"; args.append(action)
    total = utils.query("SELECT COUNT(*) AS n" + where, args, one=True)['n']
    rows = utils.query("""SELECT c.command_text, c.action, c.matched_rule, c.executed_at, u.username, a.hostname"""
             + where + " ORDER BY c.id DESC LIMIT %s OFFSET %s",
             args + [ps, (page - 1) * ps])
    return utils.ok({"rows": rows, "total": total, "page": page,
                     "pages": max(1, (total + ps - 1) // ps), "page_size": ps})

@app.get("/api/v1/dashboard/stats")
async def dashboard_stats(p=Depends(require_role('admin','auditor'))):
    def cnt(sql, args=None):
        r = utils.query(sql, args, one=True)
        return list(r.values())[0] if r else 0
    return utils.ok({
        "assets": cnt("SELECT COUNT(*) c FROM assets"),
        "online_sessions": cnt("SELECT COUNT(*) c FROM sessions WHERE status='active'"),
        "today_commands": cnt("SELECT COUNT(*) c FROM command_logs WHERE DATE(executed_at)=CURDATE()"),
        "high_risk_alerts": cnt("SELECT COUNT(*) c FROM command_logs WHERE action IN ('block','alert') AND DATE(executed_at)=CURDATE()"),
        "users": cnt("SELECT COUNT(*) c FROM users WHERE is_active=1"),
    })

# ============================================================
# 6. RDP token（无状态 JWT，60s 有效，跨 worker 可验证）
# ============================================================
@app.post("/api/v1/rdp/tokens")
async def rdp_token(request: Request, p=Depends(auth)):
    b = await request.json()
    asset_id, account_id = b.get('asset_id'), b.get('account_id')
    user = utils.query("SELECT * FROM users WHERE id=%s", (p['sub'],), one=True)
    asset = utils.query("SELECT * FROM assets WHERE id=%s", (asset_id,), one=True)
    if not asset:
        raise HTTPException(404, "asset not found")
    # ---- account_id=0：临时凭据（ct=ticket，用户自输账密） ----
    temp_login = temp_pass = None
    if account_id == 0:
        entry = _read_temp_ticket(b.get("ct") or "", user['id'], asset_id) if b.get("ct") else None
        if not entry:
            raise HTTPException(401, "临时凭据已失效，请重新输入")
        temp_login, temp_pass = entry["l"], entry["p"]
        acc = {"id": 0, "username": temp_login}
    else:
        acc = utils.query("SELECT * FROM asset_accounts WHERE id=%s AND asset_id=%s", (account_id, asset_id), one=True)
        if not acc:
            raise HTTPException(404, "account not found")
    pol = check_access(user, asset_id, acc['username'])
    if not pol:
        raise HTTPException(403, "无授权访问该资产")
    # R5: RDP 连接前置 TCP 预检——不通时给明确提示（而非黑屏超时）
    if asset.get("protocol") == "rdp":
        import socket as _sock
        try:
            _s = _sock.socket(); _s.settimeout(2.5)
            _s.connect((asset["ip"], asset["rdp_port"] or 3389)); _s.close()
        except Exception:
            raise HTTPException(502, f"目标 {asset['ip']}:{asset['rdp_port'] or 3389} 网络不可达——请联系管理员放行堡垒机到该地址的 RDP 端口")
    import jwt as pyjwt
    from config import JWT_SECRET
    rdp_jti = uuid.uuid4().hex
    # 会话分辨率 = 用户真实屏幕（前端上报），RDP 按此分辨率建立 → 1:1 铺满不缩放
    sw = max(640, min(3840, int(b.get('screen_width') or 1280)))
    sh = max(480, min(2160, int(b.get('screen_height') or 720)))
    payload = {"kind": "rdp", "asset": asset_id, "acct": account_id,
               "uid": user['id'], "jti": rdp_jti,
               "sw": sw, "sh": sh,
               "exp": int(time.time()) + RDP_TOKEN_TTL}
    # 临时凭据内嵌 token（AESGCM 加密，60s 有效期与 token 同生命周期）
    if temp_login is not None:
        payload["tc"] = utils.encrypt_secret(json.dumps({"l": temp_login, "p": temp_pass}, ensure_ascii=False)).hex()
    token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")
    cfg = merged_session_config(user, asset_id, acc['username'])
    return utils.ok({"token": token, "expires_in": RDP_TOKEN_TTL, "rdp_config": cfg})

@app.post("/api/v1/rdp/retoken")
async def rdp_retoken(request: Request, p=Depends(auth)):
    """分辨率切换续签：旧 rdp token（含 tc 临时凭据声明）换新 token（新分辨率）。
    旧 token 的凭据声明直接复用——临时凭据用户无需重输。"""
    b = await request.json()
    old_token = b.get("token") or ""
    import jwt as pyjwt
    from config import JWT_SECRET
    try:
        old = pyjwt.decode(old_token, JWT_SECRET, algorithms=["HS256"])
        if old.get("kind") != "rdp" or int(old.get("uid", 0)) != int(p['sub']):
            raise ValueError("bad token")
    except Exception:
        raise HTTPException(401, "旧 RDP token 无效或已过期")
    sw = max(640, min(3840, int(b.get('screen_width') or old.get("sw") or 1280)))
    sh = max(480, min(2160, int(b.get('screen_height') or old.get("sh") or 720)))
    payload = {"kind": "rdp", "asset": old["asset"], "acct": old.get("acct", 0),
               "uid": old["uid"], "jti": uuid.uuid4().hex,
               "sw": sw, "sh": sh,
               "exp": int(time.time()) + RDP_TOKEN_TTL}
    if old.get("tc"):          # 临时凭据声明原样续签
        payload["tc"] = old["tc"]
    token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return utils.ok({"token": token, "expires_in": RDP_TOKEN_TTL})

@app.websocket("/ws/rdp/{token}")
async def ws_rdp(ws: WebSocket, token: str):
    """RDP 信令通道：JWT 校验（无状态，任意 worker 可验证）"""
    try:
        import jwt as pyjwt
        info = pyjwt.decode(token, __import__('config').JWT_SECRET, algorithms=["HS256"])
        assert info.get('kind') == 'rdp'
    except Exception:
        await ws.close(code=4401, reason="invalid rdp token")
        return
    await ws.accept()
    asset = utils.query("SELECT * FROM assets WHERE id=%s", (info['asset'],), one=True)
    await ws.send_text(json.dumps({
        "type": "info",
        "message": f"RDP 通道已建立（token 校验通过）。目标 {asset['hostname']}({asset['ip']}:{asset['rdp_port']})。"
                   f"V1 图形流由 guacd 网关承载（部署包内置），本 WS 为信令通道。",
        "asset": {"hostname": asset['hostname'], "ip": asset['ip'], "port": asset['rdp_port']}
    }, ensure_ascii=False))
    try:
        while True:
            msg = await ws.receive_text()
            if msg == 'ping':
                await ws.send_text(json.dumps({"type": "pong"}))
            else:
                await ws.send_text(json.dumps({"type": "echo", "data": msg}))
    except WebSocketDisconnect:
        pass

# ============================================================
# 7. SSH Web Terminal（WS + asyncssh）
# ============================================================
def match_filter(cmd: str, rules=None):
    """返回 (action, rule_name)；action ∈ allow/alert/block"""
    rules = rules or DEFAULT_FILTER_RULES
    for r in rules:
        flag = re.IGNORECASE if r.get('icase') else 0
        if re.search(r['regex'], cmd, flag):
            return r['action'], r.get('name', r['regex'])
    return 'allow', ''

# ============================================================
# 临时凭据（资产未托管账号时，用户连接自输账密）
# ticket = 自包含 JWT（凭据 AESGCM 加密内嵌，60s 有效；WS 消费即换新随机 token 防重放）
# 多 worker 安全：无共享内存状态
# ============================================================
TEMP_USED = set()   # 已消费 jti（进程内尽力去重；主防线是 60s 短时效 + jti 随机）

def _make_temp_ticket(uid: int, asset_id: int, login: str, password: str) -> str:
    import jwt as pyjwt
    from config import JWT_SECRET
    body = utils.encrypt_secret(json.dumps({"u": uid, "a": asset_id, "l": login, "p": password}, ensure_ascii=False))
    # 10 分钟有效（用户可能需要翻找密码），一次性消费由 jti 去重保证
    return pyjwt.encode({"kind": "tcred", "data": body.hex(),
                         "jti": uuid.uuid4().hex, "exp": int(time.time()) + 600},
                        JWT_SECRET, algorithm="HS256")

def _read_temp_ticket(ticket: str, uid: int, asset_id: int):
    import jwt as pyjwt
    from config import JWT_SECRET
    try:
        payload = pyjwt.decode(ticket, JWT_SECRET, algorithms=["HS256"])
        if payload.get("kind") != "tcred":
            return None
        body = utils.decrypt_secret(bytes.fromhex(payload["data"]))
        d = json.loads(body)
        if int(d["u"]) != int(uid) or int(d["a"]) != int(asset_id) or payload["jti"] in TEMP_USED:
            return None
        TEMP_USED.add(payload["jti"])
        if len(TEMP_USED) > 5000:
            for j in list(TEMP_USED)[:2500]:
                TEMP_USED.discard(j)
        return d
    except Exception:
        return None

@app.post("/api/v1/temp-cred")
async def issue_temp_cred(request: Request, p=Depends(auth)):
    """签发临时凭据 ticket：body {asset_id, login, password}；10 分钟内一次性使用"""
    b = await request.json()
    asset_id, login, password = b.get("asset_id"), (b.get("login") or "").strip(), b.get("password") or ""
    if not (asset_id and login and password):
        raise HTTPException(400, "asset_id/login/password 必填")
    # R2: 防暴力猜测——同用户 10 分钟内签发 ≥10 次限流 10 分钟（签发时无法验密码，按签发频次限流自动化滥用）
    _key = f"tc:{p['sub']}"
    _now = time.time()
    _fails = [t for t in _TEMP_FAILS.get(_key, []) if _now - t < 600]
    if len(_fails) >= 10:
        raise HTTPException(429, "凭据签发过于频繁，请 10 分钟后再试")
    _fails.append(_now); _TEMP_FAILS[_key] = _fails
    # 授权校验：账号模式必须匹配（否则可绕过账号维度授权）
    user = utils.query("SELECT * FROM users WHERE id=%s", (p['sub'],), one=True)
    pol = check_access(user, asset_id, login)
    if not pol:
        _TEMP_FAILS.pop(_key, None)   # 授权失败不占签发额度（计数已在上方）
        raise HTTPException(403, "无该资产的访问授权（或授权账号模式不匹配）")
    ticket = _make_temp_ticket(user['id'], asset_id, login, password)
    write_audit(user['username'], 'temp_cred', 'asset', asset_id, {'login': login})
    return utils.ok({"ticket": ticket, "expires_in": 600})

_TEMP_FAILS = {}   # uid -> [fail_ts,...]（R2 限流，进程内）

@app.websocket("/ws/terminal/{asset_id}/{account_id}")
async def ws_terminal(ws: WebSocket, asset_id: int, account_id: int, token: str = "", ct: str = ""):
    await ws.accept()
    payload = None
    try:
        payload = utils.decode_token(token)
        if payload.get('kind') != 'access':
            raise ValueError("wrong token kind")
    except Exception:
        await ws.send_text('\r\n\x1b[31m[NextBastion] 认证失败：token 无效，请重新登录\r\n\x1b[0m')
        await ws.close(code=4401)
        return
    user = utils.query("SELECT * FROM users WHERE id=%s", (payload['sub'],), one=True)
    asset = utils.query("SELECT * FROM assets WHERE id=%s", (asset_id,), one=True)
    # ---- account_id=0：用户自输临时凭据（ct=自包含 JWT ticket，60s 一次性） ----
    temp_cred = None
    if account_id == 0:
        entry = _read_temp_ticket(ct, payload['sub'], asset_id) if ct else None
        if not entry:
            await ws.send_text('\r\n\x1b[31m[NextBastion] 临时凭据已失效，请重新输入\r\n\x1b[0m')
            await ws.close(code=4401)
            return
        temp_cred = entry
        # 构造虚拟账号行（不落库）：凭据经内存传递后即刻弃用
        acc = {"id": 0, "asset_id": asset_id, "username": entry["l"],
               "secret_encrypted": utils.encrypt_secret(entry["p"]), "status": "active", "cred_type": "temp"}
    else:
        acc = utils.query("SELECT * FROM asset_accounts WHERE id=%s AND asset_id=%s", (account_id, asset_id), one=True)
    if user and not user['is_active']:
        await ws.send_text('\r\n\x1b[31m[NextBastion] 账号已被禁用\r\n\x1b[0m')
        await ws.close(code=4403)
        return
    if not (user and acc and asset):
        await ws.send_text('\r\n\x1b[31m[NextBastion] 资产或账号不存在\r\n\x1b[0m')
        await ws.close(code=4404)
        return
    # 安全修复（渗透跟进）：资产=堡垒机自身 → 拒绝 SSH 会话（防授权继承链直接 root 堡垒机）
    if (asset.get("ip") or "").strip() in ("127.0.0.1", "localhost", "::1") and user.get("role") != "admin":
        await ws.send_text('\r\n\x1b[31m[NextBastion] 普通用户禁止连接堡垒机自身（如需运维堡垒机请使用管理员账号）\r\n\x1b[0m')
        write_audit(user['username'], 'deny_terminal', 'asset', asset_id, {'reason': 'self-bastion ssh blocked'})
        await ws.close(code=4403)
        return
    pol = check_access(user, asset_id, acc['username'])
    if not pol:
        await ws.send_text(f"\r\n\x1b[31m[NextBastion] 五维授权校验未通过：用户 {user['username']} 无权以 {acc['username']} 访问 {asset['hostname']}\r\n\x1b[0m")
        write_audit(user['username'], 'deny_terminal', 'asset', asset_id, {'reason': 'no policy'})
        await ws.close(code=4403)
        return
    # P0-4：该会话生效的命令过滤规则集（策略绑定优先）
    session_rules = get_filter_rules(pol.get('command_filter_id'))

    # 会话登记 + cast 录像文件（分级目录：<用户名>/<日期>/）
    sid = utils.new_session_id()
    cast_dir = utils.record_subdir(RECORD_DIR, user['username'])
    cast_path = os.path.join(cast_dir, f"{sid}.cast")
    cast_f = open(cast_path, 'w', encoding='utf-8')
    cast_f.write(json.dumps({"version": 2, "width": 120, "height": 32,
                             "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
                             "timestamp": int(time.time())}) + "\n")
    cast_f.flush()
    utils.execute("""INSERT INTO sessions (id, user_id, asset_id, protocol, account_name, client_ip, cast_file_path)
                     VALUES (%s,%s,%s,'ssh',%s,%s,%s)""",
                  (sid, user['id'], asset_id, acc['username'],
                   ws.client.host if ws.client else '-', cast_path))
    try:
        import syslog_fwd
        syslog_fwd.emit("session_open", f"SSH 会话建立: {user['username']} → {asset['hostname']}",
                        {"actor": user['username'], "asset": asset['hostname'], "session": sid})
    except Exception:
        pass

    import asyncssh
    try:
        secret = utils.decrypt_secret(acc['secret_encrypted'])
    except Exception:
        await ws.send_text('\r\n\x1b[31m[NextBastion] 托管凭据解密失败\r\n\x1b[0m')
        await ws.close(code=4500)
        return

    conn = None
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(asset['ip'], port=asset['ssh_port'], username=acc['username'],
                             password=secret, known_hosts=None), timeout=10)
    except Exception as e:
        msg = f"\r\n\x1b[31m[NextBastion] SSH 连接失败: {type(e).__name__}: {e}\r\n\x1b[0m\r\n"
        await ws.send_text(msg)
        cast_f.write(json.dumps([time.time() - int(time.time()), "o", msg]) + "\n")
        cast_f.close()
        utils.execute("UPDATE sessions SET status='closed', ended_at=NOW() WHERE id=%s", (sid,))
        await ws.close()
        return

    await ws.send_text(f"\r\n\x1b[32m[NextBastion] 会话已建立: {user['username']} → {asset['hostname']} ({acc['username']}) · 会话ID {sid} · 全程录像中\r\n\x1b[0m\r\n")

    async def reader(stream):
        """SSH stdout → WS（asyncssh SSHReader 不支持 async-for，用 read() 循环）"""
        while True:
            data = await stream.read(8192)
            if not data:
                break
            text = data if isinstance(data, str) else data.decode('utf-8', 'replace')
            try:
                await ws.send_text(text)
                cast_f.write(json.dumps([round(time.time() - t0, 3), "o", text]) + "\n")
                cast_f.flush()
            except Exception:
                return

    async def pump_ws_to_ssh(stdin_writer):
        """WS → SSH：控制帧（resize）拦截；输入原样透传 + 旁路行缓冲做命令审计与高危阻断
        阻断方式：命中 block 规则时吞掉本次回车（命令永不下发 shell 执行）"""
        line_buf = ''
        while True:
            msg = await ws.receive_text()
            if msg.startswith('{"__nb":'):
                try:
                    ctl = json.loads(msg)
                    if ctl.get('__nb') == 'resize' and process_ref[0]:
                        process_ref[0].change_terminal_size(ctl['rows'], ctl['cols'])
                    continue
                except Exception:
                    continue

            # ---- 旁路解析：重组命令行并审计 ----
            last_action = None
            for ch in msg:
                if ch in ('\r', '\n'):
                    cmdline = line_buf.strip()
                    line_buf = ''
                    if cmdline:
                        action, rule = match_filter(cmdline, session_rules)
                        last_action = action
                        risk = 'high' if action == 'block' else ('mid' if action == 'alert' else 'low')
                        try:
                            utils.execute(
                                "INSERT INTO command_logs (session_id,user_id,asset_id,command_text,matched_rule,action,risk_level) "
                                "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                                (sid, user['id'], asset_id, cmdline, rule, action, risk))
                        except Exception:
                            pass
                        if action == 'block':
                            try:
                                await ws.send_text(f"\r\n\x1b[41;97m[NextBastion] 命令已被高危策略阻断（规则: {rule}）· 已告警管理员\x1b[0m\r\n")
                                utils.execute("UPDATE sessions SET is_high_risk=1 WHERE id=%s", (sid,))
                                asyncio.create_task(notify_alert(cmdline, rule, user['username'], asset['hostname']))
                                import syslog_fwd
                                syslog_fwd.emit("cmd_block", f"命令阻断: {cmdline[:100]}",
                                                {"actor": user['username'], "rule": rule, "session": sid})
                            except Exception:
                                pass
                        elif action == 'alert':
                            try:
                                await ws.send_text(f"\r\n\x1b[43;30m[NextBastion] 该命令命中告警规则（{rule}）· 已放行并通知管理员\x1b[0m\r\n")
                                asyncio.create_task(notify_alert(cmdline, rule, user['username'], asset['hostname']))
                            except Exception:
                                pass
                elif ch in ('\x7f', '\b'):
                    if line_buf:
                        line_buf = line_buf[:-1]
                elif ch in ('\x03', '\x15'):      # Ctrl+C / Ctrl+U 作废当前行
                    line_buf = ''
                elif ch >= ' ' or ch == '\t':
                    line_buf += ch

            # ---- 透传（block 时吞掉回车：命令留在屏幕但不执行） ----
            try:
                out_msg = msg.replace('\r', '').replace('\n', '') if last_action == 'block' else msg
                stdin_writer.write(out_msg)
                await stdin_writer.drain()
            except Exception:
                return

    t0 = time.time()
    process = None
    process_ref = [None]          # pump 循环内可访问（动态 resize）
    reader_task = pump_task = None
    try:
        # asyncssh 交互 shell 高层 API：create_process 返回 SSHClientProcess
        # 初始 100x30；前端 onopen 后立刻上报真实尺寸触发 change_terminal_size
        process = await conn.create_process(term_type='xterm-256color', term_size=(30, 100))
        process_ref[0] = process
        stdin_w = process.stdin
        reader_task = asyncio.create_task(reader(process.stdout))
        pump_task = asyncio.create_task(pump_ws_to_ssh(stdin_w))

        while True:
            await asyncio.sleep(0.5)
            # 强断检测查 DB（跨 worker 生效）
            if sid in ACTIVE_KILL:
                break
            row = utils.query("SELECT status FROM sessions WHERE id=%s", (sid,), one=True)
            if row and row['status'] in ('killed', 'closed'):
                break
            if ws.client_state == WebSocketState.DISCONNECTED:
                break
            if reader_task.done() or pump_task.done():
                if reader_task.done() and reader_task.exception():
                    import traceback; traceback.print_exc(type(reader_task.exception()))
                if pump_task.done() and pump_task.exception():
                    import traceback; traceback.print_exc(type(pump_task.exception()))
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        import traceback; traceback.print_exc()
    finally:
        ACTIVE_KILL.discard(sid)
        for t in (reader_task, pump_task):
            if t:
                try:
                    t.cancel()
                except Exception:
                    pass
        try:
            if process:
                process.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        try:
            cast_f.close()
        except Exception:
            pass
        dur = int(time.time() - t0)
        utils.execute("UPDATE sessions SET status=%s, ended_at=NOW(), duration_s=%s WHERE id=%s",
                      ('killed' if sid in ACTIVE_KILL else 'closed', dur, sid))
        # R9: 会话关闭事件 Syslog（含时长，ELK 可算会话完整性）
        try:
            import syslog_fwd
            syslog_fwd.emit("session_close", f"SSH 会话结束: {user['username']} → {asset['hostname']}（{dur}s）",
                            {"actor": user['username'], "asset": asset['hostname'], "session": sid,
                             "duration_s": dur, "asset_id": asset_id})
        except Exception:
            pass
        try:
            await ws.close()
        except Exception:
            pass

# ============================================================
# 8. 命令拦截钩子（由 pump 逻辑调用 —— V1 简化为行级拦截）
# ============================================================
async def intercept_command(sid: str, user_id: int, asset_id: int, cmdline: str) -> str:
    action, rule = match_filter(cmdline)
    if action != 'allow':
        try:
            utils.execute("INSERT INTO command_logs (session_id,user_id,asset_id,command_text,matched_rule,action,risk_level) "
                          "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                          (sid, user_id, asset_id, cmdline, rule, action,
                           'high' if action == 'block' else 'mid'))
            if action == 'block':
                utils.execute("UPDATE sessions SET is_high_risk=1 WHERE id=%s", (sid,))
        except Exception:
            pass
    return action

# ============================================================
# 9. 健康检查（必须在静态挂载之前注册，否则被 StaticFiles 吞掉）
# ============================================================
@app.get("/api/v1/health")
async def health():
    return utils.ok({"status": "up", "time": datetime.now().isoformat(), "version": "1.0.0"})

# ============================================================
# 12. V1.1 P1 功能（监视/导入/探测/导出/告警）
# ============================================================
from config import RECORD_DIR as _RD

# ---- P1-5 实时屏幕监视：cast 文件 tail 转发（跨 worker 天然支持，文件即状态） ----
@app.get("/api/v1/sessions/{sid}/live")
async def session_live(sid: str, p=Depends(require_role('admin','auditor'))):
    row = utils.query("SELECT s.*, u.username, a.hostname FROM sessions s JOIN users u ON s.user_id=u.id JOIN assets a ON s.asset_id=a.id WHERE s.id=%s", (sid,), one=True)
    if not row or row['status'] != 'active' or not row['cast_file_path'] or not os.path.exists(row['cast_file_path']):
        raise HTTPException(404, "会话不存在或无可监视流")
    size = os.path.getsize(row['cast_file_path'])
    return utils.ok({"sid": sid, "username": row['username'], "hostname": row['hostname'],
                     "protocol": row['protocol'], "cast_size": size})

@app.websocket("/ws/live/{sid}")
async def ws_live(ws: WebSocket, sid: str, token: str = ""):
    """管理员/审计实时观看：cast 文件增量推送（0.5s 轮询文件增长）
    安全修复（渗透⑤）：仅接受 kind=access；SID 与请求者绑定——admin/auditor 可监视任意会话，
    普通 user 只能监视自己开启的会话；同 token 并发监视不限次数但均受上述约束。"""
    try:
        payload = utils.decode_token(token)
        if payload.get('kind') != 'access':
            raise ValueError("wrong token kind")
        assert payload['role'] in ('admin', 'auditor') or True   # 角色放行到 SID 绑定层判定
    except Exception:
        await ws.close(code=4403, reason="forbidden")
        return
    await ws.accept()
    row = utils.query("SELECT * FROM sessions WHERE id=%s", (sid,), one=True)
    # SID 绑定：非 admin/auditor 只能看自己的会话
    if row and payload['role'] not in ('admin', 'auditor') and row['user_id'] != payload['sub']:
        write_audit(payload.get('username', '?'), 'deny_live_watch', 'session', sid, {'reason': 'not owner'})
        await ws.send_text(json.dumps({"type": "nb-error", "message": "仅可监视自己的会话"}))
        await ws.close(code=4403)
        return
    if not row or not row['cast_file_path'] or not os.path.exists(row['cast_file_path']):
        await ws.send_text(json.dumps({"type": "nb-error", "message": "无可监视流"}))
        await ws.close()
        return
    path = row['cast_file_path']
    pos = 0
    try:
        while True:
            sess = utils.query("SELECT status FROM sessions WHERE id=%s", (sid,), one=True)
            if not sess or sess['status'] != 'active':
                await ws.send_text(json.dumps({"type": "nb-end", "message": "会话已结束"}))
                break
            size = os.path.getsize(path)
            if size > pos:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                if chunk:
                    await ws.send_text(json.dumps({"type": "cast", "data": chunk}))
            await asyncio.sleep(0.5)
    except Exception as e:
        import traceback; traceback.print_exc()
    try:
        await ws.close()
    except Exception:
        pass

# ---- P1-6 CSV 批量导入资产 ----
@app.get("/api/v1/assets/import/template")
async def import_template(p=Depends(require_role('admin'))):
    """R10: CSV 导入模板下载"""
    from fastapi.responses import PlainTextResponse
    csv = ("hostname,ip,protocol,os_type,node_name,account,password,ssh_port,rdp_port\n"
           "web-nginx-01,172.18.1.10,ssh,CentOS 7.9,生产区,root,,22,\n"
           "win-jump-02,192.168.30.55,rdp,Windows Server 2022,测试区,administrator,,,\"3389\"\n")
    return PlainTextResponse(csv, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=nb_assets_template.csv"})

@app.post("/api/v1/assets/import")
async def import_assets(request: Request, p=Depends(require_role('admin'))):
    """CSV 格式: hostname,ip,protocol,os_type,node_name,account,password,ssh_port,rdp_port"""
    body = await request.json()
    lines = (body.get('csv') or '').strip().splitlines()
    if not lines:
        raise HTTPException(400, "CSV 内容为空")
    created, errors = 0, []
    nodes = {n['name']: n['id'] for n in utils.query("SELECT id,name FROM asset_nodes")}
    for i, line in enumerate(lines, 1):
        parts = [x.strip() for x in line.split(',')]
        if len(parts) < 2 or not parts[0] or parts[0].lower().startswith('hostname'):
            if i == 1 and parts[0].lower().startswith('hostname'):
                continue
            if len(parts) < 2:
                errors.append(f"第{i}行: 字段不足")
                continue
            errors.append(f"第{i}行: 字段不足")
            continue
        hostname, ip = parts[0], parts[1]
        protocol = parts[2].lower() if len(parts) > 2 and parts[2].lower() in ('ssh', 'rdp') else 'ssh'
        os_type = parts[3] if len(parts) > 3 else ('Windows Server' if protocol == 'rdp' else 'Linux')
        node_id = nodes.get(parts[4], 4) if len(parts) > 4 else 4
        account = parts[5] if len(parts) > 5 else ('administrator' if protocol == 'rdp' else 'root')
        password = parts[6] if len(parts) > 6 else ''
        ssh_port = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 22
        rdp_port = int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 3389
        try:
            aid = utils.execute(
                "INSERT INTO assets (node_id, hostname, ip, os_type, ssh_port, rdp_port, protocol) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (node_id, hostname, ip, os_type, ssh_port, rdp_port, protocol))
            if password:
                utils.execute("INSERT INTO asset_accounts (asset_id, username, cred_type, secret_encrypted) VALUES (%s,%s,'password',%s)",
                              (aid, account, utils.encrypt_secret(password)))
            created += 1
        except Exception as e:
            errors.append(f"第{i}行 {hostname}: {str(e)[:60]}")
    write_audit(p['username'], 'import_assets', 'asset', 0, {'created': created, 'errors': len(errors)})
    return utils.ok({"created": created, "total": len(lines), "errors": errors[:50]})

# ---- P1-7 资产连通性探测 ----
def _probe_throttled(aid: int, window: int = 60) -> bool:
    """跨 worker 节流：以文件 mtime 为共享时钟"""
    import os
    f = f"/tmp/nb_probe_{aid}"
    try:
        if time.time() - os.path.getmtime(f) < window:
            return True
        with open(f, "w") as fh:
            fh.write(str(time.time()))
    except FileNotFoundError:
        with open(f, "w") as fh:
            fh.write(str(time.time()))
    return False

@app.post("/api/v1/assets/{aid}/probe")
async def probe_asset(aid: int, p=Depends(auth)):
    # IM-02: 探测仅对授权用户/角色开放（admin/auditor 或命中授权策略）
    if p['role'] not in ('admin', 'auditor'):
        user = utils.query("SELECT * FROM users WHERE id=%s", (p['sub'],), one=True)
        if not user or not check_access(user, aid, '*'):
            raise HTTPException(403, "无授权探测该资产")
    # I5：60 秒内同资产只探测一次（文件时钟，跨 worker 生效）
    if _probe_throttled(aid):
        row = utils.query("SELECT ip, status FROM assets WHERE id=%s", (aid,), one=True)
        if row:
            return utils.ok({"asset_id": aid, "host": row['ip'], "port": None, "reachable": row['status'] == 'online', "latency_ms": None, "cached": True})
    import socket
    row = utils.query("SELECT * FROM assets WHERE id=%s", (aid,), one=True)
    if not row:
        raise HTTPException(404, "asset not found")
    port = row['rdp_port'] if row['protocol'] == 'rdp' else row['ssh_port']
    result = {"asset_id": aid, "host": row['ip'], "port": port, "reachable": False, "latency_ms": None}
    try:
        t0 = time.time()
        s = socket.create_connection((row['ip'], port), timeout=3)
        result['latency_ms'] = round((time.time() - t0) * 1000)
        s.close()
        result['reachable'] = True
        utils.execute("UPDATE assets SET status='online' WHERE id=%s", (aid,))
    except Exception:
        utils.execute("UPDATE assets SET status='offline' WHERE id=%s", (aid,))
    return utils.ok(result)

# ---- P1-8 审计导出 ----
@app.get("/api/v1/export/{kind}")
async def export_data(kind: str, request: Request, p=Depends(require_role('admin','auditor'))):
    import csv, io
    q = request.query_params.get('q', '')
    buf = io.StringIO()
    w = csv.writer(buf)
    if kind == 'sessions':
        w.writerow(['会话ID', '用户', '资产', '协议', '开始', '结束', '时长s', '状态', '命令数', '高危'])
        for r in utils.query("""SELECT s.id,u.username,a.hostname,s.protocol,s.started_at,s.ended_at,s.duration_s,s.status,
                               (SELECT COUNT(*) FROM command_logs c WHERE c.session_id=s.id) cc, s.is_high_risk
                               FROM sessions s JOIN users u ON s.user_id=u.id JOIN assets a ON s.asset_id=a.id
                               ORDER BY s.started_at DESC LIMIT 5000"""):
            w.writerow([r['id'], r['username'], r['hostname'], r['protocol'], r['started_at'], r['ended_at'], r['duration_s'], r['status'], r['cc'], r['is_high_risk']])
    elif kind == 'commands':
        w.writerow(['时间', '用户', '资产', '命令', '规则', '动作'])
        sql = """SELECT c.executed_at,u.username,a.hostname,c.command_text,c.matched_rule,c.action
                 FROM command_logs c JOIN users u ON c.user_id=u.id JOIN assets a ON c.asset_id=a.id"""
        args = []
        if q:
            sql += " WHERE c.command_text LIKE %s"; args.append(f"%{q}%")
        for r in utils.query(sql + " ORDER BY c.id DESC LIMIT 10000", args):
            w.writerow([r['executed_at'], r['username'], r['hostname'], r['command_text'], r['matched_rule'], r['action']])
    elif kind == 'logins':
        w.writerow(['时间', '用户', '来源IP', '结果', '原因'])
        for r in utils.query("SELECT logged_at,username,client_ip,result,reason FROM login_logs ORDER BY id DESC LIMIT 10000"):
            w.writerow([r['logged_at'], r['username'], r['client_ip'], r['result'], r['reason']])
    else:
        raise HTTPException(404, "unknown kind")
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={kind}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"})

# ---- P1-9 高危告警 Webhook ----
WEBHOOKS_KEY = "webhook_urls"
@app.get("/api/v1/settings/webhook")
async def get_webhook(p=Depends(require_role('admin'))):
    row = utils.query("SELECT detail FROM audit_logs WHERE action='webhook_config' ORDER BY id DESC LIMIT 1", one=True)
    try:
        return utils.ok(json.loads(row['detail']) if row else {"urls": []})
    except Exception:
        return utils.ok({"urls": []})

@app.post("/api/v1/settings/webhook")
async def set_webhook(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    urls = [u.strip() for u in (b.get('urls') or '').splitlines() if u.strip()]
    write_audit(p['username'], 'webhook_config', 'system', 0, {"urls": urls})
    return utils.ok({"urls": urls})

@app.post("/api/v1/settings/webhook/test")
async def test_webhook(request: Request, p=Depends(require_role('admin'))):
    """向已保存（或请求体临时提交）的 webhook 发送测试消息，逐 URL 返回成败与耗时
    安全修复④（SSRF）：仅 http/https + 公网地址；错误信息统一（去差异 oracle）"""
    b = await request.json()
    # 优先用请求体里的（未保存也可测），否则用已保存配置
    urls = [u.strip() for u in (b.get('urls') or '').splitlines() if u.strip()]
    if not urls:
        row = utils.query("SELECT detail FROM audit_logs WHERE action='webhook_config' ORDER BY id DESC LIMIT 1", one=True)
        try:
            urls = (json.loads(row['detail']) or {}).get('urls', []) if row else []
        except Exception:
            urls = []
    if not urls:
        return utils.ok({"results": [], "message": "未配置任何 Webhook 地址"})
    import urllib.request, time as _t, ipaddress, socket as _sock
    from urllib.parse import urlparse

    def _validate_webhook_url(u: str) -> str | None:
        """返回拒绝原因；None=允许。仅 http(s) 且目标为公网。"""
        try:
            pr = urlparse(u)
        except Exception:
            return "URL 格式错误"
        if pr.scheme not in ("http", "https"):
            return f"仅支持 http/https（{pr.scheme or '空'} 协议被拒绝）"
        if not pr.hostname:
            return "URL 缺少主机名"
        try:
            infos = _sock.getaddrinfo(pr.hostname, pr.port or (443 if pr.scheme == 'https' else 80), _sock.AF_UNSPEC, _sock.SOCK_STREAM)
        except Exception:
            return "域名解析失败"
        for ai in infos:
            ip = ipaddress.ip_address(ai[4][0])
            if not ip.is_global:
                return "禁止指向内网/回环/链路本地地址"
        return None

    results = []
    payload = json.dumps({"msgtype": "text", "text": {
        "content": f"[NextBastion] ✅ Webhook 连通性测试\n由 {p['username']} 于 {datetime.now()} 触发\n收到此消息说明高危命令告警通道正常。"}
    }).encode()
    for u in urls:
        t0 = _t.time()
        deny = _validate_webhook_url(u)
        if deny:
            results.append({"url": u, "ok": False, "error": deny, "ms": 0})
            continue
        try:
            req = urllib.request.Request(u, data=payload, headers={"Content-Type": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            code = getattr(resp, 'status', None) or resp.getcode()
            ms = int((_t.time() - t0) * 1000)
            results.append({"url": u, "ok": True, "status": code, "ms": ms})
        except Exception:
            # 安全修复：不回显异常原文（连接差异/端口扫描 oracle）；不暴露精确 ms
            ms = int((_t.time() - t0) * 1000 // 500 * 500)
            results.append({"url": u, "ok": False, "error": "目标不可达或响应异常", "ms": ms})
    ok_n = sum(1 for r in results if r['ok'])
    return utils.ok({"results": results, "message": f"{ok_n}/{len(results)} 个地址测试成功"})

async def notify_alert(cmdline, rule, username, hostname):
    """高危命令实时推送 webhook（钉钉/企微文本格式兼容）+ Syslog（F5）"""
    try:
        import syslog_fwd
        syslog_fwd.emit("high_risk", f"高危命令: {cmdline[:120]}", {"actor": username, "asset": hostname, "rule": rule})
    except Exception:
        pass
    try:
        row = utils.query("SELECT detail FROM audit_logs WHERE action='webhook_config' ORDER BY id DESC LIMIT 1", one=True)
        if not row:
            return
        urls = (json.loads(row['detail']) or {}).get('urls', [])
        import urllib.request
        from urllib.parse import urlparse as _up
        import ipaddress as _ipa, socket as _sk
        payload = json.dumps({"msgtype": "text", "text": {
            "content": f"[NextBastion 高危告警]\n用户: {username}\n资产: {hostname}\n命令: {cmdline[:200]}\n规则: {rule}\n时间: {datetime.now()}"}
        }).encode()
        def _webhook_ok(u):
            try:
                pr=_up(u)
                if pr.scheme not in ("http","https"): return False
                for ai in _sk.getaddrinfo(pr.hostname, pr.port or 80, _sk.AF_UNSPEC, _sk.SOCK_STREAM):
                    if not _ipa.ip_address(ai[4][0]).is_global: return False
                return True
            except Exception:
                return False
        for u in urls:
            if not _webhook_ok(u):
                continue
            try:
                req = urllib.request.Request(u, data=payload, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass
    except Exception:
        pass

# ============================================================
# 12bis. F4 Web SFTP 文件管理（2026-10-14）
# ============================================================
import fileman

@app.post("/api/v1/files/{asset_id}/{account_id}/session")
async def file_session(asset_id: int, account_id: int, request: Request = None, p=Depends(auth)):
    """建立文件管理会话（校验五维授权），返回 fsid；支持临时凭据（account_id=0 + ct ticket）"""
    user = utils.query("SELECT * FROM users WHERE id=%s", (p['sub'],), one=True)
    asset = utils.query("SELECT * FROM assets WHERE id=%s", (asset_id,), one=True)
    if not (user and asset):
        raise HTTPException(404, "asset not found")
    if asset.get("protocol") not in ("ssh", None):
        raise HTTPException(400, "仅支持 SSH 协议资产")
    # ---- account_id=0：临时凭据 ----
    if account_id == 0:
        ct = (request.query_params.get("ct") if request else "") or ""
        body = {}
        try:
            body = await request.json() if request else {}
        except Exception:
            body = {}
        ct = ct or body.get("ct") or ""
        entry = _read_temp_ticket(ct, user['id'], asset_id) if ct else None
        if not entry:
            raise HTTPException(401, "临时凭据已失效，请重新输入")
        acc = {"id": 0, "asset_id": asset_id, "username": entry["l"],
               "secret_encrypted": utils.encrypt_secret(entry["p"]), "status": "active", "cred_type": "temp"}
    else:
        acc = utils.query("SELECT * FROM asset_accounts WHERE id=%s AND asset_id=%s", (account_id, asset_id), one=True)
        if not acc:
            raise HTTPException(404, "account not found")
    try:
        fsid = await fileman.open_session(user, asset, acc)
    except PermissionError as e:
        write_audit(p['username'], 'deny_fileman', 'asset', asset_id,
                    {'reason': str(e) or 'no policy'})
        msg = "无该资产的访问授权" if "not granted" not in str(e) else "该资产的授权策略未开启「文件传输」权限（请联系管理员在授权策略中勾选）"
        # 安全层拒绝（敏感下载/高危上传/堡垒机自身）直接透传原因
        if "禁止" in str(e):
            msg = str(e)
        raise HTTPException(403, msg)
    except asyncio.TimeoutError:
        raise HTTPException(502, "SSH 连接超时")
    except Exception as e:
        raise HTTPException(502, f"SSH 连接失败: {str(e)[:80]}")
    write_audit(p['username'], 'fileman_open', 'asset', asset_id, {'fsid': fsid})
    return utils.ok({"fsid": fsid, "hostname": asset['hostname'], "ip": asset['ip'],
                     "home": fileman.FSESSIONS.get(fsid, {}).get("home", "/")})

@app.post("/api/v1/files/{fsid}/close")
async def file_close(fsid: str, p=Depends(auth)):
    """手动断开文件管理会话（释放 SSH/SFTP 连接）"""
    s = fileman.FSESSIONS.get(fsid)
    if not s:
        return utils.ok(message="session not found (already closed)")
    # 安全校验：仅会话属主或 admin 可断开
    if s["user"]["id"] != p['sub'] and p.get('role') != 'admin':
        raise HTTPException(403, "not your file session")
    fileman.close_session(fsid)
    write_audit(p['username'], 'fileman_close', 'asset', s["asset"]["id"], {'fsid': fsid})
    return utils.ok(message="closed")

@app.get("/api/v1/files/{fsid}/list")
async def file_list(fsid: str, path: str = "/", p=Depends(auth)):
    try:
        return utils.ok(await fileman.list_dir(fsid, path))
    except KeyError:
        raise HTTPException(410, "文件会话已过期，请重新打开")
    except FileNotFoundError:
        raise HTTPException(404, "路径不存在")
    except PermissionError as e:
        write_audit(p['username'], 'deny_list', 'file', path, {'reason': str(e)})
        raise HTTPException(403, str(e))
    except Exception:
        raise HTTPException(500, "列目录失败")

@app.post("/api/v1/files/{fsid}/upload")
async def file_upload(fsid: str, request: Request, p=Depends(auth)):
    """分片上传：?path=&offset=&append=1|0&last=1（last=1 时记一条完整审计，避免分片刷屏）"""
    path = request.query_params.get('path', '')
    offset = int(request.query_params.get('offset', 0) or 0)
    append = request.query_params.get('append', '0') == '1'
    last = request.query_params.get('last', '0') == '1'
    data = await request.body()
    if not path:
        raise HTTPException(400, "missing path")
    try:
        written = await fileman.upload_chunk(fsid, path, offset, data, append)
        if last:
            s = fileman._sess(fsid)
            sf = await fileman._sftp(s)
            st = await sf.stat(path)
            total = getattr(st, "st_size", None) or getattr(st, "size", 0) or written
            fileman.log_transfer(s, "upload", path, total, "ok")
        return utils.ok({"offset": written})
    except KeyError:
        raise HTTPException(410, "文件会话已过期")
    except PermissionError as e:
        write_audit(p['username'], 'deny_upload', 'file', path, {'reason': str(e)})
        raise HTTPException(403, str(e))
    except Exception:
        raise HTTPException(500, "上传失败")

@app.get("/api/v1/files/{fsid}/stat")
async def file_stat(fsid: str, path: str, p=Depends(auth)):
    """R4: 远端文件元信息（断点续传）；敏感路径 403（不给存在性探测面）"""
    try:
        return utils.ok(await fileman.stat_file(fsid, path))
    except KeyError:
        raise HTTPException(410, "文件会话已过期")
    except PermissionError as e:
        write_audit(p['username'], 'deny_stat', 'file', path, {'reason': str(e)})
        raise HTTPException(403, str(e))

@app.get("/api/v1/files/{fsid}/download")
async def file_download(fsid: str, path: str, p=Depends(auth)):
    try:
        r = await fileman.download(fsid, path)
    except KeyError:
        raise HTTPException(410, "文件会话已过期")
    except FileNotFoundError:
        raise HTTPException(404, "文件不存在")
    except PermissionError as e:
        write_audit(p['username'], 'deny_download', 'file', path, {'reason': str(e)})
        raise HTTPException(403, str(e))
    except Exception:
        raise HTTPException(500, "下载失败")
    return StreamingResponse(r["f"], media_type="application/octet-stream",
                             headers={"Content-Disposition":
                                      f"attachment; filename*=UTF-8''{__import__('urllib.parse', fromlist=['quote']).quote(os.path.basename(path))}"})

@app.post("/api/v1/files/{fsid}/op")
async def file_op(fsid: str, request: Request, p=Depends(auth)):
    """rename / delete（删除进回收站）"""
    b = await request.json()
    op = b.get("op")
    try:
        s = fileman._sess(fsid)
        if op == "rename":
            await fileman.rename(fsid, b["old"], b["new"])
        elif op == "delete":
            await fileman.delete(fsid, b["path"])
        else:
            raise HTTPException(400, "unknown op")
        write_audit(p['username'], f'fileman_{op}', 'asset', s["asset"]["id"],
                    {'path': b.get('path') or b.get('old')})
        return utils.ok(message="done")
    except KeyError:
        raise HTTPException(410, "文件会话已过期")
    except PermissionError as e:
        write_audit(p['username'], f'deny_{op}', 'file', str(b.get('path') or b.get('old')), {'reason': str(e)})
        raise HTTPException(403, str(e))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(500, "操作失败")

@app.get("/api/v1/files/transfers")
async def file_transfers(request: Request, p=Depends(require_role('admin', 'auditor'))):
    """文件传输审计（分页 + 筛选）"""
    q = request.query_params.get('q', '').strip()
    direction = request.query_params.get('direction', '').strip()
    page = max(1, int(request.query_params.get('page', 1) or 1))
    size = min(200, max(20, int(request.query_params.get('page_size', 20) or 20)))
    where, args = "1=1", []
    if q:
        where += " AND (t.file_name LIKE %s OR u.username LIKE %s OR a.hostname LIKE %s)"
        args += [f"%{q}%"] * 3
    if direction:
        where += " AND t.direction=%s"
        args.append(direction)
    total = utils.query(f"SELECT COUNT(*) c FROM file_transfer_logs t LEFT JOIN users u ON t.user_id=u.id LEFT JOIN assets a ON t.asset_id=a.id WHERE {where}", args, one=True)['c']
    rows = utils.query(
        f"""SELECT t.id, u.username, a.hostname, t.direction, t.file_name, t.file_size,
            t.result, t.evidence_sha256, t.transferred_at
            FROM file_transfer_logs t LEFT JOIN users u ON t.user_id=u.id LEFT JOIN assets a ON t.asset_id=a.id
            WHERE {where} ORDER BY t.id DESC LIMIT %s OFFSET %s""", args + [size, (page - 1) * size])
    pages = (total + size - 1) // size
    return utils.ok({"rows": rows, "total": total, "page": page, "pages": pages, "page_size": size})

# ============================================================
# 12ter. F5 Syslog 转发（2026-10-14）
# ============================================================
import syslog_fwd

@app.on_event("startup")
async def _start_syslog():
    syslog_fwd.start()

@app.get("/api/v1/settings/syslog")
async def syslog_get(p=Depends(require_role('admin'))):
    return utils.ok(syslog_fwd.get_config())

@app.post("/api/v1/settings/syslog")
async def syslog_set(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    syslog_fwd.save_config(b)
    syslog_fwd.emit("config_change", f"Syslog 配置已更新（enabled={b.get('enabled')}）", {"actor": p['username']})
    # 注意：write_audit 的 action 不能用 syslog_config（该 action 是 syslog_fwd 的配置存储行，会被 get_config 误读）
    write_audit(p['username'], 'syslog_saved', 'system', 0, {'enabled': b.get('enabled'), 'server': b.get('server')})
    return utils.ok(message="saved")

@app.post("/api/v1/settings/syslog/test")
async def syslog_test(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    r = syslog_fwd.test_message(b.get("server", ""), b.get("proto", "tcp"))
    write_audit(p['username'], 'syslog_test', 'system', 0, r)
    return utils.ok(r)

@app.get("/api/v1/settings/syslog/stats")
async def syslog_stats(p=Depends(require_role('admin'))):
    return utils.ok({**syslog_fwd.STATS, "queue": syslog_fwd.Q.qsize()})

# ============================================================
# 12quater. F8 账号盘点（2026-10-14）
# ============================================================
import account_scan as _ascan

@app.post("/api/v1/account-scan/run")
async def account_scan_run(bg: int = 0, p=Depends(require_role('admin'))):
    """手动扫描（bg=1 后台跑，立即返回）；async 上下文里用 to_thread 跑（scan_all 内部用 asyncio.run）"""
    if bg:
        import threading
        threading.Thread(target=_ascan.scan_all, kwargs={"actor": p['username']}, daemon=True).start()
        return utils.ok({"started": True})
    r = await asyncio.to_thread(_ascan.scan_all, **{"actor": p['username']})
    write_audit(p['username'], 'account_scan', 'system', 0,
                {'ok': r['ok'], 'failed': r['failed'], 'high_risk': len(r['high_risk'])})
    return utils.ok(r)

@app.get("/api/v1/account-scan/latest")
async def account_scan_latest(p=Depends(require_role('admin', 'auditor'))):
    row = utils.query("SELECT id, summary, detail, created_by, created_at FROM account_scans ORDER BY id DESC LIMIT 1", one=True)
    if not row:
        return utils.ok(None)
    return utils.ok({"id": row["id"],
                     "summary": json.loads(row["summary"]) if isinstance(row["summary"], str) else row["summary"],
                     "details": json.loads(row["detail"]) if isinstance(row["detail"], str) else row["detail"],
                     "created_by": row["created_by"], "created_at": str(row["created_at"])})

@app.get("/api/v1/account-scan/history")
async def account_scan_history(p=Depends(require_role('admin', 'auditor'))):
    rows = utils.query("SELECT id, summary, created_by, created_at FROM account_scans ORDER BY id DESC LIMIT 20")
    return utils.ok([{"id": r["id"], "created_by": r["created_by"], "created_at": str(r["created_at"]),
                      "summary": json.loads(r["summary"]) if isinstance(r["summary"], str) else r["summary"]} for r in rows])

# ============================================================
# 13. LDAP 目录认证（M1）
# ============================================================
import ldap_auth

# ===== 角色管理（F1~F7：A1+B1+C1 方案）=====
@app.get("/api/v1/role-settings")
async def role_settings_get(p=Depends(require_role('admin'))):
    """默认角色 + LDAP 角色映射（聚合视图）"""
    cfg = ldap_auth.get_config()
    return utils.ok({
        "default_role": cfg.get("default_role") or "user",
        "role_map": ldap_auth.get_role_map(cfg),
        "ldap_enabled": bool(cfg.get("enabled")),
    })

@app.put("/api/v1/role-settings")
async def role_settings_put(request: Request, p=Depends(require_role('admin'))):
    """保存默认角色 + 角色映射（写入 ldap_config；role_map 为 {admin:[dn],auditor:[dn]}）"""
    b = await request.json()
    dr = b.get("default_role")
    if dr not in ("admin", "auditor", "user"):
        raise HTTPException(400, "default_role 必须是 admin/auditor/user")
    rm = b.get("role_map") or {}
    if not isinstance(rm, dict):
        raise HTTPException(400, "role_map 格式错误")
    clean = {}
    for k in ("admin", "auditor"):
        lst = rm.get(k) or []
        if isinstance(lst, str):
            lst = [lst]
        clean[k] = [str(x).strip() for x in lst if str(x).strip()][:20]
    cfg = ldap_auth.get_config()
    # ldap 未启用也可保存（待启用后生效）
    if cfg.get("enabled") or True:
        ldap_auth.save_config({**cfg, "default_role": dr,
                               "role_map": json.dumps(clean, ensure_ascii=False)})
    write_audit(p['username'], 'role_settings', 'system', 0,
                {'default_role': dr, 'role_map': clean})
    return utils.ok(message="saved")

@app.get("/api/v1/role-matrix")
async def role_matrix(p=Depends(auth)):
    """角色权限矩阵（对齐前端 PAGE_ROLES + 后端 require_role/check_access 实际逻辑）
    值语义：True=完全可用 / 'own'=仅自己 / 'policy'=受五维授权约束 / False=无权限"""
    m = [
        # ---- 登录与自助 ----
        {"group": "登录与自助", "page": "登录（密码 + TOTP 双因子）", "admin": True, "auditor": True, "user": True},
        {"group": "登录与自助", "page": "仪表盘（个人统计）", "admin": True, "auditor": True, "user": True},
        {"group": "登录与自助", "page": "修改自己的密码 / 重绑 TOTP", "admin": True, "auditor": True, "user": True},
        # ---- 资产访问 ----
        {"group": "资产访问", "page": "我的资产列表（五维授权过滤）", "admin": "policy", "auditor": False, "user": "policy"},
        {"group": "资产访问", "page": "SSH 终端会话（命令过滤/录像审计）", "admin": "policy", "auditor": False, "user": "policy"},
        {"group": "资产访问", "page": "RDP 远程桌面（guacd 网关）", "admin": "policy", "auditor": False, "user": "policy"},
        {"group": "资产访问", "page": "SFTP 文件管理（上传/下载/重命名）", "admin": "policy", "auditor": False, "user": "policy"},
        {"group": "资产访问", "page": "临时凭据连接（无托管账号资产）", "admin": "policy", "auditor": False, "user": "policy"},
        {"group": "资产访问", "page": "连接堡垒机自身", "admin": True, "auditor": False, "user": False},
        # ---- 资产与节点管理 ----
        {"group": "资产管理", "page": "资产管理（增删改/批量探测/批量删除）", "admin": True, "auditor": False, "user": False},
        {"group": "资产管理", "page": "节点管理（树增删改/移动）", "admin": True, "auditor": False, "user": False},
        {"group": "资产管理", "page": "CSV 批量导入资产", "admin": True, "auditor": False, "user": False},
        {"group": "资产管理", "page": "查看资产列表（只读）", "admin": True, "auditor": False, "user": False},
        # ---- 授权与账号 ----
        {"group": "授权与账号", "page": "授权管理（五维策略增删改）", "admin": True, "auditor": False, "user": False},
        {"group": "授权与账号", "page": "用户管理（增删改/批量角色/重置TOTP）", "admin": True, "auditor": False, "user": False},
        {"group": "授权与账号", "page": "角色管理（默认角色/权限矩阵）", "admin": True, "auditor": False, "user": False},
        {"group": "授权与账号", "page": "账号盘点（资产凭据扫描）", "admin": True, "auditor": True, "user": False},
        # ---- 审计 ----
        {"group": "审计与监控", "page": "在线会话列表 / 强制断开", "admin": True, "auditor": True, "user": False},
        {"group": "审计与监控", "page": "SSH 会话实时监视（asciicast）", "admin": True, "auditor": True, "user": "own"},
        {"group": "审计与监控", "page": "会话回放（全程录像）", "admin": True, "auditor": True, "user": False},
        {"group": "审计与监控", "page": "命令审计（检索/回放定位）", "admin": True, "auditor": True, "user": False},
        {"group": "审计与监控", "page": "文件传输审计（含高危留证副本）", "admin": True, "auditor": True, "user": False},
        {"group": "审计与监控", "page": "登录日志 / 拒绝审计（deny_*）", "admin": True, "auditor": True, "user": False},
        {"group": "审计与监控", "page": "高危规则管理（命令过滤集）", "admin": True, "auditor": False, "user": False},
        # ---- 系统 ----
        {"group": "系统", "page": "系统设置（LDAP 目录认证/角色组映射）", "admin": True, "auditor": False, "user": False},
        {"group": "系统", "page": "Webhook / Syslog 转发配置", "admin": True, "auditor": False, "user": False},
        {"group": "系统", "page": "LDAP 手动全量同步", "admin": True, "auditor": False, "user": False},
        {"group": "系统", "page": "审计日志导出（CSV）", "admin": True, "auditor": True, "user": False},
    ]
    counts = {"admin": 0, "auditor": 0, "user": 0}
    for row in utils.query("SELECT role, COUNT(*) c FROM users GROUP BY role"):
        counts[row["role"]] = row["c"]
    return utils.ok({"matrix": m, "counts": counts})

@app.post("/api/v1/users/batch-role")
async def users_batch_role(request: Request, p=Depends(require_role('admin'))):
    """批量改角色 {ids:[...], role:'admin|auditor|user'}；不可改自己（防最后一个管理员误操作降权）"""
    b = await request.json()
    ids, role = b.get("ids") or [], b.get("role")
    if role not in ("admin", "auditor", "user"):
        raise HTTPException(400, "role 非法")
    if not ids:
        raise HTTPException(400, "ids 为空")
    admins = [r["id"] for r in utils.query("SELECT id FROM users WHERE role='admin' AND is_active=1")]
    try:
        me_id = int(p['sub'])
    except (TypeError, ValueError):
        me_id = -1
    ids = [int(i) for i in ids if str(i).isdigit()]
    if me_id in ids and role != 'admin':
        raise HTTPException(400, "不能修改自己的角色（防误降权锁死）")
    remaining = [a for a in admins if a not in ids]
    if role != 'admin' and not remaining:
        raise HTTPException(400, "系统至少需保留一名激活的管理员")
    for uid in ids:
        utils.execute("UPDATE users SET role=%s WHERE id=%s", (role, uid))
    write_audit(p['username'], 'batch_role', 'user', 0, {'ids': ids, 'role': role})
    return utils.ok(message=f"已更新 {len(ids)} 个用户角色为 {role}")

@app.get("/api/v1/ldap/groups")
async def ldap_groups(request: Request, p=Depends(require_role('admin'))):
    """测试连接拉取 LDAP 组 DN 列表（供角色映射选择；组过滤 objectClass=groupOfNames|posixGroup）"""
    cfg = ldap_auth.get_config()
    from ldap3 import SUBTREE
    try:
        conn = ldap_auth._conn(cfg)
        conn.search(cfg["base_dn"], "(|(objectClass=groupOfNames)(objectClass=posixGroup))",
                    SUBTREE, attributes=["cn"])
        groups = [str(e.entry_dn) for e in conn.entries][:500]
        conn.unbind()
        return utils.ok({"groups": groups, "total": len(groups)})
    except Exception as e:
        raise HTTPException(502, f"LDAP 连接失败: {str(e)[:80]}")

@app.get("/api/v1/settings/ldap")
async def ldap_get(p=Depends(require_role('admin'))):
    return utils.ok(ldap_auth.get_config())

@app.post("/api/v1/settings/ldap")
async def ldap_save(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    # 服务端校验（与前端一致）
    import re as _re
    if not _re.match(r"^ldaps?:\/\/[^:]+:\d+$", b.get("url", "")):
        raise HTTPException(400, "LDAP URL 格式应为 ldaps://host:636 或 ldap://host:389")
    if not b.get("base_dn", "").startswith(("dc=", "ou=", "cn=")):
        raise HTTPException(400, "Base DN 应以 dc=/ou=/cn= 开头")
    if b.get("url", "").startswith("ldap://") and not b.get("starttls"):
        raise HTTPException(400, "ldap:// 389 明文被拒绝：请使用 ldaps:// 或勾选 StartTLS")
    ldap_auth.save_config(b)
    write_audit(p['username'], 'ldap_config', 'system', 0, {'enabled': b.get('enabled')})
    return utils.ok(message="saved")

@app.post("/api/v1/settings/ldap/test")
async def ldap_test(request: Request, p=Depends(require_role('admin'))):
    b = await request.json()
    # 测试时如果没填密码则用已存密码；布尔/0 值不过滤
    stored = ldap_auth.get_config()
    cfg = dict(stored)
    for k, v in b.items():
        if v not in (None, "") or isinstance(v, bool) or isinstance(v, int):
            cfg[k] = v
    if b.get("bind_pw"):
        ldap_auth.save_config({**cfg, "bind_pw": b["bind_pw"]})
    steps = ldap_auth.test_connection(cfg)
    ok_all = all(s[1] for s in steps) and len(steps) >= 4
    write_audit(p['username'], 'ldap_test', 'system', 0, {'ok': ok_all})
    return utils.ok({"ok": ok_all, "steps": [{"name": n, "pass": okk, "detail": d} for n, okk, d in steps]})

@app.post("/api/v1/settings/ldap/sync")
async def ldap_sync_now(p=Depends(require_role('admin'))):
    report = ldap_auth.sync_full(actor=p['username'])
    write_audit(p['username'], 'ldap_sync', 'system', 0,
                {'created': report.get('created'), 'suspended': report.get('suspended')})
    return utils.ok(report)

# ============================================================
# 10. 真实 RDP 图形通道（WS ↔ guacd 桥）
# ============================================================
from guac_bridge import ws_guac_bridge as _ws_guac

@app.websocket("/ws/guac/{token}")
async def ws_guac(ws: WebSocket, token: str):
    await _ws_guac(ws, token)

# ============================================================
# 11. 静态页面（SPA）——挂载放最后，不拦截 /api 与 /ws
# ============================================================
# RDP 活动会话注册表（sid → WebSocket）：同资产新建会话时踢出旧会话（Windows 不支持并发桌面会话）
app.state.guac_live_sockets = {}

WEB_DIR = os.path.join(os.path.dirname(__file__), 'web')
if os.path.isdir(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
