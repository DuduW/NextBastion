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
    except Exception as e:
        return JSONResponse(utils.err(500, f"internal error: {e}"), status_code=500)

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
    return request.client.host if request.client else 'unknown'

def write_login_log(username, ip, result, reason=''):
    try:
        utils.execute("INSERT INTO login_logs (username, client_ip, result, reason) VALUES (%s,%s,%s,%s)",
                      (username, ip, result, reason))
    except Exception:
        pass

def write_audit(actor, action, target_type='', target_id='', detail=None):
    try:
        utils.execute("INSERT INTO audit_logs (actor, action, target_type, target_id, detail) VALUES (%s,%s,%s,%s,%s)",
                      (actor, action, target_type, str(target_id), json.dumps(detail or {}, ensure_ascii=False)))
    except Exception:
        pass

# ============================================================
# 1. 认证 API
# ============================================================
@app.post("/api/v1/auth/login")
async def login(request: Request):
    body = await request.json()
    username, password, totp = body.get('username'), body.get('password'), body.get('totp', '')
    ip = client_ip(request)
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
        # I1：TOTP 防重放——同时间片二次使用拒绝
        used = utils.query("SELECT detail FROM audit_logs WHERE actor=%s AND action='totp_used' ORDER BY id DESC LIMIT 1", (username,), one=True)
        try:
            last_ts = int(json.loads(used['detail'])['ts']) if used else 0
        except Exception:
            last_ts = 0
        now_ts = int(time.time()) // 30
        if now_ts == last_ts:
            write_login_log(username, ip, 'fail', 'totp replay')
            raise HTTPException(401, "动态口令已使用，请等待下一码")
        utils.execute("INSERT INTO audit_logs (actor, action, detail) VALUES (%s,'totp_used',%s)",
                      (username, json.dumps({"ts": now_ts})))
    utils.execute("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=%s", (u['id'],))
    write_login_log(username, ip, 'success')
    return utils.ok({
        "access_token": utils.make_token(u['id'], u['username'], u['role']),
        "refresh_token": utils.make_token(u['id'], u['username'], u['role'], kind='refresh'),
        "user": {"id": u['id'], "username": u['username'], "role": u['role'], "display_name": u['display_name']}
    })

@app.post("/api/v1/auth/refresh")
async def refresh(request: Request):
    body = await request.json()
    try:
        payload = utils.decode_token(body.get('refresh_token', ''))
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
    secret = pyotp.random_base32()
    uid = utils.execute(
        "INSERT INTO users (username, password_hash, totp_secret, display_name, role, is_mfa_enabled) VALUES (%s,%s,%s,%s,%s,%s)",
        (b['username'], utils.hash_password(b.get('password', 'ChangeMe@2026')), secret,
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
    """五维授权判定：用户/组 × 资产/节点 × 账号 × 时段。返回命中的策略或 None"""
    asset = utils.query("SELECT * FROM assets WHERE id=%s", (asset_id,), one=True)
    if not asset:
        return None
    gids = user_group_ids(user['id'])
    conds_user = "(user_or_group_type='user' AND user_or_group_id=%s)"
    args = [user['id']]
    if gids:
        conds_user += f" OR (user_or_group_type='group' AND user_or_group_id IN ({','.join(['%s']*len(gids))}))"
        args += gids
    now = datetime.now()
    sql = f"""SELECT * FROM access_policies WHERE is_enabled=1
        AND ({conds_user})
        AND ((asset_or_node_type='asset' AND asset_or_node_id=%s)
             OR (asset_or_node_type='node' AND asset_or_node_id=%s))
        AND (valid_until IS NULL OR valid_until > NOW())
        AND (valid_from IS NULL OR valid_from < NOW())"""
    args += [asset_id, asset['node_id']]
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
    sql = f"""SELECT DISTINCT a.id, a.hostname, a.ip, a.os_type, a.protocol, a.labels, n.name AS node_name
              FROM assets a
              JOIN asset_nodes n ON a.node_id=n.id
              WHERE EXISTS (SELECT 1 FROM access_policies p WHERE p.is_enabled=1 AND ({conds})
                            AND ((p.asset_or_node_type='asset' AND p.asset_or_node_id=a.id)
                              OR (p.asset_or_node_type='node' AND p.asset_or_node_id=a.node_id)))
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
        where += " AND c.command_text LIKE %s"; args.append(f"%{q}%")
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
    acc = utils.query("SELECT * FROM asset_accounts WHERE id=%s AND asset_id=%s", (account_id, asset_id), one=True)
    if not acc:
        raise HTTPException(404, "account not found")
    pol = check_access(user, asset_id, acc['username'])
    if not pol:
        raise HTTPException(403, "无授权访问该资产")
    import jwt as pyjwt
    from config import JWT_SECRET
    rdp_jti = uuid.uuid4().hex
    # 会话分辨率 = 用户真实屏幕（前端上报），RDP 按此分辨率建立 → 1:1 铺满不缩放
    sw = max(640, min(3840, int(b.get('screen_width') or 1280)))
    sh = max(480, min(2160, int(b.get('screen_height') or 720)))
    token = pyjwt.encode({"kind": "rdp", "asset": asset_id, "acct": account_id,
                          "uid": user['id'], "jti": rdp_jti,
                          "sw": sw, "sh": sh,
                          "exp": int(time.time()) + RDP_TOKEN_TTL},
                         JWT_SECRET, algorithm="HS256")
    cfg = {}
    try:
        cfg = json.loads(pol['rdp_session_config']) if pol['rdp_session_config'] else {}
    except Exception:
        pass
    return utils.ok({"token": token, "expires_in": RDP_TOKEN_TTL, "rdp_config": cfg})

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

@app.websocket("/ws/terminal/{asset_id}/{account_id}")
async def ws_terminal(ws: WebSocket, asset_id: int, account_id: int, token: str = ""):
    await ws.accept()
    payload = None
    try:
        payload = utils.decode_token(token)
    except Exception:
        await ws.send_text('\r\n\x1b[31m[NextBastion] 认证失败：token 无效，请重新登录\r\n\x1b[0m')
        await ws.close(code=4401)
        return
    user = utils.query("SELECT * FROM users WHERE id=%s", (payload['sub'],), one=True)
    acc = utils.query("SELECT * FROM asset_accounts WHERE id=%s AND asset_id=%s", (account_id, asset_id), one=True)
    asset = utils.query("SELECT * FROM assets WHERE id=%s", (asset_id,), one=True)
    if user and not user['is_active']:
        await ws.send_text('\r\n\x1b[31m[NextBastion] 账号已被禁用\r\n\x1b[0m')
        await ws.close(code=4403)
        return
    if not (user and acc and asset):
        await ws.send_text('\r\n\x1b[31m[NextBastion] 资产或账号不存在\r\n\x1b[0m')
        await ws.close(code=4404)
        return
    pol = check_access(user, asset_id, acc['username'])
    if not pol:
        await ws.send_text(f"\r\n\x1b[31m[NextBastion] 五维授权校验未通过：用户 {user['username']} 无权以 {acc['username']} 访问 {asset['hostname']}\r\n\x1b[0m")
        write_audit(user['username'], 'deny_terminal', 'asset', asset_id, {'reason': 'no policy'})
        await ws.close(code=4403)
        return
    # P0-4：该会话生效的命令过滤规则集（策略绑定优先）
    session_rules = get_filter_rules(pol.get('command_filter_id'))

    # 会话登记 + cast 录像文件
    sid = utils.new_session_id()
    os.makedirs(RECORD_DIR, exist_ok=True)
    cast_path = os.path.join(RECORD_DIR, f"{sid}.cast")
    cast_f = open(cast_path, 'w', encoding='utf-8')
    cast_f.write(json.dumps({"version": 2, "width": 120, "height": 32,
                             "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
                             "timestamp": int(time.time())}) + "\n")
    cast_f.flush()
    utils.execute("""INSERT INTO sessions (id, user_id, asset_id, protocol, account_name, client_ip, cast_file_path)
                     VALUES (%s,%s,%s,'ssh',%s,%s,%s)""",
                  (sid, user['id'], asset_id, acc['username'],
                   ws.client.host if ws.client else '-', cast_path))

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
    """管理员实时观看：cast 文件增量推送（0.5s 轮询文件增长）"""
    try:
        payload = utils.decode_token(token)
        assert payload['role'] in ('admin', 'auditor')
    except Exception:
        await ws.close(code=4403, reason="forbidden")
        return
    await ws.accept()
    row = utils.query("SELECT * FROM sessions WHERE id=%s", (sid,), one=True)
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
    """向已保存（或请求体临时提交）的 webhook 发送测试消息，逐 URL 返回成败与耗时"""
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
    import urllib.request, time as _t
    results = []
    payload = json.dumps({"msgtype": "text", "text": {
        "content": f"[NextBastion] ✅ Webhook 连通性测试\n由 {p['username']} 于 {datetime.now()} 触发\n收到此消息说明高危命令告警通道正常。"}
    }).encode()
    for u in urls:
        t0 = _t.time()
        try:
            req = urllib.request.Request(u, data=payload, headers={"Content-Type": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            code = getattr(resp, 'status', None) or resp.getcode()
            ms = int((_t.time() - t0) * 1000)
            results.append({"url": u, "ok": True, "status": code, "ms": ms})
        except Exception as e:
            ms = int((_t.time() - t0) * 1000)
            results.append({"url": u, "ok": False, "error": str(e)[:120], "ms": ms})
    ok_n = sum(1 for r in results if r['ok'])
    return utils.ok({"results": results, "message": f"{ok_n}/{len(results)} 个地址测试成功"})

async def notify_alert(cmdline, rule, username, hostname):
    """高危命令实时推送 webhook（钉钉/企微文本格式兼容）"""
    try:
        row = utils.query("SELECT detail FROM audit_logs WHERE action='webhook_config' ORDER BY id DESC LIMIT 1", one=True)
        if not row:
            return
        urls = (json.loads(row['detail']) or {}).get('urls', [])
        import urllib.request
        payload = json.dumps({"msgtype": "text", "text": {
            "content": f"[NextBastion 高危告警]\n用户: {username}\n资产: {hostname}\n命令: {cmdline[:200]}\n规则: {rule}\n时间: {datetime.now()}"}
        }).encode()
        for u in urls:
            try:
                req = urllib.request.Request(u, data=payload, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass
    except Exception:
        pass

# ============================================================
# 13. LDAP 目录认证（M1）
# ============================================================
import ldap_auth

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
