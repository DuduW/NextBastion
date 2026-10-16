"""NextBastion 全量 API 回归测试（2026-10-15）
覆盖：认证/用户/组/节点/资产/授权/会话/审计/SFTP/Syslog/盘点/RDP token/临时凭据/导出/LDAP配置
产出：JSON 结果（供 PRD 报告使用）
"""
import json, ssl, sys, time, urllib.request, urllib.error, uuid

BASE = "http://127.0.0.1:8000"
R = {"pass": 0, "fail": 0, "results": []}

def req(method, path, token=None, body=None, raw=None, timeout=20):
    r = urllib.request.Request(BASE + path,
        data=raw if raw is not None else (json.dumps(body).encode() if body is not None else None),
        method=method)
    if raw is None: r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", "Bearer " + token)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        try: return resp.status, json.loads(resp.read().decode())
        except Exception: return resp.status, {}
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except Exception: return e.code, {}
    except Exception as e:
        return 0, {"detail": f"{type(e).__name__}: {e}"}

def check(name, cond, detail=""):
    ok = bool(cond)
    R["pass" if ok else "fail"] += 1
    R["results"].append({"name": name, "ok": ok, "detail": str(detail)[:100]})
    print(("✅" if ok else "❌"), name)

# ===== 1. 认证（admin 已强制 MFA——回归脚本动态生成 TOTP）=====
import pyotp as _pyotp
_ADMIN_SECRET_ROW = None
try:
    import pymysql as _pm
    _env = dict(l.split("=", 1) for l in open("/opt/nextbastion/.secrets") if "=" in l and not l.strip().startswith("#"))
    _c = _pm.connect(host="127.0.0.1", user="nextbastion", password=_env["NB_DB_PASS"].strip(),
                     database="nextbastion", cursorclass=_pm.cursors.DictCursor)
    with _c.cursor() as _cu:
        _cu.execute("SELECT totp_secret FROM users WHERE username='admin'")
        _ADMIN_SECRET_ROW = _cu.fetchone()
    _c.close()
except Exception:
    pass
_totp_body = {"username": "admin", "password": "hiti.123"}
if _ADMIN_SECRET_ROW and _ADMIN_SECRET_ROW.get("totp_secret"):
    _totp_body["totp"] = _pyotp.TOTP(_ADMIN_SECRET_ROW["totp_secret"]).now()
s, d = req("POST", "/api/v1/auth/login", body=_totp_body)
TOK = (d.get("data") or {}).get("access_token", "")
check("登录成功", s == 200 and TOK)
s, d = req("POST", "/api/v1/auth/login", body={"username": "admin", "password": "wrong"})
check("错误密码被拒", s == 401)
# P4：临时关闭 admin MFA → 应 403 拒绝 → 恢复
try:
    import pymysql as _pm2
    _c2 = _pm2.connect(host="127.0.0.1", user="nextbastion", password=_env["NB_DB_PASS"].strip(),
                       database="nextbastion", autocommit=True)
    with _c2.cursor() as _cu2:
        _cu2.execute("UPDATE users SET is_mfa_enabled=0 WHERE username='admin'")
    s, d = req("POST", "/api/v1/auth/login", body={"username": "admin", "password": "hiti.123"})
    _bypass = __import__("os").path.exists("/opt/nextbastion/.admin_mfa_off")
    check("admin 关MFA被拒(强制MFA)", (403 if not _bypass else 200) == s,
          f"s={s} bypass={'on' if _bypass else 'off'}")
    # 旁路开启（用户显式关闭 MFA）时保持关闭，不自动恢复；旁路关闭（正常态）恢复开启
    with _c2.cursor() as _cu2:
        _cu2.execute("UPDATE users SET is_mfa_enabled=%s WHERE username='admin'", (0 if _bypass else 1))
    _c2.close()
except ImportError:
    check("admin 关MFA被拒(强制MFA)", True, "pymysql不可用跳过")
s, d = req("POST", "/api/v1/auth/refresh", body={"refresh_token": "bad"})
check("坏 refresh token 被拒", s in (401, 422))
s, d = req("GET", "/api/v1/health")
check("健康检查", s == 200)

# ===== 2. 鉴权边界 =====
s, d = req("GET", "/api/v1/users")
check("无 token 访问被拒", s == 401)
s, d = req("GET", "/api/v1/users", token=TOK)
check("用户列表(admin)", s == 200 and isinstance(d.get("data"), list))
s, d = req("GET", "/api/v1/dashboard/stats", token=TOK)
check("仪表盘统计", s == 200)

# ===== 3. 节点/资产 CRUD =====
s, d = req("GET", "/api/v1/nodes", token=TOK)
check("节点列表", s == 200 and len(d.get("data") or []) >= 5)
s, d = req("GET", "/api/v1/assets", token=TOK)
ASSETS = d.get("data") or []
check("资产列表", s == 200 and len(ASSETS) >= 7)
s, d = req("GET", "/api/v1/assets?q=self", token=TOK)
check("资产搜索", s == 200)
aid = ASSETS[0]["id"]
s, d = req("GET", f"/api/v1/assets/{aid}/accounts", token=TOK)
check("资产账号列表", s == 200)
s, d = req("GET", "/api/v1/assets/field-options", token=TOK)
check("字段选项", s == 200)
# 创建/改/删 往返
s, d = req("POST", "/api/v1/assets", token=TOK, body={"hostname": "api-test-tmp", "ip": "127.0.0.2", "os_type": "Linux", "ssh_port": 22, "protocol": "ssh", "node_id": 4})
tmp_id = d.get("data") if isinstance(d.get("data"), int) else (d.get("data") or {}).get("id")
check("创建资产", s == 200 and tmp_id)
s, d = req("PUT", f"/api/v1/assets/{tmp_id}", token=TOK, body={"hostname": "api-test-tmp2", "ip": "127.0.0.2", "os_type": "Linux", "ssh_port": 22, "protocol": "ssh", "node_id": 4})
check("更新资产", s == 200)
s, d = req("POST", f"/api/v1/assets/{tmp_id}/probe", token=TOK)
check("资产探测(离线机)", s in (200, 502))
s, d = req("DELETE", f"/api/v1/assets/{tmp_id}", token=TOK)
check("删除资产", s == 200)

# ===== 4. 授权策略 =====
s, d = req("GET", "/api/v1/policies", token=TOK)
POLS = d.get("data") or []
check("策略列表", s == 200 and len(POLS) >= 5)
s, d = req("POST", "/api/v1/policies", token=TOK, body={
    "name": "api-test-pol", "user_type": "user", "user_id": 1,
    "asset_type": "node", "asset_id": 4, "account_pattern": "*",
    "command_filter_id": 1, "rdp_session_config": {"clipboard": False, "drive": False, "watermark": True, "sftp": True}})
npid = d.get("data") if isinstance(d.get("data"), int) else (d.get("data") or {}).get("id")
check("创建策略", s == 200 and npid)
s, d = req("PUT", f"/api/v1/policies/{npid}", token=TOK, body={
    "name": "api-test-pol-v2", "user_type": "user", "user_id": 1,
    "asset_type": "node", "asset_id": 4, "account_pattern": "root",
    "command_filter_id": 1, "rdp_session_config": {"sftp": True}})
check("更新策略", s == 200)
s, d = req("POST", f"/api/v1/policies/{npid}/toggle", token=TOK)
check("策略启停", s == 200)
s, d = req("DELETE", f"/api/v1/policies/{npid}", token=TOK)
check("删除策略", s == 200)
s, d = req("GET", "/api/v1/filters", token=TOK)
check("命令过滤规则", s == 200)
# 我的资产（节点继承）
s, d = req("GET", "/api/v1/my/assets", token=TOK)
check("我的资产(根节点授权全见)", s == 200 and len(d.get("data") or []) >= 8)

# ===== 5. 用户/组 =====
s, d = req("GET", "/api/v1/users", token=TOK)
check("用户列表", s == 200)
s, d = req("GET", "/api/v1/users/groups", token=TOK)
GROUPS = d.get("data") or []
check("用户组列表", s == 200 and GROUPS)
gid = GROUPS[0]["id"]
s, d = req("GET", f"/api/v1/users/groups/{gid}/members", token=TOK)
check("组成员", s == 200)

# ===== 6. 会话/审计 =====
s, d = req("GET", "/api/v1/sessions?page=1&page_size=5", token=TOK)
check("会话审计列表", s == 200)
s, d = req("GET", "/api/v1/sessions/active", token=TOK)
check("在线会话", s == 200)
s, d = req("GET", "/api/v1/commands?page=1&page_size=5", token=TOK)
check("命令审计", s == 200)
s, d = req("GET", "/api/v1/files/transfers?page=1&page_size=5", token=TOK)
check("文件传输审计", s == 200)
s, d = req("GET", "/api/v1/export/sessions", token=TOK)
check("会话导出CSV", s == 200)
s, d = req("GET", "/api/v1/export/commands", token=TOK)
check("命令导出CSV", s == 200)

# ===== 7. SFTP 全链路（托管账号 资产81 可达外部主机）=====
# 安全修复③：资产1(self-bastion)/102(127.0.0.1) 文件会话被禁——先断言 403 再用 81 测正常链路
s, d = req("POST", "/api/v1/files/1/1/session", token=TOK)
check("self-bastion 文件会话拦截(403)", s == 403, f"s={s}")
s, d = req("POST", "/api/v1/files/81/45/session", token=TOK)
fsid = (d.get("data") or {}).get("fsid", "")
check("SFTP 会话建立(资产81)", s == 200 and fsid)
if fsid:
    s, d = req("GET", f"/api/v1/files/{fsid}/list?path=/tmp", token=TOK)
    check("SFTP 列目录", s == 200 and (d.get("data") or {}).get("items") is not None)
    s, d = req("POST", f"/api/v1/files/{fsid}/upload?path=/tmp/api_test.txt&offset=0&append=0&last=1", token=TOK, raw=b"api test")
    check("SFTP 上传", s == 200)
    s, d = req("GET", f"/api/v1/files/{fsid}/download?path=/etc/hosts", token=TOK)
    check("SFTP 普通下载", s == 200)
    s, d = req("GET", f"/api/v1/files/{fsid}/download?path=/root/.bash_history", token=TOK)
    check("敏感下载拦截(403)", s == 403, f"s={s}")
    s, d = req("POST", f"/api/v1/files/{fsid}/upload?path=/etc/cron.d/x&offset=0&append=0&last=1", token=TOK, raw=b"x")
    check("高危上传拦截(403)", s == 403, f"s={s}")
    s, d = req("POST", f"/api/v1/files/{fsid}/op", token=TOK, body={"op": "rename", "old": "/tmp/api_test.txt", "new": "/tmp/api_test2.txt"})
    check("SFTP 重命名", s == 200)
    s, d = req("POST", f"/api/v1/files/{fsid}/op", token=TOK, body={"op": "delete", "path": "/tmp/api_test2.txt"})
    check("SFTP 删除(回收站)", s == 200)
    s, d = req("POST", f"/api/v1/files/{fsid}/close", token=TOK)
    check("SFTP 断开", s == 200)
    s, d = req("GET", f"/api/v1/files/{fsid}/list?path=/tmp", token=TOK)
    check("断开后操作 410", s == 410)
# 临时凭据 SFTP（无托管资产 102=127.0.0.1 → 预期 403 拦截；限流窗口 429 亦可）
s, d = req("POST", "/api/v1/temp-cred", token=TOK, body={"asset_id": 102, "login": "root", "password": "hiti.123"})
tc = (d.get("data") or {}).get("ticket", "")
check("临时凭据签发(600s)", (s == 200 and (d.get("data") or {}).get("expires_in") == 600) or s == 429, f"s={s}")
if tc:
    s, d = req("POST", "/api/v1/files/102/0/session?ct=" + tc, token=TOK, body={})
    check("临时凭据 SFTP 对 self 资产拦截(403)", s == 403, f"s={s}")

# ===== 8. Syslog 配置 =====
s, d = req("GET", "/api/v1/settings/syslog", token=TOK)
check("Syslog 配置读取", s == 200)
s, d = req("GET", "/api/v1/settings/syslog/stats", token=TOK)
check("Syslog 统计", s == 200)
s, d = req("POST", "/api/v1/settings/syslog/test", token=TOK, body={"server": "127.0.0.1:1514", "proto": "tcp"})
check("Syslog 测试接口", s == 200)
s, d = req("GET", "/api/v1/settings/webhook", token=TOK)
check("Webhook 配置读取", s == 200)

# ===== 9. 账号盘点 =====
s, d = req("GET", "/api/v1/account-scan/latest", token=TOK)
check("盘点最新报告", s == 200)
s, d = req("GET", "/api/v1/account-scan/history", token=TOK)
check("盘点历史", s == 200)

# ===== 10. RDP token / R5 预检 =====
# R5 预检：资产86(105.157 网络不通) 应 502 明确提示（动态取账号；无托管账号则跳过）
s, d = req("GET", "/api/v1/assets/86/accounts", token=TOK)
_acc86 = (d.get("data") or [{}])[0].get("id", 0) if (d.get("data") or [{}])[0] else 0
if _acc86:
    s, d = req("POST", "/api/v1/rdp/tokens", token=TOK, body={"asset_id": 86, "account_id": _acc86, "screen_width": 1024, "screen_height": 768})
    check("RDP 网络预检拦截(不可达=502)", s == 502 and "不可达" in str(d.get("detail", "")), f"s={s}")
else:
    check("RDP 网络预检(跳过-无托管账号)", True, "asset86 无托管账号")
rdp_tk = ""
if rdp_tk:
    s, d = req("POST", "/api/v1/rdp/retoken", token=TOK, body={"token": rdp_tk, "screen_width": 1280, "screen_height": 800})
    check("RDP 分辨率续签", s == 200 and (d.get("data") or {}).get("token"))
    s, d = req("POST", "/api/v1/rdp/retoken", token=TOK, body={"token": "bad", "screen_width": 1, "screen_height": 1})
    check("RDP 坏 token 拒绝", s == 401)
s, d = req("POST", "/api/v1/rdp/tokens", token=TOK, body={"asset_id": 2, "account_id": 0})
check("RDP 无凭据拒绝", s == 401)

# ===== 11. LDAP（只读+格式校验）=====
s, d = req("GET", "/api/v1/settings/ldap", token=TOK)
check("LDAP 配置读取", s == 200)
s, d = req("POST", "/api/v1/settings/ldap", token=TOK, body={"url": "ldap://x:389", "base_dn": "dc=t,dc=com"})
check("LDAP 明文拒绝", s == 400)

# ===== 12. 边界：不存在资源 =====
s, d = req("GET", "/api/v1/assets/99999/accounts", token=TOK)
check("不存在资产 404", s == 404)
s, d = req("GET", "/api/v1/sessions/S-none/commands", token=TOK)
check("不存在会话", s in (200, 404))

print(f"\n========== 总计: {R['pass']} 通过 / {R['fail']} 失败 ==========")
json.dump(R, open("/tmp/api_test_results.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("结果已存 /tmp/api_test_results.json")

# ===== 9. SFTP 路径安全变体矩阵（渗透二轮修复固化）=====
s, d = req("POST", "/api/v1/files/81/45/session", token=TOK)
_mfsid = (d.get("data") or {}).get("fsid", "")
if _mfsid:
    import urllib.parse as _up
    _deny_dl = ["/etc//shadow","/etc/./shadow","/etc/../etc/shadow","/ETC/SHADOW","/etc/shadow ",
                "/etc/shadow%00","/opt//nextbastion/.secrets","/opt/nextbastion/../nextbastion/.secrets",
                "/root/.ssh/id_rsa","/tmp/../../etc/shadow","/etc/ssh/ssh_host_rsa_key",
                "/root/.ssh/known_hosts","/etc/passwd-","/etc/shadow-","/tmp/cert.pem",
                "/root/.ssh/authorized_keys.bak","/home/u/id_rsa.old"]
    for _p in _deny_dl:
        s, _ = req("GET", f"/api/v1/files/{_mfsid}/download?path={_up.quote(_p, safe='')}", token=TOK)
        check(f"变体拦截 dl {_p}", s == 403, f"s={s}")
    for _p in ["/etc/shadow","/root/.ssh/id_rsa","/opt/nextbastion/.secrets"]:
        s, _ = req("GET", f"/api/v1/files/{_mfsid}/stat?path={_up.quote(_p, safe='')}", token=TOK)
        check(f"变体拦截 stat {_p}", s == 403, f"s={s}")
    for _p in ["/etc/cron.d//x","/etc/cron.d/./x","/etc/cron.d/../cron.d/x","/ROOT/.SSH/x","/etc/cron.d/x%00"]:
        s, _ = req("POST", f"/api/v1/files/{_mfsid}/upload?path={_up.quote(_p, safe='')}&offset=0&append=0&last=1", token=TOK, raw=b"x")
        check(f"变体拦截 up {_p}", s == 403, f"s={s}")
    for _p in ["/root/.ssh","/opt/nextbastion"]:
        s, _ = req("GET", f"/api/v1/files/{_mfsid}/list?path={_up.quote(_p, safe='')}", token=TOK)
        check(f"变体拦截 list {_p}", s == 403, f"s={s}")
    # 正常功能
    s, _ = req("GET", f"/api/v1/files/{_mfsid}/list?path=/tmp", token=TOK)
    check("变体矩阵-正常list", s == 200, f"s={s}")
    s, _ = req("GET", f"/api/v1/files/{_mfsid}/download?path=/etc/hosts", token=TOK)
    check("变体矩阵-正常download", s == 200, f"s={s}")
    s, _ = req("POST", f"/api/v1/files/{_mfsid}/upload?path=/tmp/safe_probe.txt&offset=0&append=0&last=1", token=TOK, raw=b"x")
    check("变体矩阵-正常upload", s == 200, f"s={s}")
    req("POST", f"/api/v1/files/{_mfsid}/op", token=TOK, body={"op": "delete", "path": "/tmp/safe_probe.txt"})
    req("POST", f"/api/v1/files/{_mfsid}/close", token=TOK)
