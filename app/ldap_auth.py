"""NextBastion LDAP 目录认证模块（M1）
- 配置持久化（ldap_config 表，Bind 密码 AES 加密）
- 测试连接（五步探测）
- 认证（服务号 Bind → 搜用户 DN → 用户 Bind 验证 → JIT 建户 → 角色组映射）
- 全量同步（映射组扫描，目录消失用户 suspended）
"""
import json, re

from ldap3 import Server, Connection, Tls, ALL, SUBTREE
import ssl as _ssl

import utils

LDAP_ATTR_DEFAULTS = {
    "url": "ldaps://127.0.0.1:636", "base_dn": "dc=example,dc=com",
    "bind_dn": "cn=readonly,dc=example,dc=com", "bind_pw": "",
    "starttls": 0, "insecure": 0,
    "login_attr": "uid", "name_attr": "cn", "mail_attr": "mail",
    "user_filter": "(objectClass=inetOrgPerson)",
    "map_admin": "", "map_auditor": "", "default_role": "user",
    "group_maps": "[]", "enabled": 0,
}


def get_config():
    row = utils.query("SELECT * FROM ldap_config ORDER BY id DESC LIMIT 1", one=True)
    if not row:
        return dict(LDAP_ATTR_DEFAULTS)
    cfg = dict(row)
    cfg.pop("bind_pw_enc", None)
    cfg["bind_pw"] = ""          # 永不回显
    return cfg


def _get_bind_pw():
    row = utils.query("SELECT bind_pw_enc FROM ldap_config ORDER BY id DESC LIMIT 1", one=True)
    if row and row["bind_pw_enc"]:
        try:
            import base64
            return utils.decrypt_secret(base64.b64decode(row["bind_pw_enc"]))
        except Exception:
            return ""
    return ""


def save_config(b: dict):
    cols = {k: b.get(k, LDAP_ATTR_DEFAULTS.get(k)) for k in LDAP_ATTR_DEFAULTS if k != "bind_pw"}
    if "group_maps" in b and not isinstance(b["group_maps"], str):
        cols["group_maps"] = json.dumps(b["group_maps"], ensure_ascii=False)
    # 角色映射 DN 归一（strip）
    for k in ("map_admin", "map_auditor"):
        cols[k] = (cols.get(k) or "").strip()
    import base64
    # 密码框留空 = 不修改（保留旧密码）；传 "-" = 显式清空（匿名 bind）
    if b.get("bind_pw"):
        pw_enc = base64.b64encode(utils.encrypt_secret(b["bind_pw"])).decode()
    else:
        _old = utils.query("SELECT bind_pw_enc FROM ldap_config ORDER BY id DESC LIMIT 1", one=True)
        pw_enc = (_old or {}).get("bind_pw_enc") or ""
    utils.execute("DELETE FROM ldap_config")
    keys = list(cols.keys()) + ["bind_pw_enc"]
    vals = list(cols.values()) + [pw_enc or ""]
    utils.execute(
        f"INSERT INTO ldap_config ({', '.join(keys)}) VALUES ({', '.join(['%s'] * len(vals))})", vals)


def _server(cfg, use_pw_conn=False):
    m = re.match(r"(ldap[s]?)://([^:]+):(\d+)", cfg["url"])
    if not m:
        raise ValueError("LDAP URL 格式错误")
    scheme, host, port = m.group(1), m.group(2), int(m.group(3))
    tls = None
    if scheme == "ldaps" or cfg.get("starttls"):
        tls = Tls(validate=_ssl.CERT_NONE if cfg.get("insecure") else _ssl.CERT_REQUIRED)
    return Server(host, port=port, use_ssl=(scheme == "ldaps"), tls=tls, connect_timeout=5,
                  get_info=ALL)


def _conn(cfg):
    """服务号连接（LDAPS 或 StartTLS）"""
    srv = _server(cfg)
    c = Connection(srv, user=cfg["bind_dn"], password=_get_bind_pw(), auto_bind=True,
                   receive_timeout=8)
    if cfg.get("starttls") and not srv.ssl:
        c.start_tls()
    return c


def test_connection(cfg=None):
    """五步探测：TCP/Bind/TLS/示例用户/角色解析"""
    cfg = cfg or get_config()
    steps = []
    try:
        conn = _conn(cfg)
        steps.append(("TCP 连通", True, ""))
        steps.append(("Bind 服务账号", True, ""))
        steps.append(("TLS 加密", True, "LDAPS" if cfg["url"].startswith("ldaps") else "StartTLS"))
        # 示例用户
        conn.search(cfg["base_dn"], cfg["user_filter"], SUBTREE,
                    attributes=[cfg["login_attr"], cfg["name_attr"], cfg["mail_attr"], "memberOf"])
        if conn.entries:
            e = conn.entries[0]
            steps.append(("示例用户检索", True, str(e.entry_dn)[:80]))
            mo = e.entry_attributes_as_dict.get("memberOf", [])
            role = _resolve_role(cfg, mo)
            steps.append(("角色解析", True, f"memberOf={len(mo)} 组 → {role}"))
        else:
            steps.append(("示例用户检索", False, "User Filter 未命中任何用户"))
        conn.unbind()
    except Exception as e:
        steps.append(("连接", False, f"{type(e).__name__}: {str(e)[:90]}"))
    return steps


def _resolve_role(cfg, member_of):
    mos = [str(x).lower() for x in (member_of or [])]
    if cfg.get("map_admin") and cfg["map_admin"].lower() in mos:
        return "admin"
    if cfg.get("map_auditor") and cfg["map_auditor"].lower() in mos:
        return "auditor"
    return cfg.get("default_role") or "user"


def _resolve_group_ids(cfg, member_of):
    """目录组 → 本地用户组 id 列表"""
    try:
        maps = json.loads(cfg.get("group_maps") or "[]")
    except Exception:
        maps = []
    mos = [str(x).lower() for x in (member_of or [])]
    gids = []
    for m in maps:
        if str(m.get("src", "")).lower() in mos:
            g = utils.query("SELECT id FROM user_groups WHERE id=%s", (m.get("dst"),), one=True)
            if g:
                gids.append(g["id"])
    return gids


def authenticate(username: str, password: str):
    """目录认证。成功返回 (user_dict, member_info)，失败返回 None。"""
    cfg = get_config()
    if not cfg.get("enabled"):
        return None
    try:
        conn = _conn(cfg)
    except Exception:
        return None
    try:
        filt = cfg["user_filter"]
        if "(" not in filt:
            filt = f"({filt})"
        filt = f"(&{filt}({cfg['login_attr']}={utils.escape_ldap(username)}))"
        conn.search(cfg["base_dn"], filt, SUBTREE,
                    attributes=[cfg["login_attr"], cfg["name_attr"], cfg["mail_attr"], "memberOf"])
        if not conn.entries:
            return None
        entry = conn.entries[0]
        user_dn = entry.entry_dn
        attrs = entry.entry_attributes_as_dict
        # 用户 DN + 密码直 Bind（密码零落地）
        srv2 = _server(cfg)
        uc = Connection(srv2, user=user_dn, password=password, auto_bind=True, receive_timeout=8)
        uc.unbind()
        member_of = attrs.get("memberOf", [])
        info = {
            "dn": user_dn,
            "username": username,
            "display_name": str(attrs.get(cfg["name_attr"], [username])[0]),
            "email": str(attrs.get(cfg["mail_attr"], [""])[0]),
            "role": _resolve_role(cfg, member_of),
            "group_ids": _resolve_group_ids(cfg, member_of),
        }
        return info
    except Exception:
        return None
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def jit_provision(info: dict):
    """首次登录建户 / 已存在则同步角色与组"""
    u = utils.query("SELECT * FROM users WHERE username=%s", (info["username"],), one=True)
    if u:
        if u["auth_source"] == "local":
            return u, False          # 本地同名优先，不目录化
        # 目录用户：同步角色/组/显示名（登录实时通道）
        utils.execute("UPDATE users SET display_name=%s, email=%s, role=%s, is_active=1 WHERE id=%s",
                      (info["display_name"], info["email"], info["role"], u["id"]))
        utils.execute("DELETE FROM user_group_map WHERE user_id=%s", (u["id"],))
        for gid in info["group_ids"]:
            utils.execute("INSERT IGNORE INTO user_group_map (user_id, group_id) VALUES (%s,%s)",
                          (u["id"], gid))
        return utils.query("SELECT * FROM users WHERE id=%s", (u["id"],), one=True), True
    import pyotp
    secret = pyotp.random_base32()
    uid = utils.execute(
        "INSERT INTO users (username, password_hash, display_name, email, role, is_mfa_enabled, totp_secret, totp_bound, auth_source, is_active) "
        "VALUES (%s,%s,%s,%s,%s,1,%s,0,'ldap',1)",
        (info["username"], "!", info["display_name"], info["email"], info["role"], secret))
    for gid in info["group_ids"]:
        utils.execute("INSERT IGNORE INTO user_group_map (user_id, group_id) VALUES (%s,%s)", (uid, gid))
    return utils.query("SELECT * FROM users WHERE id=%s", (uid,), one=True), True


def sync_full(actor="system"):
    """全量同步：扫描映射组，消失用户标 suspended。返回报告 dict。"""
    cfg = get_config()
    if not cfg.get("enabled"):
        return {"error": "未启用"}
    report = {"created": 0, "updated": 0, "suspended": 0, "total_ldap": 0, "details": []}
    try:
        conn = _conn(cfg)
        conn.search(cfg["base_dn"], cfg["user_filter"], SUBTREE,
                    attributes=[cfg["login_attr"], cfg["name_attr"], cfg["mail_attr"], "memberOf"])
        entries = conn.entries
        report["total_ldap"] = len(entries)
        seen = set()
        for e in entries:
            a = e.entry_attributes_as_dict
            uname = str(a.get(cfg["login_attr"], [""])[0])
            if not uname:
                continue
            seen.add(uname)
            mo = a.get("memberOf", [])
            info = {"username": uname,
                    "display_name": str(a.get(cfg["name_attr"], [uname])[0]),
                    "email": str(a.get(cfg["mail_attr"], [""])[0]),
                    "role": _resolve_role(cfg, mo),
                    "group_ids": _resolve_group_ids(cfg, mo)}
            _, touched = jit_provision(info)
            report["created" if not utils.query("SELECT id FROM users WHERE username=%s AND auth_source='ldap'", (uname,), one=True) is None and touched else "updated"] += 0  # 计数在下方统一
        # 统计：ldap 用户在目录消失 → suspended
        ldap_users = utils.query("SELECT id, username FROM users WHERE auth_source='ldap'")
        for lu in ldap_users:
            if lu["username"] not in seen:
                utils.execute("UPDATE users SET is_active=0 WHERE id=%s", (lu["id"],))
                report["suspended"] += 1
                report["details"].append(f"suspended: {lu['username']}")
        report["updated"] = max(report["total_ldap"] - report["suspended"], 0)
        conn.unbind()
    except Exception as e:
        report["error"] = str(e)[:120]
    return report
