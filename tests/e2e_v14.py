import json, urllib.request, urllib.error, pymysql

BASE = "http://127.0.0.1:8000"

def req(method, path, token=None, body=None):
    r = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        resp = urllib.request.urlopen(r, timeout=20)
        return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}

env = dict(l.split("=", 1) for l in open("/opt/nextbastion/.secrets") if "=" in l and not l.strip().startswith("#"))
dbc = pymysql.connect(host="127.0.0.1", user="nextbastion", password=env["NB_DB_PASS"].strip(),
                      database="nextbastion", cursorclass=pymysql.cursors.DictCursor, autocommit=True)
cu = dbc.cursor()
cu.execute("SELECT totp_secret FROM users WHERE username='admin'")
import pyotp
code = pyotp.TOTP(cu.fetchone()["totp_secret"]).now()
import time
time.sleep(0.2)
s, d = req("POST", "/api/v1/auth/login", body={"username": "admin", "password": "hiti.123", "totp": code})
TOK = d["data"]["access_token"]
print("登录:", s)

# 1) 建 MySQL 资产（指向本机 MySQL，账号 nextbastion 只读用）
s, d = req("POST", "/api/v1/assets", token=TOK, body={
    "hostname": "db-local-test", "ip": "127.0.0.1", "os_type": "MySQL", "protocol": "ssh",
    "ssh_port": 3306, "node_id": 1, "device_type": "mysql",
    "account": "nextbastion", "password": env["NB_DB_PASS"].strip(), "initial_db": "nextbastion"})
print("建 MySQL 资产:", s, d.get("data", {}).get("id"))
AID = d["data"]["id"]
s, d = req("GET", f"/api/v1/assets/{AID}/accounts", token=TOK)
ACCID = d["data"][0]["id"]
print("托管账号:", ACCID)

# 2) 能力开关策略：先关 sql 测 403，再开
cu.execute("SELECT id FROM access_policies WHERE user_or_group_id=1 AND user_or_group_type='user' AND asset_or_node_type='node' AND is_enabled=1 LIMIT 1")
pid = cu.fetchone()["id"]
cu.execute("SELECT rdp_session_config FROM access_policies WHERE id=%s", (pid,))
_cfg0 = json.loads(cu.fetchone()["rdp_session_config"] or "{}")
_cfg0.pop("sql", None)
cu.execute("UPDATE access_policies SET rdp_session_config=%s WHERE id=%s", (json.dumps(_cfg0), pid))
s, d = req("POST", f"/api/v1/sql/{AID}/{ACCID}/session", token=TOK)
print("未开 sql 能力开会话:", s, str(d.get("detail", ""))[:50], "(预期 403)")
# 3) 开 sql 能力
cu.execute("UPDATE access_policies SET rdp_session_config=%s WHERE id=%s", (json.dumps({**_cfg0, "sql": True}), pid))
# 4) 策略 rdp_session_config 开 sql 能力
cu.execute("SELECT rdp_session_config FROM access_policies WHERE id=%s", (pid,))
cur_cfg = cu.fetchone()["rdp_session_config"] or "{}"
cfg = json.loads(cur_cfg)
cfg["sql"] = True
cu.execute("UPDATE access_policies SET rdp_session_config=%s WHERE id=%s", (json.dumps(cfg), pid))

# 5) 开 SQL 会话（预期 read_only=True——allow_sql_write=0）
s, d = req("POST", f"/api/v1/sql/{AID}/{ACCID}/session", token=TOK)
print("SQL 会话:", s, "read_only =", d.get("data", {}).get("read_only"))
FSID = d["data"]["fsid"]

# 6) SELECT 正常
s, d = req("POST", f"/api/v1/sql/{FSID}/query", token=TOK, body={"sql": "SELECT id,hostname FROM assets LIMIT 5"})
dd = d.get("data", {})
print("SELECT:", s, "rows =", len(dd.get("rows", [])), "cols =", dd.get("cols"))

# 7) 写语句（只读拦截，不达 DB）
s, d = req("POST", f"/api/v1/sql/{FSID}/query", token=TOK, body={"sql": "UPDATE assets SET hostname='hack' WHERE id=1"})
print("UPDATE(只读):", s, str(d.get("detail", ""))[:40])

# 8) 高危 DROP（阻断）
s, d = req("POST", f"/api/v1/sql/{FSID}/query", token=TOK, body={"sql": "DROP DATABASE nextbastion"})
print("DROP DATABASE:", s, str(d.get("detail", ""))[:50])

# 9) schema 树
s, d = req("GET", f"/api/v1/sql/{FSID}/schema", token=TOK)
print("schema:", s, "dbs =", [t["db"] for t in d.get("data", [])][:4])

# 10) 关闭
s, d = req("POST", f"/api/v1/sql/{FSID}/close", token=TOK)
print("close:", s)

# 11) 开写权限 → 读写会话 → 建临时表写成功再删
cu.execute("UPDATE access_policies SET allow_sql_write=1 WHERE id=%s", (pid,))
s, d = req("POST", f"/api/v1/sql/{AID}/{ACCID}/session", token=TOK)
print("读写会话 read_only =", d.get("data", {}).get("read_only"), "(预期 False)")
FSID2 = d["data"]["fsid"]
s, d = req("POST", f"/api/v1/sql/{FSID2}/query", token=TOK, body={"sql": "CREATE TEMPORARY TABLE _t14(x INT)"})
print("CREATE TEMP:", s)
s, d = req("POST", f"/api/v1/sql/{FSID2}/query", token=TOK, body={"sql": "INSERT INTO _t14 VALUES (42)"})
print("INSERT:", s, "affected =", d.get("data", {}).get("affected"))
s, d = req("POST", f"/api/v1/sql/{FSID2}/query", token=TOK, body={"sql": "DROP TABLE _t14"})
print("DROP TABLE(告警放行):", s, "action =", d.get("data", {}).get("action"))
req("POST", f"/api/v1/sql/{FSID2}/close", token=TOK)
cu.execute("UPDATE access_policies SET allow_sql_write=0 WHERE id=%s", (pid,))

# 12) 网络设备类型资产（建卡验证字段 + 删除）
s, d = req("POST", "/api/v1/assets", token=TOK, body={
    "hostname": "SW-TEST-S57", "ip": "127.0.0.95", "os_type": "VRP", "protocol": "ssh",
    "ssh_port": 22, "node_id": 1, "device_type": "huawei",
    "account": "netadmin", "password": "x", "enable_password": "enasecret"})
print("建华为资产:", s)
s, d = req("GET", "/api/v1/assets", token=TOK)
tgt = [a for a in d["data"] if a["hostname"] == "SW-TEST-S57"]
print("回读 device_type:", tgt[0]["device_type"] if tgt else "?")
# 清理
for a in [x for x in d["data"] if x["hostname"] in ("SW-TEST-S57", "db-local-test")]:
    req("DELETE", f"/api/v1/assets/{a['id']}", token=TOK)
print("清理完成")
print("=== E2E V1.4 完成 ===")
