"""NextBastion F8 - 账号盘点（僵尸/私建账号识别）
- SSH 采集：/etc/passwd（可登录用户）+ lastlog 最后登录
- 四分类比对：托管活跃 / 托管闲置 / 未托管（私建嫌疑）/ 托管失效
- 结果存 account_scans 表（每次扫描一行汇总 + 明细 JSON）
"""
import asyncio, json, time
from datetime import datetime

import asyncssh

import utils


async def _collect_asset(asset: dict, account: dict) -> dict:
    """单资产采集：返回 {users:[{name,uid,shell,last}], error}"""
    try:
        secret = utils.decrypt_secret(account["secret_encrypted"])
        conn = await asyncio.wait_for(
            asyncssh.connect(asset["ip"], port=asset["ssh_port"] or 22,
                             username=account["username"], password=secret,
                             known_hosts=None), timeout=8)
        try:
            res = await asyncio.wait_for(conn.run(
                "awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ && ($3>=1000 || $3==0) {print $1\":\"$3\":\"$7}' /etc/passwd",
                timeout=10), timeout=12)
            users_raw = res.stdout.strip().splitlines() if res.stdout else []
            # lastlog 批量（最后一次登录时间）
            res2 = await asyncio.wait_for(conn.run(
                "lastlog 2>/dev/null | tail -n +2 | awk 'NF>3 {date=\"\"; for(i=5;i<=NF;i++)date=date\" \"$i; print $1\"|\"date}'",
                timeout=10), timeout=12)
            lastlog = {}
            for ln in (res2.stdout or "").strip().splitlines():
                if "|" in ln:
                    u, d = ln.split("|", 1)
                    lastlog[u.strip()] = d.strip()
            users = []
            for line in users_raw:
                name, uid, shell = line.split(":")
                users.append({"name": name, "uid": int(uid), "shell": shell,
                              "last": lastlog.get(name, "")[:30]})
            return {"users": users, "error": ""}
        finally:
            conn.close()
    except Exception as e:
        return {"users": [], "error": f"{type(e).__name__}: {str(e)[:60]}"}


def classify(scan_users: list, asset_id: int) -> list:
    """四分类比对：资产账号 vs 托管账号 vs 90 天会话活跃"""
    # 托管账号
    managed = {r["username"]: r for r in utils.query(
        "SELECT username, id FROM asset_accounts WHERE asset_id=%s AND status='active'", (asset_id,))}
    # 近 90 天有会话的账号（sessions.account_name）
    since = datetime.now().timestamp() - 90 * 86400
    active_names = set(r["account_name"] for r in utils.query(
        "SELECT DISTINCT account_name FROM sessions WHERE asset_id=%s AND UNIX_TIMESTAMP(started_at)>=%s",
        (asset_id, int(since))))
    out = []
    for u in scan_users:
        name = u["name"]
        if name in managed:
            cat = "managed_active" if (name in active_names or u.get("last")) else "managed_idle"
        else:
            cat = "unmanaged"
        risk = "high" if (cat == "unmanaged" and u.get("uid") == 0) else \
               ("mid" if cat == "managed_idle" else "")
        out.append({**u, "category": cat, "risk": risk})
    # 托管但资产上不存在（托管失效）
    scan_names = {u["name"] for u in scan_users}
    for name, acc in managed.items():
        if name not in scan_names:
            out.append({"name": name, "uid": "-", "shell": "-", "last": "-",
                        "category": "managed_missing", "risk": "low"})
    return out


def scan_all(actor="system") -> dict:
    """全量扫描入口（同步包装）"""
    assets = utils.query(
        """SELECT a.* FROM assets a
           WHERE (a.protocol='ssh' OR a.protocol IS NULL)
           AND EXISTS (SELECT 1 FROM asset_accounts x WHERE x.asset_id=a.id AND x.status='active')""")
    details, ok_count, fail_count = [], 0, 0
    cat_total = {"managed_active": 0, "managed_idle": 0, "unmanaged": 0, "managed_missing": 0}
    high_risk = []

    async def run_all():
        tasks = []
        for a in assets:
            acc = utils.query("SELECT * FROM asset_accounts WHERE asset_id=%s AND status='active' LIMIT 1", (a["id"],), one=True)
            if acc:
                tasks.append(_collect_asset(a, acc))
        return await asyncio.gather(*tasks)

    results = asyncio.run(run_all()) if assets else []
    for a, r in zip(assets, results):
        if r["error"]:
            fail_count += 1
            details.append({"asset": a["hostname"], "asset_id": a["id"], "ip": a["ip"],
                            "error": r["error"], "users": []})
            continue
        ok_count += 1
        cls = classify(r["users"], a["id"])
        for c in cls:
            cat_total[c["category"]] += 1
            if c["risk"] == "high":
                high_risk.append({"asset": a["hostname"], "user": c["name"], "uid": c["uid"]})
        details.append({"asset": a["hostname"], "asset_id": a["id"], "ip": a["ip"],
                        "error": "", "users": cls})

    report = {"ok": ok_count, "failed": fail_count, "total": len(details),
              "categories": cat_total, "high_risk": high_risk, "details": details,
              "scanned_at": datetime.now().strftime("%F %T"), "actor": actor}
    utils.execute(
        "INSERT INTO account_scans (summary, detail, created_by) VALUES (%s,%s,%s)",
        (json.dumps({k: report[k] for k in ("ok", "failed", "categories", "high_risk", "scanned_at")}, ensure_ascii=False),
         json.dumps(details, ensure_ascii=False), actor))
    return report
