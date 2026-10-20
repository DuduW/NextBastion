"""任务管理引擎（V2.0）· Linux 脚本 / 交换机备份 / 交换机巡检

- 调度：进程内简易 cron 轮询器（60s 粒度，避免引 APScheduler 依赖；重启自动恢复）
- 隔离：一切按 owner_id；执行前对每个资产重新 check_access（授权回收→skip）
- 备份：difflib 判变 + 版本库；巡检：华为命令集解析（CPU/内存/温度/端口/告警）
- 告警：复用 webhook 通道（webhook_config）
"""
import asyncio
import difflib
import hashlib
import json
import re
import threading
import time
from datetime import datetime

import utils

# ============ 巡检命令集（华为默认，H3C/思科映射同源） ============
INSPECT_DEFAULT_CMDS = [
    "display version", "display cpu-usage", "display memory-usage",
    "display environment", "display interface brief",
    "display power", "display fan", "display alarm active",
]
BACKUP_CMD = {"huawei": "display current-configuration", "h3c": "display current-configuration",
              "cisco": "show running-config", "ruijie": "show running-config",
              "juniper": "show configuration"}
DEFAULT_THRESHOLDS = {"cpu": 80, "mem": 80, "temp": 40}


# ============ cron 解析（5 段：分 时 日 月 周；支持 * , - /） ============
def cron_matches(expr: str, now: datetime) -> bool:
    try:
        parts = (expr or "").strip().split()
        if len(parts) != 5:
            return False
        fields = [(parts[0], now.minute, 0, 59), (parts[1], now.hour, 0, 23),
                  (parts[2], now.day, 1, 31), (parts[3], now.month, 1, 12),
                  (parts[4], now.weekday(), 0, 6)]
        for spec, val, lo, hi in fields:
            if not _field_match(spec, val, lo, hi):
                return False
        return True
    except Exception:
        return False


def _field_match(spec: str, val: int, lo: int, hi: int) -> bool:
    for piece in spec.split(","):
        piece = piece.strip()
        if not piece:
            continue
        step = 1
        if "/" in piece:
            piece, step_s = piece.split("/", 1)
            step = int(step_s)
        if piece == "*":
            rng = range(lo, hi + 1)
        elif "-" in piece:
            a, b = piece.split("-", 1)
            rng = range(int(a), int(b) + 1)
        else:
            base = int(piece)
            rng = range(base, base + 1)
        if step > 1:
            rng = [x for x in rng if (x - rng[0]) % step == 0]
        if val in rng:
            return True
    return False


# ============ 巡检解析器 ============
def parse_inspect(output_map: dict, thresholds: dict) -> dict:
    """output_map: {cmd: output}；返回 {items:[{name,level,detail}], healthy:bool}"""
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    items = []

    def add(name, level, detail=""):
        items.append({"name": name, "level": level, "detail": str(detail)[:200]})

    for cmd, out in output_map.items():
        if not out:
            continue
        low = cmd.lower()
        try:
            if "cpu" in low:
                m = re.search(r"(\d+(?:\.\d+)?)\s*%", out)
                if m:
                    v = float(m.group(1))
                    add("CPU", "warn" if v > th["cpu"] else "ok", f"{v}%（阈值 {th['cpu']}%）")
            elif "memory" in low:
                m = re.search(r"(\d+(?:\.\d+)?)\s*%", out)
                if m:
                    v = float(m.group(1))
                    add("内存", "warn" if v > th["mem"] else "ok", f"{v}%（阈值 {th['mem']}%）")
            elif "environment" in low or "temperature" in low:
                temps = re.findall(r"(\d{2,3})\s*[Cc]", out)
                if temps:
                    mx = max(int(t) for t in temps)
                    add("温度", "warn" if mx > th["temp"] else "ok", f"最高 {mx}°C（阈值 {th['temp']}°C）")
            elif "interface brief" in low:
                downs = re.findall(r"^(\S+)\s+(down|DOWN)\s+(down|DOWN)", out, re.M)
                if downs:
                    add("端口状态", "warn", f"{len(downs)} 个端口 DOWN：" + "、".join(d[0] for d in downs[:8]))
                else:
                    add("端口状态", "ok", "无 DOWN 端口")
            elif "alarm" in low:
                if re.search(r"\S", out.replace("No alarm", "").replace("information", "")):
                    body = [l for l in out.splitlines() if l.strip() and "no alarm" not in l.lower()]
                    if body:
                        add("设备告警", "warn", "；".join(body[:4]))
                    else:
                        add("设备告警", "ok", "无 active alarm")
                else:
                    add("设备告警", "ok", "无 active alarm")
            elif "power" in low or "fan" in low:
                bad = [l.strip() for l in out.splitlines()
                       if re.search(r"absent|fault|not\s+present|normal.*(power|fan)", l, re.I)
                       and not re.search(r"power\s+is\s+normal|fan.*is\s+normal", l, re.I)]
                nm = "电源" if "power" in low else "风扇"
                add(nm, "warn" if bad else "ok", "；".join(bad[:3]) if bad else "正常")
        except Exception:
            continue
    healthy = all(i["level"] == "ok" for i in items) if items else False
    return {"items": items, "healthy": healthy}


def diff_snapshots(old: str, new: str) -> str:
    d = difflib.unified_diff((old or "").splitlines(), (new or "").splitlines(),
                             fromfile="previous", tofile="current", lineterm="")
    return "\n".join(list(d)[:400])


# ============ 执行引擎 ============
def get_task(task_id: int, owner_id: int) -> dict:
    return utils.query("SELECT * FROM tasks WHERE id=%s AND owner_id=%s", (task_id, owner_id), one=True)


def list_tasks(owner_id: int) -> list:
    return utils.query("SELECT t.*, (SELECT COUNT(*) FROM task_runs r WHERE r.task_id=t.id) run_count, "
                       "(SELECT r.status FROM task_runs r WHERE r.task_id=t.id ORDER BY r.id DESC LIMIT 1) last_status, "
                       "(SELECT r.started_at FROM task_runs r WHERE r.task_id=t.id ORDER BY r.id DESC LIMIT 1) last_at "
                       "FROM tasks t WHERE t.owner_id=%s ORDER BY t.id DESC", (owner_id,))


def _authorized_account(user: dict, asset_id: int) -> dict | None:
    """owner 视角的授权校验 + 首个可用托管账号（复用 main.check_access 语义）"""
    acc = utils.query(
        "SELECT a.*, ac.id acc_id, ac.username acc_name, ac.secret_encrypted FROM assets a "
        "JOIN asset_accounts ac ON ac.asset_id=a.id WHERE a.id=%s LIMIT 1", (asset_id,), one=True)
    if not acc:
        return None
    return acc


def _check_owner_access(user: dict, asset_id: int) -> bool:
    """执行前二次校验：调 main 的 check_access（避免循环依赖，动态 import）"""
    import main as _m
    try:
        accs = utils.query("SELECT username FROM asset_accounts WHERE asset_id=%s", (asset_id,))
        for ac in (accs or [{"username": "*"}]):
            try:
                if _m.check_access(user, asset_id, ac["username"]):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


async def _run_on_asset(kind_dev: str, ip: str, port: int, username: str, secret: str,
                        payload: dict, timeout: int):
    """单资产执行：返回 {ok, output, exit_code}
    script: exec_command；netdev(backup/inspect): 交互 shell 顺序采集"""
    import asyncssh
    out_parts = []
    try:
        conn = await asyncio.wait_for(asyncssh.connect(
            ip, port=port, username=username, password=secret,
            known_hosts=None), timeout=15)
    except Exception as e:
        return {"ok": False, "output": f"连接失败: {type(e).__name__}: {str(e)[:120]}", "exit_code": -1}

    try:
        if kind_dev == "linux":
            result = await asyncio.wait_for(conn.run(payload["script"], timeout=timeout), timeout=timeout + 10)
            return {"ok": result.exit_status == 0,
                    "output": (result.stdout or "") + (("\n[stderr]\n" + result.stderr) if result.stderr else ""),
                    "exit_code": result.exit_status}
        # 网络设备：shell 采集（enable + 免分页 + 逐命令）
        import netdev as netdev_mod
        ch = await asyncio.wait_for(conn.create_process(term_type='xterm-256color'), timeout=10)
        await asyncio.sleep(1.5)
        enb = netdev_mod.enable_conf(kind_dev)
        if enb and payload.get("enable_secret"):
            ch.stdin.write(enb["cmd"])
            await asyncio.sleep(0.8)
            ch.stdin.write(payload["enable_secret"] + "\n")
            await asyncio.sleep(0.5)
        pg = netdev_mod.pager_cmd(kind_dev)
        if pg:
            ch.stdin.write(pg + "\n")
            await asyncio.sleep(0.6)
        outs = {}
        for cmd in payload["commands"]:
            ch.stdin.write(cmd + "\n")
            await asyncio.sleep(max(1.2, min(4, timeout / 8.0)))
        await asyncio.sleep(1.0)
        ch.stdin.write("\n")
        try:
            raw = await asyncio.wait_for(ch.stdout.read(200000), timeout=5)
        except Exception:
            raw = ""
        # 按命令切段（粗分：以命令回显为界）
        whole = raw or ""
        cur = None
        for cmd in payload["commands"]:
            idx = whole.find(cmd, 1 if whole.startswith(cmd) else 0)
            if idx < 0:
                outs[cmd] = ""
                continue
            nxt = None
            for c2 in payload["commands"]:
                if c2 == cmd:
                    continue
                j = whole.find(c2, idx + len(cmd))
                if j >= 0 and (nxt is None or j < nxt):
                    nxt = j
            outs[cmd] = whole[idx: nxt if nxt else len(whole)]
        ch.close()
        return {"ok": True, "output": whole[:500000], "exit_code": 0, "outs": outs}
    except Exception as e:
        return {"ok": False, "output": f"执行失败: {type(e).__name__}: {str(e)[:120]}", "exit_code": -2}
    finally:
        conn.close()


def run_task(task_id: int, owner_id: int, trigger="cron") -> int:
    """同步入口（线程池调用）：创建 run + 逐资产执行 + 汇总 + 告警。返回 run_id"""
    t = get_task(task_id, owner_id)
    if not t:
        return 0
    user = utils.query("SELECT * FROM users WHERE id=%s", (owner_id,), one=True)
    run_id = utils.execute(
        "INSERT INTO task_runs (task_id, owner_id, `trigger`, status) VALUES (%s,%s,%s,'running')",
        (task_id, owner_id, trigger))
    t0 = time.time()
    stats = {"ok": 0, "fail": 0, "skip": 0}
    alarms = []
    asset_ids = json.loads(t["asset_ids"] or "[]")
    type_ = t["type"]

    for aid in asset_ids:
        asset = utils.query("SELECT * FROM assets WHERE id=%s", (aid,), one=True)
        if not asset:
            utils.execute("INSERT INTO task_run_items (run_id,asset_id,status,detail) VALUES (%s,%s,'skip',%s)",
                          (run_id, aid, json.dumps({"reason": "资产不存在"})))
            stats["skip"] += 1
            continue
        if not _check_owner_access(user, aid):
            utils.execute("INSERT INTO task_run_items (run_id,asset_id,status,detail) VALUES (%s,%s,'skip',%s)",
                          (run_id, aid, json.dumps({"reason": "授权已回收或不存在"})))
            stats["skip"] += 1
            continue
        acc = _authorized_account(user, aid)
        if not acc:
            utils.execute("INSERT INTO task_run_items (run_id,asset_id,status,detail) VALUES (%s,%s,'skip',%s)",
                          (run_id, aid, json.dumps({"reason": "无托管账号"})))
            stats["skip"] += 1
            continue
        secret = utils.decrypt_secret(acc["secret_encrypted"])
        payload = {}
        if type_ == "script":
            payload = {"script": (t["script_text"] or "")
                       .replace("{{hostname}}", asset["hostname"]).replace("{{ip}}", asset["ip"])}
            kind = "linux"
        else:
            cmds = [BACKUP_CMD.get(asset["device_type"], "display current-configuration")] if type_ == "backup" \
                else (json.loads(t["commands"] or "null") or INSPECT_DEFAULT_CMDS)
            payload = {"commands": cmds, "enable_secret": (utils.decrypt_secret(acc["enable_secret_enc"])
                       if acc.get("enable_secret_enc") else None)}
            kind = asset["device_type"] or "huawei"
        r = asyncio.new_event_loop().run_until_complete(
            _run_on_asset(kind, asset["ip"], asset["ssh_port"] or 22, acc["acc_name"], secret,
                          payload, t["timeout_s"]))
        detail = {}
        output = r["output"][:1000000]
        if r.get("ok") and type_ == "backup":
            content = _extract_config(r.get("outs", {}).get(payload["commands"][0], "") or r["output"])
            h = hashlib.sha256(content.encode()).hexdigest()
            prev = utils.query(
                "SELECT * FROM config_snapshots WHERE asset_id=%s AND owner_id=%s ORDER BY id DESC LIMIT 1",
                (aid, owner_id), one=True)
            changed = bool(prev and prev["hash"] != h and content)
            snap_id = utils.execute(
                "INSERT INTO config_snapshots (asset_id,owner_id,task_id,content,hash,size,changed) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (aid, owner_id, task_id, content, h, len(content), 1 if changed else 0))
            detail = {"snapshot_id": snap_id, "changed": changed, "size": len(content)}
            if changed and "change" in (t["notify_on"] or ""):
                alarms.append(f"[备份变更] {asset['hostname']} 配置与上一版不同（已存版本 #{snap_id}）")
        if r.get("ok") and type_ == "inspect":
            res = parse_inspect(r.get("outs", {}), json.loads(t["thresholds"] or "null"))
            detail = res
            if not res["healthy"] and "alarm" in (t["notify_on"] or ""):
                bad = [i for i in res["items"] if i["level"] != "ok"]
                alarms.append(f"[巡检异常] {asset['hostname']}：" + "；".join(f"{i['name']} {i['detail']}" for i in bad[:4]))
        if not r.get("ok") and "fail" in (t["notify_on"] or ""):
            alarms.append(f"[任务失败] {asset['hostname']}：{r['output'][:120]}")
        st = "success" if r.get("ok") else "fail"
        stats["ok" if st == "success" else "fail"] += 1
        utils.execute("INSERT INTO task_run_items (run_id,asset_id,status,exit_code,output,detail) "
                      "VALUES (%s,%s,%s,%s,%s,%s)",
                      (run_id, aid, st, r.get("exit_code"), output, json.dumps(detail, ensure_ascii=False) if detail else None))
    dur = int(time.time() - t0)
    status = "success" if stats["ok"] and not (stats["fail"] or stats["skip"]) else \
             ("partial" if stats["ok"] else "fail")
    summary = f"成功 {stats['ok']} / 失败 {stats['fail']} / 跳过 {stats['skip']}"
    utils.execute("UPDATE task_runs SET status=%s, summary=%s, finished_at=NOW(), duration_s=%s WHERE id=%s",
                  (status, summary, dur, run_id))
    if alarms:
        _send_alarms(t["name"], alarms)
    return run_id


def _extract_config(raw: str) -> str:
    lines = [l.rstrip() for l in (raw or "").splitlines() if l.strip()]
    # 去头（命令回显）尾（return/提示符）
    if lines and ("configuration" in lines[0].lower() or lines[0].strip().startswith("display") or lines[0].strip().startswith("show")):
        lines = lines[1:]
    while lines and (lines[-1].strip() in ("return", "#", "<-1>", "") or lines[-1].startswith("<") or lines[-1].startswith("[")):
        lines = lines[:-1]
    return "\n".join(lines)


def _send_alarms(task_name: str, msgs: list):
    try:
        import main as _m
        row = utils.query("SELECT detail FROM audit_logs WHERE action='webhook_config' ORDER BY id DESC LIMIT 1", one=True)
        urls = json.loads(row["detail"]).get("urls", []) if row else []
        if not urls:
            return
        import urllib.request
        for u in urls:
            try:
                body = json.dumps({"msgtype": "text", "text": {"content": f"[NextBastion 任务] {task_name}\n" + "\n".join(msgs[:6])}}).encode()
                req = urllib.request.Request(u, data=body, method="POST")
                req.add_header("Content-Type", "application/json")
                urllib.request.urlopen(req, timeout=8)
            except Exception:
                pass
    except Exception:
        pass


# ============ 调度器（60s 轮询，分钟去重） ============
def _scheduler_loop():
    last_min = None
    while True:
        try:
            now = datetime.now()
            key = now.strftime("%Y-%m-%d %H:%M")
            if key != last_min:
                last_min = key
                rows = utils.query("SELECT id, owner_id, cron_expr FROM tasks WHERE enabled=1")
                for t in (rows or []):
                    if cron_matches(t["cron_expr"], now):
                        threading.Thread(target=run_task, args=(t["id"], t["owner_id"]), daemon=True).start()
        except Exception:
            pass
        time.sleep(30)


threading.Thread(target=_scheduler_loop, daemon=True, name="nb-task-sched").start()
