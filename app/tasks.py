"""任务管理引擎（V2.0）· Linux 脚本 / 交换机备份 / 交换机巡检
V2.1 增强（对齐 PRD-交换机管理-备份与巡检-20261021）：
- SSH 采集层：提示符正则驱动读（替代盲等 sleep）、More 分页防御吞掉、
  慢设备 output_timeout 分段累积（不超时中断）、老 VRP KEX 优化
- 备份三段式：版本号每资产连续（失败不回退）、sha256 判变、±行数入库、
  保留策略（最近 N 份 ∪ 每日末份永久）、trigger 徽章（manual/scheduled）
- 巡检解析矩阵：version/cpu 双形态、memory 三形态、interface 双表头+逻辑口过滤、
  environment 多形态；结构化指标入 health_snapshots
- 离线防抖：连续 N 次失败才标 offline（asset_health_streak）
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

# 提示符正则（与 netdev.py 注册表一致；华为 <h> / [h-xxx] 两种形态）
_PROMPT_RES = {
    "huawei": re.compile(r"(\[[\w\-\./]+\]#|<[\w\-\./]+>)\s*$"),
    "h3c": re.compile(r"(\[[\w\-\./]+\]|<[\w\-\./]+>)\s*$"),
    "cisco": re.compile(r"([\w\-\.\(\)]+[#>])\s*$"),
    "ruijie": re.compile(r"([\w\-\.\(\)]+[#>])\s*$"),
    "juniper": re.compile(r"([\w\-@:\.]+[>#])\s*$"),
}
_MORE_RE = re.compile(r".*?-+\s*More\s*-+.*")
# 命令回显行（提示符+命令本身）
_ECHO_RE = re.compile(r"^[\[<]?[\w\-\./]+[\]>]?[#>]?\s*(display|show)\s+\S+.*$")


def _classify_ssh_error(e: Exception) -> str:
    """SSH 失败四类归类（PRD F3）：auth_failed / unreachable / timeout / session"""
    msg = str(e).lower()
    if "auth" in msg or "password" in msg or "denied" in msg:
        return "auth_failed"
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)) or "timed out" in msg or "timeout" in msg:
        return "timeout"
    if "unreachable" in msg or "no route" in msg or "refused" in msg or "connection reset" in msg:
        return "unreachable"
    return "session"


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


# ============ 巡检解析器（V2.1 结构化矩阵，对齐 PRD §3.5） ============
def parse_inspect(output_map: dict, thresholds: dict) -> dict:
    """output_map: {cmd: output}；返回 {items, healthy, metrics:{...}}（结构化指标）"""
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    items = []
    m = {"vrp": None, "uptime": None, "cpu_pct": None, "mem_pct": None,
         "temp_max": None, "ports_down": None, "ports_total": None,
         "interfaces": [], "alarms": []}

    def add(name, level, detail=""):
        items.append({"name": name, "level": level, "detail": str(detail)[:200]})

    for cmd, out in output_map.items():
        if not out:
            continue
        low = cmd.lower()
        try:
            if "version" in low:
                # 双正则：`Version X,` 与 `V\dR\d`
                mm = re.search(r"Version\s+(\S+?),", out) or re.search(r"(V\d+R\d+\S*)", out)
                up = re.search(r"uptime\s+is\s+(.+)", out, re.I) or \
                     re.search(r"(\S+\s+\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})", out)
                if mm:
                    m["vrp"] = mm.group(1)[:64]
                    add("VRP 版本", "ok", m["vrp"])
                if up:
                    m["uptime"] = up.group(1).strip()[:128]
            elif "cpu" in low:
                # 双形态：`CPU Usage : N%` / `N% CPU`
                mm = re.search(r"CPU\s+Usage\s*[:：]?\s*(\d+(?:\.\d+)?)\s*%", out) or \
                     re.search(r"(\d+(?:\.\d+)?)\s*%\s*CPU", out)
                if mm:
                    v = float(mm.group(1))
                    m["cpu_pct"] = v
                    add("CPU", "warn" if v > th["cpu"] else "ok", f"{v}%（阈值 {th['cpu']}%）")
            elif "memory" in low:
                # 三形态：Percentage 行 / Memory used 百分比 / 裸百分数兜底
                mm = re.search(r"Percentage\s+of\s+(?:memory\s+)?(?:used|Memory\s+Used)\s*[:：]?\s*(\d+(?:\.\d+)?)\s*%", out) or \
                     re.search(r"(\d+(?:\.\d+)?)\s*%\s+(?:memory|Memory)", out) or \
                     re.search(r"(\d+(?:\.\d+)?)\s*%", out)
                if mm:
                    v = float(mm.group(1))
                    m["mem_pct"] = v
                    add("内存", "warn" if v > th["mem"] else "ok", f"{v}%（阈值 {th['mem']}%）")
                else:
                    add("内存", "warn", "未能解析内存输出")
            elif "environment" in low or "temperature" in low:
                # 多形态：A 表格(Temp(c)列) / B temperature all 列序 / C `N C` 简式
                temps = []
                for lmm in re.finditer(r"(\d{2,3})\s*[Cc]\b", out):
                    temps.append(int(lmm.group(1)))
                # 表格形态：Temp(c) 列头后每行的温度数字（行内独立数字非 C 后缀）
                if "temp" in out.lower():
                    hdr = re.search(r"(?:Temp\(c\)|TEMP\(C\))", out)
                    if hdr and not temps:
                        for ln in out.splitlines():
                            g = re.match(r"^\s*(\d+)\s+(\d{2,3})\s*$", ln.strip())
                            if g:
                                temps.append(int(g.group(2)))
                            else:
                                g2 = re.findall(r"\b(\d{2,3})\b", ln)
                                if g2 and re.match(r"^\s*(?:SLOT|Slot|slot)?\s*\d*", ln):
                                    temps.extend(int(x) for x in g2 if 10 <= int(x) <= 120)
                # B 形态：`38  Normal`（温度为状态词前最后一个数字；允许 Slot/Card/Sensor 列）
                if not temps and "temp" in out.lower():
                    for ln in out.splitlines():
                        g = re.match(r"^\s*(?:\S+\s+){0,4}?(\d{2,3})\s+(?:Normal|Abnormal|Warning)\s*$", ln)
                        if g:
                            temps.append(int(g.group(1)))
                temps = [t for t in temps if 10 <= t <= 120]
                if temps:
                    mx = max(temps)
                    m["temp_max"] = float(mx)
                    add("温度", "warn" if mx > th["temp"] else "ok", f"最高 {mx}°C（阈值 {th['temp']}°C）")
            elif "interface brief" in low:
                ifaces, n_total, n_down = _parse_interfaces(out)
                m["interfaces"] = ifaces
                m["ports_total"] = n_total
                m["ports_down"] = n_down
                if n_down:
                    names = "、".join(i["name"] for i in ifaces if i["phy"] == "down" and not i["logical"])[:60]
                    add("端口状态", "warn", f"{n_down} 个物理口 DOWN：{names}")
                elif n_total:
                    add("端口状态", "ok", f"{n_total} 个物理口全 UP")
            elif "alarm" in low:
                body = [l.strip() for l in out.splitlines()
                        if l.strip() and "no alarm" not in l.lower() and not _ECHO_RE.match(l.strip())
                        and not re.match(r"^[\[<][\w\-\./]+[\]>]", l.strip())]
                if body:
                    m["alarms"] = [l[:120] for l in body[:6]]
                    add("设备告警", "warn", "；".join(body[:4])[:200])
                else:
                    add("设备告警", "ok", "无 active alarm")
            elif "power" in low or "fan" in low:
                bad = [l.strip() for l in out.splitlines()
                       if re.search(r"absent|fault|not\s+present|Offline", l, re.I)
                       and not re.search(r"power\s+is\s+normal|fan.*is\s+normal|present", l, re.I)]
                nm = "电源" if "power" in low else "风扇"
                add(nm, "warn" if bad else "ok", "；".join(bad[:3]) if bad else "正常")
        except Exception:
            continue
    healthy = all(i["level"] == "ok" for i in items) if items else False
    return {"items": items, "healthy": healthy, "metrics": m}


_LOGICAL_IF = re.compile(r"^(Vlanif|LoopBack|Tunnel|NULL|InLoopBack|MEth|Vbdif)", re.I)


def _parse_interfaces(out: str):
    """display interface brief 解析（有无 utilization/inErrors 列均可）+ 逻辑口过滤
    返回 (interfaces, n_total, n_down)——n_* 只统计物理口"""
    ifaces = []
    for line in out.splitlines():
        line = line.rstrip()
        if not line.strip() or re.match(r"^[\[<][\w\-\./]+[\]>]", line.strip()) or _ECHO_RE.match(line.strip()):
            continue
        g = None
        # 形态A：PHY(n) up/down  proto  inUti outUti inErr [outErr]
        mm = re.match(r"^(\S+)\s+(up|down)\s+(up|down)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+)", line, re.I)
        if mm:
            g = mm.groups()
            ifaces.append({"name": g[0], "phy": g[1].lower(), "protocol": g[2].lower(),
                           "in_uti": float(g[3]), "out_uti": float(g[4]), "in_errors": int(g[5]), "out_errors": None})
            continue
        # 形态B：无 utilization 列：GE0/0/24  down  down  0 0 0 0
        mm = re.match(r"^(\S+)\s+(up|down)\s+(up|down)\b", line, re.I)
        if mm:
            g = mm.groups()
            ifaces.append({"name": g[0], "phy": g[1].lower(), "protocol": g[2].lower(),
                           "in_uti": None, "out_uti": None, "in_errors": None, "out_errors": None})
    for i in ifaces:
        i["logical"] = bool(_LOGICAL_IF.match(i["name"]))
    phys = [i for i in ifaces if not i["logical"]]
    return ifaces, len(phys), sum(1 for i in phys if i["phy"] == "down")


def diff_snapshots(old: str, new: str) -> str:
    d = difflib.unified_diff((old or "").splitlines(), (new or "").splitlines(),
                             fromfile="previous", tofile="current", lineterm="")
    return "\n".join(list(d)[:400])


def diff_line_counts(old: str, new: str) -> tuple:
    """± 行数（对齐 PRD F5：unified diff ±行数入库）"""
    d = difflib.unified_diff((old or "").splitlines(), (new or "").splitlines(), lineterm="")
    added = removed = 0
    for l in d:
        if l.startswith("+") and not l.startswith("+++"):
            added += 1
        elif l.startswith("-") and not l.startswith("---"):
            removed += 1
    return added, removed


# ============ 保留策略（纯函数，可单测 · 对齐 PRD §3.4） ============
def protected_ids(rows: list, keep_n, keep_daily: bool) -> set:
    """rows: [{id, created_at}]（按 id 降序）；返回受保护 id 集
    规则：最近 N 份 ∪ 每日末份（每天 id 最大的版本）"""
    if not rows:
        return set()
    keep_n = keep_n or 0
    prot = set()
    if keep_n > 0:
        prot |= {r["id"] for r in rows[:keep_n]}
    if keep_daily:
        last_of_day = {}
        for r in rows:  # 降序——首个即当日最新
            day = str(r.get("created_at") or "")[:10]
            if day and day not in last_of_day:
                last_of_day[day] = r["id"]
        prot |= set(last_of_day.values())
    return prot


# ============ 执行引擎 ============
def get_task(task_id: int, owner_id: int) -> dict:
    return utils.query("SELECT * FROM tasks WHERE id=%s AND owner_id=%s", (task_id, owner_id), one=True)


def list_tasks(owner_id: int) -> list:
    return utils.query("SELECT t.*, (SELECT COUNT(*) FROM task_runs r WHERE r.task_id=t.id) run_count, "
                       "(SELECT r.status FROM task_runs r WHERE r.task_id=t.id ORDER BY r.id DESC LIMIT 1) last_status, "
                       "(SELECT r.started_at FROM task_runs r WHERE r.task_id=t.id ORDER BY r.id DESC LIMIT 1) last_at "
                       "FROM tasks t WHERE t.owner_id=%s ORDER BY t.id DESC", (owner_id,))


def _authorized_account(user: dict, asset_id: int):
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


async def _netdev_connect(ip: str, port: int, username: str, secret: str):
    """netdev SSH 连接（老 VRP KEX 优化：优先快速算法集，失败回退默认协商）"""
    import asyncssh
    try:
        kex = ["curve25519-sha256", "ecdh-sha2-nistp256",
               "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"]
        conn = await asyncio.wait_for(asyncssh.connect(
            ip, port=port, username=username, password=secret,
            known_hosts=None, kex_algs=kex), timeout=15)
        return conn
    except Exception:
        # KEX 限制失败 → 回退默认算法协商（兼容更多老设备）
        conn = await asyncio.wait_for(asyncssh.connect(
            ip, port=port, username=username, password=secret, known_hosts=None), timeout=15)
        return conn


async def _read_until_prompt(ch, prompt_re, output_timeout: int = 60, idle_limit: float = 8.0):
    """提示符驱动读：数据到达即累积；提示符在行尾出现即完成；More 行吞掉（防御）；
    慢设备分段累积不中断——只要仍有数据到达就续读，总上限 output_timeout。"""
    buf = ""
    deadline = time.monotonic() + max(30, output_timeout)
    last_data = time.monotonic()
    while time.monotonic() < deadline:
        chunk = None
        try:
            chunk = await asyncio.wait_for(ch.stdout.read(65536), timeout=0.8)
        except asyncio.TimeoutError:
            pass
        if chunk:
            buf += chunk
            last_data = time.monotonic()
        buf = _MORE_RE.sub("", buf)
        lines = buf.split("\n")
        if prompt_re and prompt_re.search(lines[-1] if lines else ""):
            break
        if not chunk and (time.monotonic() - last_data) > idle_limit:
            break  # 提示符未现但链路空闲超限 → 认为本段结束
    return buf


async def _netdev_collect(conn, kind_dev: str, commands: list, enable_secret, timeout: int):
    """netdev 交互采集：enable → 免分页 → 逐命令提示符驱动读。
    超时预算：连接后总预算 = timeout + 10s；单命令 idle 上限动态取剩余预算。"""
    import netdev as netdev_mod
    pre = _PROMPT_RES.get(kind_dev)
    ch = await asyncio.wait_for(conn.create_process(term_type='xterm-256color'), timeout=10)
    await asyncio.sleep(1.0)
    try:
        await asyncio.wait_for(ch.stdout.read(4000), timeout=2)
    except Exception:
        pass
    enb = netdev_mod.enable_conf(kind_dev)
    if enb and enable_secret:
        ch.stdin.write(enb["cmd"])
        await asyncio.sleep(0.8)
        ch.stdin.write(enable_secret + "\n")
        await asyncio.sleep(0.8)
        try:
            await asyncio.wait_for(ch.stdout.read(8000), timeout=2)
        except Exception:
            pass
    pg = netdev_mod.pager_cmd(kind_dev)
    if pg:
        ch.stdin.write(pg + "\n")
        try:
            await asyncio.wait_for(_read_until_prompt(ch, pre, output_timeout=15, idle_limit=3.0), timeout=20)
        except Exception:
            pass
    outs = {}
    whole_parts = []
    deadline = time.monotonic() + max(40, timeout) + 10
    per_idle = max(4.0, min(8.0, timeout / max(1, len(commands))))
    for cmd in commands:
        remain = deadline - time.monotonic()
        if remain < 4:
            outs[cmd] = ""
            continue
        ch.stdin.write(cmd + "\n")
        try:
            seg = await asyncio.wait_for(
                _read_until_prompt(ch, pre, output_timeout=int(remain), idle_limit=per_idle),
                timeout=remain + 2)
        except Exception:
            seg = ""
        outs[cmd] = seg
        whole_parts.append(seg)
    ch.close()
    whole = "\n".join(p for p in whole_parts if p)
    return {"ok": True, "output": whole[:500000], "exit_code": 0, "outs": outs}


async def _run_on_asset(kind_dev: str, ip: str, port: int, username: str, secret: str,
                        payload: dict, timeout: int):
    """单资产执行：返回 {ok, output, exit_code, outs:{cmd:output}, err_class}
    - script: exec_command
    - netdev: 提示符驱动交互 shell（enable 升权 → 免分页 → 逐命令提示符读全）"""
    import asyncssh
    try:
        if kind_dev == "linux":
            conn = await asyncio.wait_for(asyncssh.connect(
                ip, port=port, username=username, password=secret, known_hosts=None), timeout=15)
        else:
            conn = await _netdev_connect(ip, port, username, secret)
    except Exception as e:
        ec = _classify_ssh_error(e)
        return {"ok": False, "output": f"连接失败[{ec}]: {str(e)[:120]}", "exit_code": -1, "err_class": ec}

    try:
        if kind_dev == "linux":
            result = await asyncio.wait_for(conn.run(payload["script"], timeout=timeout), timeout=timeout + 10)
            return {"ok": result.exit_status == 0,
                    "output": (result.stdout or "") + (("\n[stderr]\n" + result.stderr) if result.stderr else ""),
                    "exit_code": result.exit_status}
        # ---- 网络设备：提示符驱动交互采集 ----
        return await _netdev_collect(conn, kind_dev, payload["commands"],
                                     payload.get("enable_secret"), timeout)
    except Exception as e:
        ec = _classify_ssh_error(e)
        return {"ok": False, "output": f"执行失败[{ec}]: {type(e).__name__}: {str(e)[:120]}",
                "exit_code": -2, "err_class": ec}
    finally:
        conn.close()


# ============ 备份三段式（对齐 PRD §3.3） ============
def _alloc_version(asset_id: int, owner_id: int, task_id: int, trigger: str):
    """①占位：max(version_no)+1，插占位行（失败也占版本——保证版本连续可比）"""
    row = utils.query("SELECT MAX(version_no) mv FROM config_snapshots WHERE asset_id=%s AND owner_id=%s",
                      (asset_id, owner_id), one=True)
    vno = (row["mv"] or 0) + 1
    h = hashlib.sha256(b"").hexdigest()
    sid = utils.execute(
        "INSERT INTO config_snapshots (asset_id,owner_id,task_id,content,hash,size,changed,trigger_type,version_no) "
        "VALUES (%s,%s,%s,'',%s,0,0,%s,%s)", (asset_id, owner_id, task_id, h, trigger, vno))
    return sid, vno


def _apply_retention(asset_id: int, owner_id: int, keep_n, keep_daily: bool):
    """保留策略：删除不在保护集内的旧版本（快照存 DB，无文件清理）"""
    if not keep_n and not keep_daily:
        return 0
    rows = utils.query("SELECT id, version_no, changed, created_at FROM config_snapshots "
                       "WHERE asset_id=%s AND owner_id=%s ORDER BY id DESC", (asset_id, owner_id))
    prot = protected_ids(rows, keep_n, keep_daily)
    victim = [r["id"] for r in rows if r["id"] not in prot]
    for vid in victim:
        utils.execute("DELETE FROM config_snapshots WHERE id=%s", (vid,))
    return len(victim)


def _bump_streak(asset_id: int, owner_id: int, success: bool):
    """离线防抖：连续失败 streak；最新成功即复位（对齐 PRD F11）"""
    try:
        if success:
            utils.execute(
                "INSERT INTO asset_health_streak (asset_id,owner_id,fail_streak,last_ok_at) VALUES (%s,%s,0,NOW()) "
                "ON DUPLICATE KEY UPDATE fail_streak=0, last_ok_at=NOW()",
                (asset_id, owner_id))
        else:
            utils.execute(
                "INSERT INTO asset_health_streak (asset_id,owner_id,fail_streak) VALUES (%s,%s,1) "
                "ON DUPLICATE KEY UPDATE fail_streak=fail_streak+1",
                (asset_id, owner_id))
    except Exception:
        pass


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
        # 备份任务走三段式版本管理
        snap_id = vno = None
        if type_ == "backup":
            snap_id, vno = _alloc_version(aid, owner_id, task_id,
                                          "scheduled" if trigger == "cron" else "manual")
        r = asyncio.new_event_loop().run_until_complete(
            _run_on_asset(kind, asset["ip"], asset["ssh_port"] or 22, acc["acc_name"], secret,
                          payload, t["timeout_s"]))
        detail = {}
        output = r["output"][:1000000]
        if type_ == "backup" and snap_id:
            if r.get("ok"):
                content = _extract_config(r.get("outs", {}).get(payload["commands"][0], "") or r["output"])
                h = hashlib.sha256(content.encode()).hexdigest()
                prev = utils.query(
                    "SELECT * FROM config_snapshots WHERE asset_id=%s AND owner_id=%s AND id<%s AND hash<>%s "
                    "ORDER BY id DESC LIMIT 1", (aid, owner_id, snap_id, hashlib.sha256(b"").hexdigest()), one=True)
                changed = bool(prev and prev["hash"] != h and content)
                added, removed = (0, 0) if not changed else diff_line_counts(
                    prev["content"] if prev else "", content)
                utils.execute(
                    "UPDATE config_snapshots SET content=%s, hash=%s, size=%s, changed=%s, "
                    "diff_added=%s, diff_removed=%s WHERE id=%s",
                    (content, h, len(content), 1 if changed else 0, added, removed, snap_id))
                detail = {"snapshot_id": snap_id, "version_no": vno, "changed": changed,
                          "size": len(content), "diff": f"+{added}/-{removed}"}
                if changed and "change" in (t["notify_on"] or ""):
                    alarms.append(f"[备份变更] {asset['hostname']} v{vno} 与上一版不同（+{added}/-{removed}）")
                _bump_streak(aid, owner_id, success=bool(content))
            else:
                # 失败：版本号不回退，记录 fail_reason
                utils.execute(
                    "UPDATE config_snapshots SET fail_reason=%s WHERE id=%s",
                    (r.get("err_class") or "session", snap_id))
                detail = {"snapshot_id": snap_id, "version_no": vno, "failed": True,
                          "reason": r.get("err_class")}
                _bump_streak(aid, owner_id, success=False)
            # 保留策略
            removed_n = _apply_retention(aid, owner_id, t.get("retention_count"), t.get("retention_daily"))
            if removed_n:
                detail["retention_removed"] = removed_n
        if r.get("ok") and type_ == "inspect":
            res = parse_inspect(r.get("outs", {}), json.loads(t["thresholds"] or "null"))
            detail = res
            hs_id = utils.execute(
                "INSERT INTO health_snapshots (asset_id,owner_id,task_id,vrp,uptime,cpu_pct,mem_pct,temp_max,"
                "ports_down,ports_total,interfaces_json,alarms_json,items_json,healthy) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (aid, owner_id, task_id, res["metrics"]["vrp"], res["metrics"]["uptime"],
                 res["metrics"]["cpu_pct"], res["metrics"]["mem_pct"],
                 res["metrics"]["temp_max"], res["metrics"]["ports_down"], res["metrics"]["ports_total"],
                 json.dumps(res["metrics"]["interfaces"], ensure_ascii=False),
                 json.dumps(res["metrics"]["alarms"], ensure_ascii=False),
                 json.dumps(res["items"], ensure_ascii=False), 1 if res["healthy"] else 0))
            detail["health_snapshot_id"] = hs_id
            if not res["healthy"] and "alarm" in (t["notify_on"] or ""):
                bad = [i for i in res["items"] if i["level"] != "ok"]
                alarms.append(f"[巡检异常] {asset['hostname']}：" + "；".join(f"{i['name']} {i['detail']}" for i in bad[:4]))
            _bump_streak(aid, owner_id, success=bool(res["items"]))
        if not r.get("ok") and type_ != "backup" and "fail" in (t["notify_on"] or ""):
            alarms.append(f"[任务失败] {asset['hostname']}：{r['output'][:120]}")
        if not r.get("ok"):
            _bump_streak(aid, owner_id, success=False)
        st = "success" if r.get("ok") else "fail"
        stats["ok" if st == "success" else "fail"] += 1
        utils.execute("INSERT INTO task_run_items (run_id,asset_id,status,exit_code,output,detail) "
                      "VALUES (%s,%s,%s,%s,%s,%s)",
                      (run_id, aid, st, r.get("exit_code"), output,
                       json.dumps(detail, ensure_ascii=False) if detail else None))
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
    if lines and ("configuration" in lines[0].lower() or lines[0].strip().startswith("display")
                  or lines[0].strip().startswith("show")):
        lines = lines[1:]
    while lines and (lines[-1].strip() in ("return", "#", "<-1>", "") or lines[-1].startswith("<") or lines[-1].startswith("[")):
        lines = lines[:-1]
    return "\n".join(lines)


def _send_alarms(task_name: str, msgs: list):
    try:
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
