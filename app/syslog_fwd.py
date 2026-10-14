"""NextBastion F5 - Syslog/SIEM 转发（RFC5424）
- 后台线程 + 内存队列（上限 10000，满丢弃计数）
- TCP/UDP 可配，断线重连（3s 退避）
- 配置存 audit_logs（action='syslog_config'，与 webhook 同模式）
"""
import json
import queue
import socket
import threading
import time
from datetime import datetime

import utils

Q = queue.Queue(maxsize=10000)
STATS = {"sent": 0, "failed": 0, "dropped": 0, "last_error": "", "last_ok_ts": None}
_thread = None


def get_config() -> dict:
    row = utils.query("SELECT detail FROM audit_logs WHERE action='syslog_config' ORDER BY id DESC LIMIT 1", one=True)
    try:
        cfg = (json.loads(row["detail"]) if row else {}) or {}
    except Exception:
        cfg = {}
    defaults = {"enabled": 0, "server": "", "proto": "tcp", "facility": 132, "events": {
        "login": 1, "cmd_block": 1, "high_risk": 1, "session": 1,
        "file_transfer": 1, "config_change": 0}}
    defaults.update({k: v for k, v in cfg.items() if v not in (None, "")})
    return defaults


def save_config(cfg: dict):
    utils.execute("DELETE FROM audit_logs WHERE action='syslog_config'")
    utils.execute("INSERT INTO audit_logs (actor, action, detail) VALUES ('system','syslog_config',%s)",
                  (json.dumps(cfg, ensure_ascii=False),))


def emit(event: str, msg: str, sd: dict = None):
    """埋点入口：event 属于配置开关的事件类别才入队"""
    if not event:
        return
    try:
        cfg = get_config()
        if not cfg.get("enabled") or not cfg.get("server"):
            return
        ev_map = {"login": "login", "login_fail": "login", "lock": "login",
                  "cmd_block": "cmd_block", "high_risk": "high_risk",
                  "session_open": "session", "session_close": "session",
                  "file_transfer": "file_transfer", "config_change": "config_change"}
        if not cfg.get("events", {}).get(ev_map.get(event, "")):
            return
        ts = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
        ts = ts[:-2] + ":" + ts[-2:]   # +0800 → +08:00
        sd_str = "".join(f' {k}="{str(v)[:120]}"' for k, v in (sd or {}).items())
        fac = int(cfg.get("facility") or 132)   # local4..local7 = 132..159 * 8
        pri = fac + 6   # informational
        line = f"<{pri}>1 {ts} nextbastion app - {event} [{event}@0{sd_str}] {msg}"
        Q.put_nowait(line)
    except queue.Full:
        STATS["dropped"] += 1
    except Exception:
        pass


def _sender():
    sock = None
    while True:
        cfg = get_config()
        if not cfg.get("enabled") or not cfg.get("server"):
            time.sleep(5)
            continue
        line = Q.get()
        try:
            host, port = cfg["server"].split(":")
            port = int(port)
            if cfg.get("proto") == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto((line + "\n").encode(), (host, port))
            else:
                if sock is None:
                    sock = socket.create_connection((host, port), timeout=5)
                sock.sendall((line + "\n").encode())
            STATS["sent"] += 1
            STATS["last_ok_ts"] = datetime.now().strftime("%F %T")
        except Exception as e:
            STATS["failed"] += 1
            STATS["last_error"] = str(e)[:120]
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
            sock = None
            Q.put(line) if Q.qsize() < 500 else None   # 重入队（限量防雪崩）
            time.sleep(3)


def start():
    global _thread
    if _thread and _thread.is_alive():
        return
    _thread = threading.Thread(target=_sender, daemon=True, name="nb-syslog")
    _thread.start()


def test_message(server: str, proto: str) -> dict:
    """设置页测试按钮：直发一条测试消息"""
    try:
        host, port = server.split(":")
        _ts = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
        _ts = _ts[:-2] + ":" + _ts[-2:]
        line = f"<142>1 {_ts} nextbastion app - test [test@0] NextBastion Syslog 连通性测试"
        t0 = time.time()
        if proto == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto((line + "\n").encode(), (host, int(port)))
        else:
            with socket.create_connection((host, int(port)), timeout=5) as s:
                s.sendall((line + "\n").encode())
        return {"ok": True, "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}
