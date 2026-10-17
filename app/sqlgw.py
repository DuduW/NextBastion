"""MySQL 远程接入网关（Web SQL 终端后端）· V1.4

会话模型：fsid → {conn, user, asset, account, read_only}
- 只读会话：连接即 SET SESSION TRANSACTION READ ONLY（DB 层硬约束）
- 前置拦截：高危 SQL 在到达 MySQL 前阻断（复用 command_filters 规则集）
- 审计：全量语句入 command_logs（关联 session，含影响行数/耗时）
- 限额：语句超时 / 结果 1000 行截断
"""
import asyncio
import json
import re
import time

import pymysql

import utils

SQL_SESSIONS = {}          # fsid → session dict
SQL_TIMEOUT = 30           # 语句执行超时（秒）
SQL_MAX_ROWS = 1000        # 结果截断行数
WRITE_RE = re.compile(r"^\s*(insert|update|delete|replace|create|drop|alter|truncate|rename|grant|revoke|lock|call|load)\b", re.I)
SELECT_ONLY_HINT = "⛔ 只读会话：当前授权未包含「SQL 写入」，写语句已被前置拦截（未到达数据库）"

# ---- SQL 流水录像（asciicast v2，复用 SSH 的监视/回放通道）----
CAST_HEADER = {"version": 2, "width": 160, "height": 50,
               "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"}}


def _cast_open(s: dict, fsid: str, cast_dir: str):
    """为 SQL 会话创建 cast 文件（语句+结果渲染成终端帧）"""
    import os, json as _json
    os.makedirs(cast_dir, exist_ok=True)
    path = os.path.join(cast_dir, f"{fsid}.cast")
    f = open(path, "w", encoding="utf-8")
    hdr = dict(CAST_HEADER); hdr["timestamp"] = int(time.time())
    f.write(_json.dumps(hdr) + "\n"); f.flush()
    s["cast_f"] = f
    s["cast_t0"] = time.time()
    s["cast_path"] = path
    _cast_write(s, f"\x1b[32m[NextBastion SQL 会话] {s['user'].get('username','?')} → "
                   f"{s['asset'].get('hostname','?')} · 账号 {s['account'].get('username','?')} · "
                   f"{'只读' if s['read_only'] else '读写'} · 全程 SQL 流水录像\x1b[0m\r\n")


def _cast_write(s: dict, text: str):
    """追加一帧输出（终端转义文本）"""
    import json as _json
    f = s.get("cast_f")
    if not f:
        return
    try:
        f.write(_json.dumps([round(time.time() - s["cast_t0"], 3), "o", text]) + "\n")
        f.flush()
    except Exception:
        pass


def _cast_close(s: dict):
    f = s.pop("cast_f", None)
    if f:
        try:
            f.close()
        except Exception:
            pass


def render_sql_frame(sql_text: str, result: dict = None, error: str = None) -> str:
    """SQL 语句+执行结果 → 终端帧文本（ANSI 着色）"""
    lines = [f"\x1b[1;36mmysql>\x1b[0m {sql_text[:400]}"]
    if error:
        lines.append(f"\x1b[31m{error[:300]}\x1b[0m")
    elif result:
        cols = result.get("cols") or []
        rows = result.get("rows") or []
        if cols:
            lines.append(" | ".join(str(c) for c in cols))
            lines.append("-" * min(120, len(" | ".join(str(c) for c in cols))))
            for r in rows[:50]:
                lines.append(" | ".join(str(r.get(c, ""))[:60] for c in cols))
            if len(rows) > 50:
                lines.append(f"... 共 {len(rows)} 行（录像展示前 50）")
        else:
            lines.append(f"\x1b[33mQuery OK, {result.get('affected', 0)} rows affected "
                         f"({result.get('elapsed', 0)}s){' · ⚠ 告警: ' + result['rule'] if result.get('action') == 'alert' else ''}\x1b[0m")
    lines.append("")
    return "\r\n".join(lines)


def open_sql_session(user: dict, asset: dict, account: dict, read_only: bool,
                     cast_dir: str = None) -> str:
    secret = utils.decrypt_secret(account["secret_encrypted"])
    conn = pymysql.connect(
        host=asset["ip"], port=asset.get("sql_port") or asset.get("ssh_port") or 3306,
        user=account["username"], password=secret,
        database=asset.get("initial_db") or None,
        connect_timeout=8, read_timeout=SQL_TIMEOUT, write_timeout=SQL_TIMEOUT,
        charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    if read_only:
        with conn.cursor() as c:
            c.execute("SET SESSION TRANSACTION READ ONLY")
    fsid = utils.new_session_id()
    SQL_SESSIONS[fsid] = {"conn": conn, "user": user, "asset": asset,
                          "account": account, "read_only": read_only,
                          "ts": time.time(), "session_id": None}
    if cast_dir:
        _cast_open(SQL_SESSIONS[fsid], fsid, cast_dir)
    return fsid


def _sess(fsid: str) -> dict:
    s = SQL_SESSIONS.get(fsid)
    if not s:
        raise KeyError("sql session not found")
    return s


def close_sql_session(fsid: str):
    s = SQL_SESSIONS.pop(fsid, None)
    if s:
        _cast_write(s, "\r\n\x1b[32m[NextBastion] SQL 会话已结束\x1b[0m\r\n")
        _cast_close(s)
        try:
            s["conn"].close()
        except Exception:
            pass


def check_write(sql_text: str, read_only: bool, fsid: str):
    """只读会话写语句前置拦截（到达 DB 前）"""
    if read_only and WRITE_RE.match(sql_text):
        s = _sess(fsid)
        if s.get("session_id"):
            try:
                utils.execute(
                    "INSERT INTO command_logs (session_id,user_id,asset_id,command_text,matched_rule,action,risk_level) "
                    "VALUES (%s,%s,%s,%s,%s,'block','high')",
                    (s["session_id"], s["user"]["id"], s["asset"]["id"],
                     sql_text[:500], "readonly-session"))
            except Exception:
                pass
        raise PermissionError(SELECT_ONLY_HINT)


def run_query(fsid: str, sql_text: str, match_fn=None):
    """执行 SQL：前置拦截（只读+高危规则）→ 执行 → 分页结果 + 审计。
    match_fn(cmdline) → (action, rule)（由 main.match_filter 注入）"""
    s = _sess(fsid)
    sql_text = (sql_text or "").strip().rstrip(";")
    if not sql_text:
        return {"cols": [], "rows": [], "affected": 0, "elapsed": 0, "truncated": False}
    t0 = time.time()
    # 1) 只读写语句拦截（写录像帧后抛出）
    try:
        check_write(sql_text, s["read_only"], fsid)
    except PermissionError as e:
        _cast_write(s, render_sql_frame(sql_text, error=str(e)))
        raise
    # 2) 高危规则拦截（MySQL 高危规则集）
    action, rule = (match_fn(sql_text) if match_fn else ("allow", None))
    if action == "block":
        _audit(s, sql_text, rule, "block", 0, time.time() - t0)
        _cast_write(s, render_sql_frame(sql_text, error=f"⛔ 高危 SQL 已阻断（规则: {rule}）"))
        raise PermissionError(f"⛔ 高危 SQL 已阻断（规则: {rule}）· 已告警管理员")
    # 3) 执行
    try:
        with s["conn"].cursor() as c:
            c.execute(sql_text)
            if c.description:      # SELECT 类：结果集
                rows = c.fetchmany(SQL_MAX_ROWS)
                cols = [d[0] for d in c.description]
                more = True
                try:
                    more = c.fetchone() is not None
                except Exception:
                    more = False
                out = {"cols": cols, "rows": [_jsonable(r) for r in rows],
                       "affected": len(rows), "elapsed": round(time.time() - t0, 3),
                       "truncated": more, "action": action, "rule": rule}
            else:                  # 写/DDL 类
                out = {"cols": [], "rows": [], "affected": s["conn"].affected_rows(),
                       "elapsed": round(time.time() - t0, 3), "truncated": False,
                       "action": action, "rule": rule}
    except PermissionError:
        raise
    except Exception as e:
        _audit(s, sql_text, None, "error", 0, time.time() - t0, err=str(e)[:120])
        _cast_write(s, render_sql_frame(sql_text, error=f"ERROR: {str(e)[:150]}"))
        raise RuntimeError(f"MySQL: {str(e)[:200]}")
    _audit(s, sql_text, rule if action in ("block", "alert") else None, action,
           out.get("affected", 0), out["elapsed"])
    _cast_write(s, render_sql_frame(sql_text, result=out))
    return out


def _jsonable(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        if isinstance(v, (bytes, bytearray)):
            v = f"<binary {len(v)}B>"
        elif hasattr(v, "isoformat"):
            v = v.isoformat(sep=" ")
        out[k] = v
    return out


def _audit(s: dict, sql_text: str, rule, action: str, affected: int, elapsed: float, err=None):
    if not s.get("session_id"):
        return
    risk = "high" if action == "block" else ("mid" if action == "alert" else "low")
    try:
        utils.execute(
            "INSERT INTO command_logs (session_id,user_id,asset_id,command_text,matched_rule,action,risk_level) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (s["session_id"], s["user"]["id"], s["asset"]["id"], sql_text[:500],
             rule or (f"err:{err}" if err else None), action, risk))
    except Exception:
        pass


def schema_tree(fsid: str, max_tables=300) -> list:
    """库/表元数据（左侧树）。注意 MySQL 8.0 information_schema 列名为大写。"""
    s = _sess(fsid)
    with s["conn"].cursor() as c:
        c.execute("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA "
                  "WHERE SCHEMA_NAME NOT IN ('performance_schema','sys') ORDER BY SCHEMA_NAME")
        dbs = [r.get("SCHEMA_NAME") or r.get("schema_name") for r in c.fetchall()]
        tree = []
        for db in dbs[:50]:
            c.execute("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s "
                      "ORDER BY TABLE_NAME LIMIT %s", (db, max_tables))
            tree.append({"db": db, "tables": [r.get("TABLE_NAME") or r.get("table_name") for r in c.fetchall()]})
        return tree
