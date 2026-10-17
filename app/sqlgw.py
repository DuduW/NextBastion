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


def open_sql_session(user: dict, asset: dict, account: dict, read_only: bool) -> str:
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
    return fsid


def _sess(fsid: str) -> dict:
    s = SQL_SESSIONS.get(fsid)
    if not s:
        raise KeyError("sql session not found")
    return s


def close_sql_session(fsid: str):
    s = SQL_SESSIONS.pop(fsid, None)
    if s:
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
    # 1) 只读写语句拦截
    check_write(sql_text, s["read_only"], fsid)
    # 2) 高危规则拦截（MySQL 高危规则集）
    action, rule = (match_fn(sql_text) if match_fn else ("allow", None))
    if action == "block":
        _audit(s, sql_text, rule, "block", 0, time.time() - t0)
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
        raise RuntimeError(f"MySQL: {str(e)[:200]}")
    _audit(s, sql_text, rule if action in ("block", "alert") else None, action,
           out.get("affected", 0), out["elapsed"])
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
