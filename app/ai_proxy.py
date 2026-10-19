"""AI 辅助分析代理（V1.8）· 后端核心

- /api/v1/ai/chat：SSE 流式转发内网 LLM（OpenAI 兼容）
- 上下文包（context_pack）由后端按句柄组装——防前端伪造越权上下文
- 发送前脱敏（简单列名/值规则；V1.7 F3 完整规则落地后切换同源实现）
- 全量审计（command_logs，action='ai_query'）
- 系统提示词按场景注入（sql/dashboard/ssh_linux/netdev/rdp）
"""
import json
import re
import time
import urllib.request

import utils

# V1.9 P3 瘦身：短提示词=快 TTFT（原 5 行压至 1 行）
SCENE_PROMPTS = {
    "sql": "NextBastion SQL 助手：解释/优化 MySQL、分析结果、NL2SQL。中文，简洁，SQL 用代码块，答案≤300字优先。",
    "dashboard": "堡垒机安全助手：基于高危/登录/会话数据做日报、归因、处置建议。中文条目化，简洁。",
    "ssh_linux": "Linux 运维助手：解释终端输出与排障建议（命令仅建议不代执行）。中文，命令用代码块，简洁。",
    "netdev": "网络设备 CLI 助手（华为/H3C/思科）：解释输出、给 display 族命令；提醒 undo/shutdown/reload 属告警命令。中文简洁。",
    "rdp": "Windows 运维助手：基于事件日志（4625/4740 等）做归因与处置建议（仅建议）。中文简洁。",
}

# 敏感值脱敏（列名/键名模式 → 处理）；值级规则（手机号/身份证/卡号）
_KEY_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|private[_-]?key)", re.I)
_PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d(?=\d{4}\D|\d{4}$)\d{4}(\d{4})(?!\d)")   # 保留前三后四在下述函数实现
_IDCARD_RE = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
_BANK_RE = re.compile(r"(?<!\d)\d{16,19}(?!\d)")


def mask_value(v: str) -> str:
    v = str(v)
    if len(v) <= 4:
        return "****"
    return v[:3] + "****" + v[-4:]


def mask_text(text: str) -> str:
    """文本级脱敏：手机号/身份证/长卡号 + 'password: xxx' 键值对打码"""
    if not text:
        return text
    def _phone(m):
        s = m.group(0)
        return s[:3] + "****" + s[-4:] if len(s) == 11 else s
    text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", _phone, text)
    text = _IDCARD_RE.sub(lambda m: m.group(0)[:4] + "***********" + m.group(0)[-2:], text)
    text = _BANK_RE.sub(lambda m: mask_value(m.group(0)), text)
    # 键值形态 password=xxx / "password": "xxx"
    text = re.sub(rf"({_KEY_RE.pattern}\s*[:=]\s*)['\"]?([^\s'\",;]+)",
                  lambda m: m.group(1) + "****", text, flags=re.I)
    return text


def get_ai_config() -> dict:
    """读取系统设置 → AI 模型连接（main 的 audit 存储）"""
    row = utils.query("SELECT detail FROM audit_logs WHERE action='ai_model_config' ORDER BY id DESC LIMIT 1", one=True)
    try:
        cfg = json.loads(row["detail"]) if row else {}
    except Exception:
        cfg = {}
    if not cfg.get("enabled"):
        return {}
    return cfg


def build_context_pack(scene: str, handle: dict, user: dict) -> str:
    """后端按句柄组装上下文（前端只传 handle，防伪造）"""
    parts = []
    # SQL 会话句柄：fsid → 取最近语句与结果摘要
    if scene == "sql" and handle.get("fsid"):
        # 从 command_logs 取该会话最近 3 条语句（已是审计侧数据）
        rows = utils.query(
            "SELECT command_text, action FROM command_logs WHERE session_id=%s ORDER BY id DESC LIMIT 3",
            (handle["fsid"],))
        if rows:
            parts.append("【最近执行的 SQL】\n" + "\n".join(
                f"- {r['command_text'][:200]}（{r['action']}）" for r in reversed(rows)))
    if handle.get("selection"):
        parts.append("【用户选中的内容】\n" + mask_text(handle["selection"][:4000]))
    if handle.get("schema_hint"):
        parts.append("【相关表结构（节选）】\n" + mask_text(handle["schema_hint"][:2000]))
    return "\n\n".join(parts)


# ---- V1.9 P1 语义缓存：问题+场景+effort 归一化哈希 → 答案缓存（LRU 200 / 24h） ----
import hashlib
import threading

_AI_CACHE = {}          # key -> {"answer": str, "ts": float}
_AI_CACHE_ORDER = []
_AI_CACHE_LOCK = threading.Lock()
CACHE_TTL = 86400
CACHE_MAX = 200


def _cache_key(scene: str, question: str, effort) -> str:
    norm = re.sub(r"\s+", "", (question or "").lower())
    return hashlib.md5(f"{scene}|{effort or 'low'}|{norm}".encode()).hexdigest()


def _cache_get(key):
    import time as _t
    with _AI_CACHE_LOCK:
        ent = _AI_CACHE.get(key)
        if ent and _t.time() - ent["ts"] < CACHE_TTL:
            return ent["answer"]
        if ent:
            _AI_CACHE.pop(key, None)
    return None


def _cache_put(key, answer):
    with _AI_CACHE_LOCK:
        if key in _AI_CACHE_ORDER:
            _AI_CACHE_ORDER.remove(key)
        _AI_CACHE_ORDER.append(key)
        while len(_AI_CACHE_ORDER) > CACHE_MAX:
            old = _AI_CACHE_ORDER.pop(0)
            _AI_CACHE.pop(old, None)
        _AI_CACHE[key] = {"answer": answer, "ts": time.time()}


# ---- V1.9 P2 连接策略：每请求新建（流式读取/取消中断下长连接复用会 ResponseNotReady，
#      实测 TLS 握手在内网网关仅 ~50ms，稳定性优先） ----
def _get_conn(base_url):
    import http.client
    from urllib.parse import urlparse
    u = urlparse(base_url)
    return http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=120)


def stream_chat(scene: str, question: str, context_pack: str, history: list, effort: str = None,
                quick: bool = False):
    """生成器：逐段 yield SSE data。
    V1.9：缓存命中直接回放；长连接复用；quick=True 限 max_tokens=800。"""
    import time as _t
    cfg = get_ai_config()
    if not cfg or not cfg.get("base_url"):
        yield {"error": "AI 未配置或未启用（系统设置 → AI 模型连接）"}
        return

    # P1 缓存（quick 动作与自由提问都参与；上下文包不同则不命中——键含场景/effort/问题）
    key = _cache_key(scene, question, effort)
    hit = _cache_get(key)
    if hit:
        # 分块回放（保持流式观感，~30ms/块）
        for i in range(0, len(hit), 24):
            yield {"delta": hit[i:i + 24], "cached": True}
            _t.sleep(0.03)
        return

    msgs = [{"role": "system", "content": SCENE_PROMPTS.get(scene, SCENE_PROMPTS["ssh_linux"])}]
    for h in (history or [])[-6:]:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            msgs.append({"role": h["role"], "content": mask_text(str(h["content"])[:2000])})
    user_content = question if not context_pack else f"{context_pack}\n\n【用户问题】\n{question}"
    msgs.append({"role": "user", "content": mask_text(user_content[:8000])})

    # P4 快捷动作限长（直答场景 800 token 足够，短输出=快结束）
    max_tok = 800 if quick else int(cfg.get("max_tokens") or 4096)
    body = {
        "model": cfg.get("model") or "glm-5.3",
        "messages": msgs,
        "max_tokens": max_tok,
        "temperature": float(cfg.get("temperature") or 0.3),
        "stream": True,
        "reasoning_effort": effort or cfg.get("reasoning_effort") or "low",
    }
    payload = json.dumps(body).encode()

    # P2 长连接
    from urllib.parse import urlparse
    u = urlparse(cfg["base_url"].rstrip("/"))
    path = (cfg["base_url"].rstrip("/") + "/chat/completions").replace(u.scheme + "://" + u.netloc, "")
    headers = {"Content-Type": "application/json"}
    if cfg.get("api_key"):
        headers["Authorization"] = "Bearer " + cfg["api_key"]
    try:
        conn = _get_conn(cfg["base_url"].rstrip("/"))
        conn.request("POST", path, body=payload, headers=headers)
        resp = conn.getresponse()
        if resp.status >= 400:
            body_txt = resp.read().decode("utf-8", "replace")[:200]
            conn.close()
            yield {"error": f"AI 上游错误 HTTP {resp.status}: {body_txt}"}
            return
    except Exception as e:
        try:
            conn.close()
        except Exception:
            pass
        yield {"error": f"AI 连接失败：{type(e).__name__}: {str(e)[:100]}"}
        return

    t0 = time.time()
    answer_parts = []
    ttft = None
    try:
        while True:
            line = resp.readline()
            if not line:
                break
            line = line.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
                delta = obj["choices"][0].get("delta", {})
                content = delta.get("content")
                reasoning = delta.get("reasoning_content")
                if content or reasoning:
                    if ttft is None:
                        ttft = time.time() - t0
                    if content:
                        answer_parts.append(content)
                        yield {"delta": content, "ttft": round(ttft, 2)}
                        ttft = None   # 只在首块带
                if reasoning:
                    yield {"reasoning": reasoning}
            except Exception:
                continue
    except GeneratorExit:
        # P5 取消传播：客户端断开 → 关闭上游连接（中止模型生成）
        try:
            conn.close()
        except Exception:
            pass
        raise
    if answer_parts:
        _cache_put(key, "".join(answer_parts))
