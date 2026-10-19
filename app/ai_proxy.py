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

SCENE_PROMPTS = {
    "sql": "你是 NextBastion 堡垒机 SQL 终端的 AI 助手。帮用户解释/优化 MySQL 语句、分析查询结果与报错、生成 NL2SQL。"
           "回答用简体中文、简洁专业；SQL 放在代码块中；优化建议给出预估收益；生成的任何 SQL 仍受堡垒机权限级别约束。",
    "dashboard": "你是 NextBastion 堡垒机安全运营 AI 助手。基于提供的高危命令/登录/会话统计做安全日报、异常归因（如爆破识别）与处置建议。回答用简体中文，条目化输出。",
    "ssh_linux": "你是 Linux 运维 AI 助手。基于用户选中的终端输出做解释与故障排查建议（命令仅建议，不可代执行）。回答用简体中文，命令放代码块。",
    "netdev": "你是网络设备（华为/H3C/思科等 VRP/Comware/IOS CLI）运维 AI 助手。解释 CLI 输出、提示当前视图状态、给出 display 族查询命令；"
              "提醒 undo/shutdown/reload 等属于堡垒机告警/阻断命令。回答用简体中文。",
    "rdp": "你是 Windows 服务器运维 AI 助手。基于提供的 Windows 事件日志（4624/4625/4740/7036 等）与会话审计做安全归因和处置步骤建议（仅建议，人工执行）。回答用简体中文。",
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


def stream_chat(scene: str, question: str, context_pack: str, history: list):
    """生成器：逐段 yield SSE data。history 为 [{role,content}]（服务端已限长）。"""
    cfg = get_ai_config()
    if not cfg or not cfg.get("base_url"):
        yield {"error": "AI 未配置或未启用（系统设置 → AI 模型连接）"}
        return
    msgs = [{"role": "system", "content": SCENE_PROMPTS.get(scene, SCENE_PROMPTS["ssh_linux"])}]
    for h in (history or [])[-6:]:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            msgs.append({"role": h["role"], "content": mask_text(str(h["content"])[:2000])})
    user_content = question if not context_pack else f"{context_pack}\n\n【用户问题】\n{question}"
    msgs.append({"role": "user", "content": mask_text(user_content[:8000])})

    payload = json.dumps({
        "model": cfg.get("model") or "glm-5.3",
        "messages": msgs,
        "max_tokens": int(cfg.get("max_tokens") or 4096),
        "temperature": float(cfg.get("temperature") or 0.3),
        "stream": True,
        # V1.8.1 性能：low=不思考直答（正文 0.8s 起流）high=深度思考（复杂分析，正文延迟 20s+）
        "reasoning_effort": cfg.get("reasoning_effort") or "low",
    }).encode()
    req = urllib.request.Request(cfg["base_url"].rstrip("/") + "/chat/completions",
                                 data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    if cfg.get("api_key"):
        req.add_header("Authorization", "Bearer " + cfg["api_key"])
    try:
        resp = urllib.request.urlopen(req, timeout=120)
    except Exception as e:
        yield {"error": f"AI 连接失败：{type(e).__name__}: {str(e)[:100]}"}
        return
    for raw in resp:
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            obj = json.loads(data)
            delta = obj["choices"][0].get("delta", {})
            content = delta.get("content")
            if content:
                yield {"delta": content}
            reasoning = delta.get("reasoning_content")
            if reasoning:
                yield {"reasoning": reasoning}
        except Exception:
            continue
