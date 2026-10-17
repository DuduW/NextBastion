"""网络设备（交换机/路由器）SSH 接入支持 · V1.4

device_type 驱动：
- 提示符正则（CLI 命令切分审计）
- 免分页命令（连接后自动下发）
- enable 升权方式（华为/H3C 与思科系不同）
"""
import re

# ---- 设备类型注册表 ----
DEVICE_TYPES = {
    "linux":   {"label": "🐧 Linux",       "kind": "ssh",    "pager": None, "prompt": r"\$|#\s*$"},
    "windows": {"label": "🖥️ Windows",     "kind": "rdp",    "pager": None, "prompt": None},
    "huawei":  {"label": "🌐 华为",        "kind": "netdev", "pager": "screen-length 0 temporary",
                "prompt": r"\[[\w\-\./]+\]#|<[\w\-\./]+>"},
    "h3c":     {"label": "🌐 H3C",         "kind": "netdev", "pager": "screen-length disable",
                "prompt": r"\[[\w\-\./]+\]|<[\w\-\./]+>"},
    "cisco":   {"label": "🌐 思科",        "kind": "netdev", "pager": "terminal length 0",
                "prompt": r"[\w\-\.\(\)]+[#>]\s*$"},
    "ruijie":  {"label": "🌐 锐捷",        "kind": "netdev", "pager": "terminal length 0",
                "prompt": r"[\w\-\.\(\)]+[#>]\s*$"},
    "juniper": {"label": "🌐 Juniper",     "kind": "netdev", "pager": "set cli screen-length 0",
                "prompt": r"[\w\-@:\.]+[>#]\s*$"},
    "mysql":   {"label": "🗄️ MySQL",       "kind": "sql",    "pager": None, "prompt": None},
}

# CLI 命令提取：命中提示符后的整行视为命令输入（供命令审计切分——bash 用回车，CLI 亦回车提交，沿用现有泵层逻辑）
PROMPT_RE = {k: re.compile(v["prompt"]) for k, v in DEVICE_TYPES.items() if v.get("prompt")}

# enable 升权序列（检测到非特权提示符 > 时自动补输）
ENABLE_SEQ = {
    "huawei":  {"detect": ">",  "cmd": "super\n", "password_prompt": ("password", "密码")},
    "h3c":     {"detect": ">",  "cmd": "super\n", "password_prompt": ("password", "密码")},
    "cisco":   {"detect": ">",  "cmd": "enable\n", "password_prompt": ("password",)},
    "ruijie":  {"detect": ">",  "cmd": "enable\n", "password_prompt": ("password",)},
}


def dev_kind(device_type: str) -> str:
    return DEVICE_TYPES.get(device_type or "linux", DEVICE_TYPES["linux"])["kind"]


def is_netdev(device_type: str) -> bool:
    return dev_kind(device_type) == "netdev"


def pager_cmd(device_type: str):
    return DEVICE_TYPES.get(device_type, {}).get("pager")


def enable_conf(device_type: str):
    return ENABLE_SEQ.get(device_type)
