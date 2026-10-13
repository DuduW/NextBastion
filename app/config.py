"""NextBastion 堡垒机 - 配置模块"""
import os

DB_CONFIG = {
    "host": os.getenv("NB_DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("NB_DB_PORT", "3306")),
    "user": os.getenv("NB_DB_USER", "nextbastion"),
    "password": os.getenv("NB_DB_PASS", "ChangeMe@2026"),
    "database": os.getenv("NB_DB_NAME", "nextbastion"),
    "charset": "utf8mb4",
}

JWT_SECRET = os.getenv("NB_JWT_SECRET", "change-me-in-production-9f8e7d6c")
JWT_ALGO = "HS256"
ACCESS_TOKEN_TTL = 30 * 60          # 30 min
REFRESH_TOKEN_TTL = 7 * 24 * 3600   # 7 d

# 凭据加密密钥（32 字节 hex）——生产必须用环境变量覆盖
CRED_KEY_HEX = os.getenv("NB_CRED_KEY", "a3f1b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80")

# RDP 一次性 token 有效期（秒）
RDP_TOKEN_TTL = 60

# 录像目录
RECORD_DIR = os.getenv("NB_RECORD_DIR", "/opt/nextbastion/records")

# 高危命令规则库（默认，可被 DB 中 command_filters 覆盖）
DEFAULT_FILTER_RULES = [
    {"regex": r"rm\s+-rf\s+/", "action": "block", "name": "递归删除根"},
    {"regex": r"\bshutdown\b", "action": "block", "name": "关机"},
    {"regex": r"\breboot\b", "action": "block", "name": "重启"},
    {"regex": r"\binit\s+0\b", "action": "block", "name": "init 0"},
    {"regex": r"drop\s+database", "action": "block", "name": "DROP DATABASE", "icase": True},
    {"regex": r"\bmkfs", "action": "block", "name": "格式化"},
    {"regex": r"userdel\s+root", "action": "block", "name": "删除root"},
    {"regex": r"chmod\s+(-R\s+)?777", "action": "alert", "name": "目录777"},
    {"regex": r"iptables\s+-F", "action": "alert", "name": "清空防火墙"},
    {"regex": r"truncate\s+table", "action": "alert", "name": "TRUNCATE", "icase": True},
]
