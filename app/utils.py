"""NextBastion - 公共工具：JWT、密码哈希、凭据加解密、DB 连接"""
import hashlib, hmac, os, re, json, time, base64
from datetime import datetime, timedelta
import pymysql, jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import DB_CONFIG, JWT_SECRET, JWT_ALGO, ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL, CRED_KEY_HEX

# ---------- DB ----------
def db():
    cfg = dict(DB_CONFIG)
    cfg.setdefault('charset', 'utf8mb4')
    return pymysql.connect(**cfg, cursorclass=pymysql.cursors.DictCursor, autocommit=True)

def query(sql, args=None, one=False):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()

def execute(sql, args=None):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            return cur.lastrowid
    finally:
        conn.close()

# ---------- 录像存储 ----------
def record_subdir(base: str, username: str, ts: float = None) -> str:
    """录像分级目录：base/<用户名>/<YYYY-MM-DD>/
    - 用户名做白名单清洗（仅字母数字._-），防路径穿越/特殊字符
    - 目录不存在自动创建；返回绝对目录路径
    """
    safe = re.sub(r'[^\w.-]', '_', (username or 'unknown').strip()) or 'unknown'
    day = time.strftime('%Y-%m-%d', time.localtime(ts))
    d = os.path.join(base, safe, day)
    os.makedirs(d, exist_ok=True)
    return d

# ---------- 密码 ----------
def hash_password(pw: str, salt: str = None) -> str:
    salt = salt or os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(salt), 100_000)
    return f"pbkdf2${salt}${dk.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt, hexdk = stored.split('$')
        dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(salt), 100_000)
        return hmac.compare_digest(dk.hex(), hexdk)
    except Exception:
        return False

# ---------- JWT ----------
def make_token(user_id: int, username: str, role: str, kind='access') -> str:
    ttl = ACCESS_TOKEN_TTL if kind == 'access' else REFRESH_TOKEN_TTL
    payload = {"sub": str(user_id), "username": username, "role": role, "kind": kind,
               "exp": int(time.time()) + ttl}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])

# ---------- 凭据 AES-256-GCM ----------
_aes = AESGCM(bytes.fromhex(CRED_KEY_HEX))

def encrypt_secret(plain: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + _aes.encrypt(nonce, plain.encode(), b'nextbastion')

def decrypt_secret(blob: bytes) -> str:
    return _aes.decrypt(blob[:12], blob[12:], b'nextbastion').decode()

# ---------- 会话 ID ----------
def new_session_id() -> str:
    return datetime.now().strftime('S-%Y%m%d-') + os.urandom(4).hex()

def escape_ldap(s: str) -> str:
    """LDAP filter 特殊字符转义（RFC 4515）"""
    return s.replace('\\', r'\5c').replace('*', r'\2a').replace('(', r'\28') \
            .replace(')', r'\29').replace('\x00', r'\00')

# ---------- 统一响应 ----------
def ok(data=None, message='success'):
    return {"code": 0, "message": message, "data": data}

def err(code, message):
    return {"code": code, "message": message, "data": None}
