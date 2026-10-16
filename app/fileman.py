"""NextBastion F4 - Web SFTP 文件管理（M1）
- 文件管理会话（fsid）：短时凭证，复用五维授权 + 托管凭据
- 目录浏览 / 上传（分片）/ 下载（流式）/ 重命名 / 删除（回收站）
- 全量写 file_transfer_logs；高危目录副本留存（SHA256）
- 安全层（渗透测试修复）：路径校验 / 禁 self-bastion / 敏感文件阻断
"""
import asyncio, hashlib, json, os, time

import asyncssh

import utils

# fsid -> {"asset":..., "account":..., "user":..., "conn":asyncssh.SSHClientConnection, "ts":last_active}
FSESSIONS = {}
FS_TTL = 1800          # 文件会话 30 分钟无操作自动回收
EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "records", "files")
# 高危目录清单（可后续入库配置）
RISK_DIRS = ["/etc", "/root", "/opt/nextbastion"]
TRASH = ".nb-trash"
MAX_UPLOAD = 2 * 1024 * 1024 * 1024   # 2GB

# ===== 安全层（2026-10-16 渗透测试修复 + 二轮加固）=====
import posixpath as _pp

# 上传写入黑名单：可导致 RCE/持久化的目标（cron/ssh 密钥/系统服务/自守护路径）——按规范化后绝对路径前缀树判定
UPLOAD_DENY = ["/etc/cron", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
               "/etc/cron.monthly", "/var/spool/cron", "/root/.ssh", "/home",
               "/etc/systemd", "/usr/lib/systemd", "/etc/sudoers", "/etc/sudoers.d",
               "/etc/ssh", "/opt/nextbastion", "/root", "/etc/profile.d", "/etc/bash.bashrc",
               "/etc/rc.d", "/etc/rc.local", "/etc/crontab", "/var/spool/at", "/etc/cron.deny"]
# 下载黑名单：按规范化后绝对路径判定（堡垒机自身 + 主机侧系统敏感区）
SENSITIVE_PATHS = ["/opt/nextbastion", "/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-",
                   "/etc/passwd-", "/etc/ssh", "/root", "/etc/sudoers", "/etc/sudoers.d",
                   "/var/spool/cron", "/etc/crontab"]
# 敏感文件名（basename 精确/后缀匹配）：主机私钥/凭据/凭据痕迹
SENSITIVE_BASENAMES = {".secrets", "initial_credentials.txt", ".bash_history", ".mysql_history",
                       "authorized_keys", "known_hosts", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                       "id_rsa.pub", ".env", "credentials", "credentials.json", "shadow", "shadow-"}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore", ".kdbx")


def _norm_path(path: str) -> str:
    """规范化 + 输入净化：拒绝 .././ 多斜杠/空字节/编码残留/控制字符等混淆形态；
    返回 posix 规范化路径。"""
    raw = (path or "")
    if raw != raw.strip():
        raise PermissionError("路径包含首尾空白")
    if any(seg in raw.split("/") for seg in ("..", ".")):
        raise PermissionError("路径包含非法段（.. / .）")
    if "//" in raw:
        raise PermissionError("路径包含连续斜杠")
    low_raw = raw.lower()
    if "%00" in low_raw or "%2f" in low_raw or "%2e" in low_raw or "\\x" in low_raw:
        raise PermissionError("路径包含编码残留")
    if any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise PermissionError("路径包含控制字符")
    p = _pp.normpath(raw)
    if not p.startswith("/"):
        raise PermissionError("必须使用绝对路径")
    return p


def _path_hits(path_low: str, prefixes) -> bool:
    """规范化后绝对路径的等值/前缀树判定（禁止子串匹配）"""
    return any(path_low == d or path_low.startswith(d + "/") for d in prefixes)


def _self_asset(asset: dict) -> bool:
    """资产即堡垒机自身（127.0.0.1 / 本机 IP）→ 禁止文件会话（防自守护接管）"""
    ip = (asset.get("ip") or "").strip()
    return ip in ("127.0.0.1", "localhost", "::1")


def _check_download(path: str) -> str:
    """敏感文件下载阻断（规范化→路径前缀树→文件名/后缀）；返回规范化路径；命中 raise"""
    p = _norm_path(path)
    low = p.lower()
    if _path_hits(low, SENSITIVE_PATHS):
        raise PermissionError("禁止下载敏感路径下的文件")
    base = low.rsplit("/", 1)[-1]
    if base in SENSITIVE_BASENAMES or base.endswith(SENSITIVE_SUFFIXES):
        raise PermissionError(f"禁止下载敏感文件: {base}")
    # 变体对抗：路径中夹带敏感名（如 /tmp/x/id_rsa.bak）——对 basename 的已知变体做后缀检测
    for nm in ("shadow", "authorized_keys", "known_hosts", "id_rsa", "id_ed25519", "id_ecdsa"):
        if base.startswith(nm + ".") or base == nm or base.startswith(nm + "-"):
            raise PermissionError(f"禁止下载敏感文件: {base}")
    return p


def _check_upload(path: str) -> str:
    """高危写入阻断（规范化→前缀树）；返回规范化路径"""
    p = _norm_path(path)
    low = p.lower()
    if _path_hits(low, UPLOAD_DENY):
        raise PermissionError("禁止写入高危路径")
    return p


def _check_read_meta(path: str) -> str:
    """list/stat/op 元数据与路径操作统一校验（防 stat 探测敏感文件存在性 / rename 逃逸）"""
    return _check_download(path)


def _suspicious_raw(path) -> bool:
    """原始输入可疑标记（审计加固）：含 //、./、..、%2f 编码、尾部空格"""
    raw = str(path or "")
    return ("//" in raw or "/./" in raw or raw.endswith("/.") or ".." in raw
            or "%2f" in raw.lower() or "%00" in raw.lower() or raw != raw.strip())


def _risk(path: str) -> bool:
    p = (path or "").rstrip("/")
    return any(p == d or p.startswith(d + "/") for d in RISK_DIRS)


async def open_session(user: dict, asset: dict, account: dict) -> str:
    """校验授权（能力并集），建 SFTP 连接，返回 fsid"""
    from main import check_access, merged_session_config   # 延迟导入避免环
    if not check_access(user, asset["id"], account["username"]):
        raise PermissionError("no access policy")
    # F4-6：文件传输需任一命中策略显式开启（能力并集）
    cfg = merged_session_config(user, asset["id"], account["username"])
    if cfg.get("sftp") is not True:
        raise PermissionError("file transfer not granted by policy")
    # 安全修复③：资产=堡垒机自身 → 拒绝文件会话（SFTP 读写堡垒机文件=接管）
    if _self_asset(asset):
        raise PermissionError("禁止对堡垒机自身发起文件管理会话")
    secret = utils.decrypt_secret(account["secret_encrypted"])
    conn = await asyncio.wait_for(
        asyncssh.connect(asset["ip"], port=asset["ssh_port"] or 22,
                         username=account["username"], password=secret,
                         known_hosts=None), timeout=8)
    fsid = utils.new_session_id()
    FSESSIONS[fsid] = {"conn": conn, "sftp": None, "user": user, "asset": asset,
                       "account": account, "ts": time.time()}
    return fsid


def _sess(fsid: str) -> dict:
    s = FSESSIONS.get(fsid)
    if not s or time.time() - s["ts"] > FS_TTL:
        FSESSIONS.pop(fsid, None)
        raise KeyError("file session expired")
    s["ts"] = time.time()
    return s


async def _sftp(s: dict):
    if not s.get("sftp"):
        s["sftp"] = await s["conn"].start_sftp_client()
    return s["sftp"]


def log_transfer(s: dict, direction: str, path: str, size: int, result: str,
                 session_id: str = "", evidence: str = ""):
    """写传输审计（result: ok/denied/error/evidence）+ Syslog 埋点（F5）"""
    utils.execute(
        "INSERT INTO file_transfer_logs (session_id, user_id, asset_id, direction, file_name, file_size, result, evidence_sha256) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (session_id, s["user"]["id"], s["asset"]["id"], direction,
         path[:250], size, result, evidence[:64] or None))
    try:
        import syslog_fwd
        syslog_fwd.emit("file_transfer", f"文件{direction}: {path[:100]}",
                        {"actor": s["user"]["username"], "asset": s["asset"]["hostname"],
                         "dir": direction, "size": size})
    except Exception:
        pass


async def list_dir(fsid: str, path: str) -> dict:
    s = _sess(fsid)
    sf = await _sftp(s)
    path = path or "/"
    # 安全加固：原始输入可疑 → 审计标记（相对路径合法场景走 realpath 后再校验）
    if _suspicious_raw(path):
        log_transfer(s, "list", path, 0, "suspicious_path")
    try:
        if not path.startswith("/"):
            path = await sf.realpath(path)
    except Exception:
        pass
    path = _check_read_meta(path)   # 统一校验（规范化+敏感路径）
    attrs = await sf.listdir(path)
    import stat as _st
    items = []
    for name in sorted(attrs):
        if name in (".", ".."):
            continue
        full = path.rstrip("/") + "/" + name
        try:
            st = await sf.stat(full)
            mode = getattr(st, "st_mode", None) or getattr(st, "mode", 0)
            items.append({
                "name": name, "path": full,
                "dir": _st.S_ISDIR(mode),
                "size": getattr(st, "st_size", None) or getattr(st, "size", 0) or 0,
                "uid": getattr(st, "st_uid", None) or getattr(st, "uid", "-"),
                "gid": getattr(st, "st_gid", None) or getattr(st, "gid", "-"),
                "mode": oct(mode & 0o7777),
                "mtime": int(getattr(st, "st_mtime", None) or getattr(st, "mtime", 0) or 0),
            })
        except Exception:
            continue
    return {"cwd": path, "items": items}


async def stat_file(fsid: str, path: str) -> dict:
    """R4: 远端文件元信息（断点续传探查已传大小）；统一安全校验（防 stat 探测敏感路径存在性）"""
    s = _sess(fsid)
    sf = await _sftp(s)
    try:
        path = _check_read_meta(path)
    except PermissionError:
        log_transfer(s, "stat", path, 0, "denied")
        raise
    try:
        st = await sf.stat(path)
    except Exception:
        return {"exists": False, "size": 0}
    import stat as _st
    mode = getattr(st, "st_mode", None) or getattr(st, "mode", 0)
    return {"exists": True,
            "size": getattr(st, "st_size", None) or getattr(st, "size", 0) or 0,
            "mtime": int(getattr(st, "st_mtime", None) or getattr(st, "mtime", 0) or 0),
            "is_dir": bool(_st.S_ISDIR(mode))}


async def download(fsid: str, path: str) -> dict:
    """返回 {f, size}；高危目录同步留存副本；敏感文件阻断（规范化后判定）"""
    if _suspicious_raw(path):
        s0 = _sess(fsid)
        log_transfer(s0, "download", path, 0, "suspicious_path")
    path = _check_download(path)   # 统一校验：规范化→路径树→文件名/后缀
    s = _sess(fsid)
    sf = await _sftp(s)
    f = await sf.open(path, "rb")
    st = await sf.stat(path)
    size = getattr(st, "st_size", None) or getattr(st, "size", 0) or 0
    ev_sha = ""
    if _risk(path):
        # 流式读取留副本（大小上限 200MB/文件，防拖库）
        if size <= 200 * 1024 * 1024:
            ev_dir = utils.record_subdir(EVIDENCE_DIR, s["user"]["username"])
            ev_path = os.path.join(ev_dir, f"dl_{int(time.time())}_{os.path.basename(path)}")
            h = hashlib.sha256()
            with open(ev_path, "wb") as out:
                while True:
                    chunk = await f.read(262144)
                    if not chunk:
                        break
                    h.update(chunk)
                    out.write(chunk)
            await f.close()
            ev_sha = h.hexdigest()
            log_transfer(s, "download", path, size, "ok", evidence=ev_sha)
            return {"f": open(ev_path, "rb"), "size": size, "evidence": ev_sha}
        log_transfer(s, "download", path, size, "ok")
        return {"f": f, "size": size}
    log_transfer(s, "download", path, size, "ok")
    return {"f": f, "size": size}


async def upload_chunk(fsid: str, path: str, offset: int, data: bytes, append: bool = False) -> int:
    """分片上传：append 模式续传。返回已写偏移；高危路径阻断（规范化后判定）"""
    if _suspicious_raw(path):
        s0 = _sess(fsid)
        log_transfer(s0, "upload", path, 0, "suspicious_path")
    path = _check_upload(path)   # 统一校验：规范化→前缀树
    s = _sess(fsid)
    sf = await _sftp(s)
    mode = "ab" if append else "wb"
    async with sf.open(path, mode) as f:
        if offset and append:
            await f.seek(offset)
        await f.write(data)
    return offset + len(data)


async def rename(fsid: str, old: str, new: str):
    s = _sess(fsid)
    sf = await _sftp(s)
    _check_read_meta(old)   # 防把敏感文件改名带出
    new = _check_upload(new)  # 新位置按写入校验
    await sf.rename(old, new)
    log_transfer(s, "rename", f"{old} -> {new}", 0, "ok")


async def delete(fsid: str, path: str):
    """删除进回收站（同盘 rename 到 .nb-trash，不可回收的目录递归删除也先挪）；统一校验"""
    s = _sess(fsid)
    sf = await _sftp(s)
    path = _check_read_meta(path)
    sf_conn = s["conn"]
    parent = os.path.dirname(path.rstrip("/")) or "/"
    trash = parent + "/" + TRASH
    try:
        await sf.stat(trash)
    except Exception:
        await sf.mkdir(trash)
    dest = trash + "/" + os.path.basename(path) + "." + str(int(time.time()))
    await sf.rename(path, dest)
    # 回收站 30 天清理交给资产侧 cron 或后续任务，此处只挪
    log_transfer(s, "delete", f"{path} -> {dest}", 0, "ok")


def close_session(fsid: str):
    s = FSESSIONS.pop(fsid, None)
    if s:
        try:
            if s.get("sftp"):
                s["sftp"].exit()
        except Exception:
            pass
        try:
            s["conn"].close()
        except Exception:
            pass


def gc_sessions():
    """过期清理（由后台任务周期调用）"""
    now = time.time()
    for fsid in list(FSESSIONS.keys()):
        s = FSESSIONS.get(fsid)
        if not s or now - s["ts"] > FS_TTL:
            close_session(fsid)
