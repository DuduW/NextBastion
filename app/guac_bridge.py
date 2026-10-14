"""NextBastion - WS ↔ guacd 桥（guacamole 协议正确时序）
流程：浏览器(guac JS) ↔ WS(binary) ↔ 本桥 ↔ guacd:4822 ↔ RDP
时序：client 发 select.rdp → guacd 回 args.<参数名...> → 本桥按参数名顺序注入值回 connect
之后纯字节透传（前端 guacamole-common.js 全权渲染）。
"""
import asyncio, json, os, re, time

import jwt as pyjwt
from fastapi import WebSocket
from starlette.websockets import WebSocketState

import utils
from config import JWT_SECRET, RECORD_DIR

GUACD_HOST, GUACD_PORT = "127.0.0.1", 4822


def guac_split(data: bytes):
    """解析 guacamole 指令流，返回 [(opcode, [args]), ...]（可能粘包）"""
    instrs, buf = [], data.decode("latin-1")
    i = 0
    while i < len(buf):
        m = re.match(r"(\d+)\.", buf[i:])
        if not m:
            break
        length = int(m.group(1))
        start = i + len(m.group(0))
        element = buf[start:start + length]
        i = start + length + 1  # 跳过分隔 , 或 ;
        if buf[i - 1] == ";":
            instrs.append(("DONE", element))
        # 元素累积在 pending，遇 ; 结束
        instrs.append(("ELEM", element)) if False else None
    return instrs


def parse_guac_instructions(data: bytes):
    """返回完整指令列表：[ [op, a1, a2...], ...]（容忍半包，未完成忽略）"""
    out, elements, buf = [], [], data.decode("latin-1")
    i = 0
    while i < len(buf):
        m = re.match(r"(\d+)\.", buf[i:])
        if not m:
            break
        length = int(m.group(1))
        start = i + m.end()
        if start + length + 1 > len(buf):
            break  # 半包
        val = buf[start:start + length]
        term = buf[start + length]
        elements.append(val)
        i = start + length + 1
        if term == ";":
            out.append(elements)
            elements = []
    return out


def guac_encode_instruction(elements) -> bytes:
    return (",".join(f"{len(e)}.{e}" for e in elements) + ";").encode()


async def ws_guac_bridge(ws: WebSocket, token: str):
    """主入口：/ws/guac/{token}（JWT 同 RDP token；前端持 token 连接）"""
    try:
        info = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        assert info.get("kind") == "rdp"
    except Exception:
        await ws.close(code=4401, reason="invalid rdp token")
        return
    # guacamole 库以子协议 "guacamole" 建 WS——服务端必须回认，否则浏览器立即断开（黑屏根源）
    await ws.accept(subprotocol="guacamole")
    # I3：一次性消费——jti 已用过即拒绝（原子标记）
    if info.get("jti"):
        try:
            used = utils.query("SELECT id FROM audit_logs WHERE action='rdp_token_used' AND target_id=%s LIMIT 1", (info["jti"],), one=True)
            if used:
                await ws.close(code=4401, reason="token already used")
                return
            utils.execute("INSERT INTO audit_logs (actor, action, target_type, target_id, detail) VALUES (%s,'rdp_token_used','rdp_token',%s,'{}')",
                          (str(info.get("uid", "-")), info["jti"]))
        except Exception as e:
            import traceback; traceback.print_exc()

    acc = utils.query("SELECT * FROM asset_accounts WHERE id=%s", (info["acct"],), one=True)
    asset = utils.query("SELECT * FROM assets WHERE id=%s", (info["asset"],), one=True)
    user = utils.query("SELECT * FROM users WHERE id=%s", (info["uid"],), one=True)
    if not (acc and asset and user):
        await ws.close(code=4404, reason="asset/account not found")
        return
    # 复用五维授权（RDP token 只有 60s，二次校验策略仍有效）
    from main import check_access
    if not check_access(user, asset["id"], acc["username"]):
        await ws.close(code=4403, reason="policy denied")
        return
    try:
        secret = utils.decrypt_secret(acc["secret_encrypted"])
    except Exception:
        await ws.close(code=4500, reason="decrypt failed")
        return

    sid = utils.new_session_id()
    # 录像分级目录：<用户名>/<日期>/（guacd recording-path 指向具体日期目录）
    rec_dir = utils.record_subdir(RECORD_DIR, user["username"])
    rec_path = os.path.join(rec_dir, f"{sid}.mkb")

    # ---- 单会话强制：同一资产+账号只允许一个活动 RDP 会话 ----
    # Windows 不支持并发 RDP 桌面会话（新连接会把旧会话顶掉导致旧画面冻结变黑）。
    # 新建前找出旧活动会话：关闭其 WS（桥内记录）→ 会话标记 closed → guacd/Windows 侧随之断开。
    old_rows = utils.query(
        "SELECT id FROM sessions WHERE asset_id=%s AND account_name=%s AND protocol='rdp' AND status='active' AND id!=%s",
        (asset["id"], acc["username"], sid))
    _live_ws = getattr(ws, "app", None)  # FastAPI app 可作全局注册表挂载点
    try:
        from main import app as _app
        _live_ws = getattr(_app, "state", None)
    except Exception:
        _live_ws = None
    registry = None
    if _live_ws is not None:
        registry = getattr(_live_ws, "guac_live_sockets", None)
    if registry:
        for old in old_rows:
            old_ws = registry.pop(old["id"], None)
            if old_ws is not None:
                try:
                    await old_ws.close(code=4409, reason="superseded by new session")
                except Exception:
                    pass
    # 数据库侧旧会话强制归档（若 WS 已死未触发 finally 收尾）
    for old in old_rows:
        utils.execute(
            "UPDATE sessions SET status='closed', ended_at=NOW(), duration_s=TIMESTAMPDIFF(SECOND,started_at,NOW()) WHERE id=%s AND status='active'",
            (old["id"],))

    utils.execute("""INSERT INTO sessions (id, user_id, asset_id, protocol, account_name, client_ip, status, video_file_path)
                     VALUES (%s,%s,%s,'rdp',%s,%s,'active',%s)""",
                  (sid, user["id"], asset["id"], acc["username"],
                   ws.client.host if ws.client else "-", rec_path))
    # 注册本会话 WS（供后续新建会话时踢出）
    if registry is not None:
        registry[sid] = ws

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(GUACD_HOST, GUACD_PORT), timeout=5)
    except Exception as e:
        await ws.send_text(json.dumps({"type": "nb-error", "message": f"guacd 连接失败: {e}"}))
        await ws.close(code=1011)
        return

    # 握手：select rdp
    writer.write(guac_encode_instruction(["select", "rdp"]))
    await writer.drain()
    args_instr = None
    leftover = b""      # args 之后同批到达的指令（可能含 ready/img）——绝不能丢
    try:
        data = b""
        # args 指令可能跨多个 TCP 段，循环读至完整
        for _ in range(8):
            data += await asyncio.wait_for(reader.read(8192), timeout=3)
            instrs = parse_guac_instructions(data)
            if instrs and instrs[0][0] == "args":
                args_instr = instrs[0]
                # 用重编码精确计算 args 指令占用字节数（避免手算误差）
                args_wire = guac_encode_instruction(first)
                idx = data.find(args_wire)
                leftover = data[idx + len(args_wire):] if idx >= 0 else b""
                break
    except Exception:
        pass
    if not args_instr:
        await ws.send_text(json.dumps({"type": "nb-error", "message": "guacd 未返回参数列表"}))
        await ws.close(code=1011)
        return
    with open("/tmp/guac_args.log", "a") as f:
        f.write(repr(args_instr) + "\n")

    # 按 guacd 给的参数名顺序填值（guac 官方 rdp 参数）
    # P0-2：取全部命中策略的会话配置并集（剪贴板/磁盘映射——任一策略开启即放行）
    rdp_cfg = {}
    try:
        from main import merged_session_config
        rdp_cfg = merged_session_config(user, asset["id"], acc["username"])
    except Exception:
        pol = check_access(user, asset["id"], acc["username"])
        if pol and pol["rdp_session_config"]:
            try:
                rdp_cfg = json.loads(pol["rdp_session_config"]) or {}
            except Exception:
                rdp_cfg = {}
    # 剪贴板/磁盘映射：默认禁用（安全默认），策略显式开启才放行
    no_clip = "false" if rdp_cfg.get("clipboard") is True else "true"
    drive_on = rdp_cfg.get("drive") is True
    # 磁盘映射目录：每用户独立（/opt/nextbastion/drives/<用户名>/），自动创建
    drive_dir = ""
    if drive_on:
        _duser = re.sub(r"[^\w.-]", "_", (user.get("username") or "unknown"))
        drive_dir = f"/opt/nextbastion/drives/{_duser}"
        os.makedirs(drive_dir, exist_ok=True)

    # 会话分辨率：token 内嵌的用户真实屏幕尺寸（无则 1280x720）
    ses_w = str(info.get("sw") or 1280)
    ses_h = str(info.get("sh") or 720)

    value_map = {
        "hostname": asset["ip"], "port": str(asset["rdp_port"]),
        "username": acc["username"], "password": secret,
        "security": "nla", "ignore-cert": "true", "cert-ignore": "true",
        "resize": "none",
        "color-depth": "24", "dpi": "96",
        "width": ses_w, "height": ses_h,
        "audio": "", "video": "", "image": "image/jpeg",
        "server-layout": "", "read-only": "", "domain": "",
        "console": "", "initial-program": "", "timezone": "",
        "enable-font-smoothing": "true", "enable-wallpaper": "true",
        # ---- 录像（P0-1；分级目录 用户名/日期）----
        "recording-path": rec_dir,
        "recording-name": f"{sid}.mkb",
        "create-recording-path": "true",
        # ---- RDP 会话策略（P0-2；磁盘映射=guacd 文件传输通道，默认禁用）----
        "disable-copy": no_clip, "disable-paste": no_clip,
        "enable-drive": "true" if drive_on else "false",
        "drive-name": "NB-" + (re.sub(r"[^\w-]", "", (user.get("username") or "user")) or "user")[:12],
        "drive-path": drive_dir,
        "create-drive-path": "true" if drive_on else "",
        "disable-download": "false" if drive_on else "true",
        "disable-upload": "false" if drive_on else "true",
    }
    # 参数名列表
    arg_names = [n for n in args_instr[1:] if n]

    # ===== 架构（对齐官方 Guacamole WebSocket tunnel servlet）=====
    # 官方部署中，服务端中间层完成与 guacd 的全部握手（select→args→size→connect），
    # 之后把 guacd 流原样推给浏览器；浏览器库被动接收 ready/img，仅回传键鼠/sync。
    # 桥在此代发 size/audio/video/image + connect（注入凭据），前端一切握手指令吞掉。
    for instr in (
        guac_encode_instruction(["size", ses_w, ses_h, "96"]),
        guac_encode_instruction(["audio"]),
        guac_encode_instruction(["video"]),
        guac_encode_instruction(["image", "image/jpeg"]),
    ):
        writer.write(instr)
    values = []
    for name in arg_names:
        if name.startswith("VERSION_"):
            values.append(name)
        else:
            values.append(value_map.get(name, ""))
    writer.write(guac_encode_instruction(["connect"] + values))
    await writer.drain()

    closed = {"flag": False}

    async def guac_to_ws():
        try:
            # 先补发握手阶段同批到达但被 args 读取消费掉的剩余指令（可能含关键的首个 sync/ready 前置流）
            if leftover:
                await ws.send_text(leftover.decode("latin-1"))
            while not closed["flag"]:
                data = await reader.read(8192)
                if not data:
                    break
                # guacamole 前端库按字符串解析 onmessage —— 必须发文本帧
                await ws.send_text(data.decode("latin-1"))
        except Exception:
            pass
        finally:
            closed["flag"] = True

    # 前端指令流处理：吞掉全部握手指令（桥已代发），只放行运行期指令
    swallowed = {"b": b""}
    HANDSHAKE_OPS = {"select", "connect", "disconnect"}

    async def ws_to_guac():
        try:
            while not closed["flag"]:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                raw = msg.get("bytes") or (msg.get("text") or "").encode("latin-1")
                if not raw:
                    continue
                buf = swallowed["b"] + raw
                passthrough = b""
                j = 0
                while True:
                    # 解析一条完整指令（多元素，以 ; 结尾）
                    m = re.match(rb"(\d+)\.", buf[j:])
                    if not m:
                        break
                    pos = j
                    parts = []
                    complete = False
                    while True:
                        m2 = re.match(rb"(\d+)\.", buf[pos:])
                        if not m2:
                            break
                        L2 = int(m2.group(1)); s2 = pos + m2.end()
                        if s2 + L2 + 1 > len(buf):
                            break
                        parts.append(buf[s2:s2+L2])
                        term = buf[s2+L2:s2+L2+1]
                        pos = s2 + L2 + 1
                        if term == b";":
                            complete = True
                            break
                    if not complete:
                        break
                    name = parts[0].decode("latin-1", "ignore") if parts else ""
                    if name in HANDSHAKE_OPS:
                        pass  # 握手已由桥代发完成（size/audio/video/image 透传给 guacd 无害，guacd 会忽略）
                    else:
                        passthrough += b",".join(b"%d.%s" % (len(p), p) for p in parts) + b";"
                    j = pos
                swallowed["b"] = buf[j:]
                if passthrough:
                    writer.write(passthrough); await writer.drain()
        except Exception:
            import traceback; traceback.print_exc()
        finally:
            closed["flag"] = True

    t1 = asyncio.create_task(guac_to_ws())
    t2 = asyncio.create_task(ws_to_guac())
    try:
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        closed["flag"] = True
        t1.cancel(); t2.cancel()
        # 注销本会话
        try:
            from main import app as _app
            getattr(getattr(_app, "state", None), "guac_live_sockets", {}).pop(sid, None)
        except Exception:
            pass
        try: writer.close()
        except Exception: pass
        try:
            rec_exists = os.path.exists(rec_path) and os.path.getsize(rec_path) > 0
            video_path = rec_path if rec_exists else ""
            utils.execute("UPDATE sessions SET status='closed', ended_at=NOW(), duration_s=TIMESTAMPDIFF(SECOND,started_at,NOW()), video_file_path=%s WHERE id=%s",
                          (video_path, sid))
        except Exception:
            pass
        try:
            if ws.client_state != WebSocketState.DISCONNECTED:
                await ws.close()
        except Exception:
            pass
