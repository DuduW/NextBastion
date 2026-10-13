#!/usr/bin/env bash
# ============================================================
# NextBastion 堡垒机 - 一键部署脚本（Rocky Linux 9 / CentOS 9 / RHEL 9）
#
# 用法:   bash deploy.sh                 # 基础部署（SSH 审计全功能）
#         NB_WITH_RDP=1 bash deploy.sh   # 额外编译 guacd（RDP 图形通道，约 5-10 分钟）
#
# 产物:   /opt/nextbastion/{app,venv,records,logs} + systemd nextbastion.service
#         + Nginx 80 反代 + 运维脚本（LDAP 同步/日志清理）定时器
# 访问:   http://<服务器IP>（初始账号打印在末尾，亦见 /opt/nextbastion/INITIAL_CREDENTIALS.txt）
#
# 可用环境变量:
#   NB_MYSQL_ROOT_PASS  MySQL root 密码（默认 ChangeRoot@2026，首次部署自动设置）
#   NB_DB_PASS          应用库密码    （默认 ChangeMe@2026）
#   NB_ADMIN_PASS       admin 初始密码（默认 Admin@2026）
#   NB_SELF_SSH_PASS    演示资产 self-bastion 的 root 密码（默认 SelfHost@2026）
#   NB_NO_MFA=1         跳过 TOTP 初始化（不推荐）
#   NB_PORT             监听端口（默认 8000）
#   NB_WITH_RDP=1       安装 guacd 1.5.5（RDP 支持）
# ============================================================
set -euo pipefail

APP_DIR="/opt/nextbastion"
VENV="$APP_DIR/venv"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"   # 脚本所在目录即源码目录
MYSQL_ROOT_PASS="${NB_MYSQL_ROOT_PASS:-ChangeRoot@2026}"
NB_DB_PASS_ENV="${NB_DB_PASS:-ChangeMe@2026}"
ADMIN_PASS="${NB_ADMIN_PASS:-Admin@2026}"
NO_MFA="${NB_NO_MFA:-0}"
PORT="${NB_PORT:-8000}"
WITH_RDP="${NB_WITH_RDP:-0}"

log(){ echo -e "\033[1;32m[deploy]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[warn]\033[0m $*"; }

# ---------- 0. 环境检查 ----------
if [[ $EUID -ne 0 ]]; then echo "必须 root 执行"; exit 1; fi
log "NextBastion 一键部署开始 · 源码目录: $SRC_DIR"

# ---------- 1. 系统依赖（幂等） ----------
log "安装系统依赖 (python3.11 mysql-server nginx)"
dnf install -y -q python3.11 python3.11-pip mysql-server nginx firewalld >/dev/null 2>&1 || {
  warn "dnf install 有告警，继续尝试"
}
python3.11 --version

# ---------- 2. MySQL ----------
log "初始化 MySQL"
systemctl enable --now mysqld >/dev/null 2>&1 || systemctl restart mysqld
sleep 2
# 探测 root 空密码或既有密码
if mysql -uroot -e "SELECT 1" >/dev/null 2>&1; then
  mysql -uroot -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';" >/dev/null
elif mysql -uroot -p"${MYSQL_ROOT_PASS}" -e "SELECT 1" >/dev/null 2>&1; then
  : # 已设置
else
  # Rocky9 默认无空密码：从日志取临时密码
  TMP_PASS=$(grep 'temporary password' /var/log/mysqld.log 2>/dev/null | awk '{print $NF}' | tail -1)
  if [[ -z "$TMP_PASS" ]]; then echo "无法获取 MySQL root 密码，请手动设置后重试 (NB_MYSQL_ROOT_PASS=xxx bash deploy.sh)"; exit 1; fi
  mysql -uroot -p"${TMP_PASS}" --connect-expired-password -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';" >/dev/null
fi
# 应用账号
mysql -uroot -p"${MYSQL_ROOT_PASS}" -e \
  "CREATE USER IF NOT EXISTS 'nextbastion'@'localhost' IDENTIFIED BY '${NB_DB_PASS_ENV}';
   CREATE USER IF NOT EXISTS 'nextbastion'@'127.0.0.1' IDENTIFIED BY '${NB_DB_PASS_ENV}';
   GRANT ALL PRIVILEGES ON nextbastion.* TO 'nextbastion'@'localhost';
   GRANT ALL PRIVILEGES ON nextbastion.* TO 'nextbastion'@'127.0.0.1';
   FLUSH PRIVILEGES;" >/dev/null

# ---------- 3. 应用目录与 venv ----------
log "部署应用文件 -> $APP_DIR"
mkdir -p "$APP_DIR/records" "$APP_DIR/logs"
# 兼容两种源码布局：源码根即 app / 源码根含 app 子目录
if [[ -d "$SRC_DIR/app" ]]; then SRC_APP="$SRC_DIR/app"; else SRC_APP="$SRC_DIR"; fi
rsync -a --delete --exclude '__pycache__' "$SRC_APP/" "$APP_DIR/app/" 2>/dev/null \
  || \cp -rf "$SRC_APP"/* "$APP_DIR/app/"
ls "$APP_DIR/app/requirements.txt" >/dev/null || { echo "requirements.txt 缺失，检查源码布局"; exit 1; }

python3.11 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip -i https://mirrors.aliyun.com/pypi/simple/ 2>/dev/null || true
"$VENV/bin/pip" install -q -r "$APP_DIR/app/requirements.txt" -i https://mirrors.aliyun.com/pypi/simple/ 2>/dev/null \
  || "$VENV/bin/pip" install -q -r "$APP_DIR/app/requirements.txt"
log "Python 依赖安装完成"

# ---------- 4. 密钥持久化（必须先于 seed：凭据加密密钥一致性） ----------
KEY_FILE="$APP_DIR/.secrets"
if [[ ! -f $KEY_FILE ]]; then
  { echo "NB_JWT_SECRET=$(openssl rand -hex 32)"; echo "NB_CRED_KEY=$(openssl rand -hex 32)"; } > "$KEY_FILE"
  chmod 600 "$KEY_FILE"
fi
source "$KEY_FILE"
export NB_JWT_SECRET NB_CRED_KEY

# 数据库密码落盘（供运维脚本读取，600 权限）
DB_ENV_FILE="$APP_DIR/.db.env"
printf 'NB_DB_PASS=%q\n' "$NB_DB_PASS_ENV" > "$DB_ENV_FILE"
chmod 600 "$DB_ENV_FILE"

# ---------- 5. 建库 + 种子数据 ----------
log "初始化数据库 schema"
cd "$APP_DIR/app"
NB_DB_PASS="$NB_DB_PASS_ENV" NB_MYSQL_ROOT_PASS="$MYSQL_ROOT_PASS" "$VENV/bin/python" db_init.py
NB_DB_PASS="$NB_DB_PASS_ENV" NB_ADMIN_PASS="$ADMIN_PASS" NB_NO_MFA="$NO_MFA" \
  NB_SELF_SSH_PASS="${NB_SELF_SSH_PASS:-SelfHost@2026}" "$VENV/bin/python" seed.py | tee "$APP_DIR/INITIAL_CREDENTIALS.txt"

# ---------- 6. systemd 服务 ----------
log "配置 systemd 服务"
cat > /etc/systemd/system/nextbastion.service <<EOF
[Unit]
Description=NextBastion Bastion Host
After=network.target mysqld.service

[Service]
Type=simple
WorkingDirectory=$APP_DIR/app
EnvironmentFile=$KEY_FILE
Environment=NB_DB_PASS=$NB_DB_PASS_ENV
Environment=NB_RECORD_DIR=$APP_DIR/records
ExecStart=$VENV/bin/uvicorn main:app --host 0.0.0.0 --port $PORT --workers 2
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now nextbastion
sleep 3
systemctl is-active nextbastion

# ---------- 7. Nginx 反代（80 -> 8000，WS 升级用 map） ----------
log "配置 Nginx 反代"
cat > /etc/nginx/conf.d/nextbastion.conf <<EOF
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}
server {
    listen 80;
    server_name _;
    client_max_body_size 100m;
    add_header Cache-Control "no-cache";
    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF
nginx -t 2>/dev/null && systemctl enable --now nginx >/dev/null 2>&1 && systemctl reload nginx || warn "nginx 配置失败（不影响 $PORT 直访）"
# Rocky9 SELinux：允许 nginx 反代上游（否则 502 Permission denied）
setsebool -P httpd_can_network_connect 1 2>/dev/null || warn "setsebool 失败（若启用了 SELinux 需手动执行）"
systemctl restart nginx >/dev/null 2>&1 || true

# ---------- 8. 防火墙 ----------
systemctl enable --now firewalld >/dev/null 2>&1 || true
firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
firewall-cmd --permanent --add-port=$PORT/tcp >/dev/null 2>&1 || true
firewall-cmd --reload >/dev/null 2>&1 || true

# ---------- 9. 可选：guacd（RDP 图形通道） ----------
if [[ "$WITH_RDP" == "1" ]]; then
  log "安装 guacd 1.5.5（RDP 支持，编译约 5-10 分钟）"
  if [[ -x /usr/local/sbin/guacd ]]; then
    log "guacd 已存在，跳过编译"
  else
    dnf install -y -q cairo-devel libjpeg-turbo-devel libpng-devel libtool uuid-devel \
      openssl-devel pango-devel freerdp-devel freerdp-plugins libvncserver-devel \
      libwebsockets-devel libssh2-devel terminus-fonts >/dev/null 2>&1 || warn "依赖安装有告警，继续"
    BUILD_DIR=$(mktemp -d)
    GUAC_VER=1.5.5
    (cd "$BUILD_DIR" && curl -fsSL -o guacamole-server.tar.gz \
      "https://archive.apache.org/dist/guacamole/${GUAC_VER}/source/guacamole-server-${GUAC_VER}.tar.gz" \
      && tar xzf guacamole-server.tar.gz && cd "guacamole-server-${GUAC_VER}" \
      && ./configure --with-init-dir=/etc/systemd/system >/dev/null 2>&1 \
      && make -j"$(nproc)" >/dev/null 2>&1 && make install >/dev/null 2>&1) \
      || { warn "guacd 编译失败，RDP 不可用（SSH 审计不受影响）"; rm -rf "$BUILD_DIR"; }
    rm -rf "$BUILD_DIR"
    ldconfig
  fi
  # guacd systemd 服务（若编译安装未自动注册）
  if [[ -x /usr/local/sbin/guacd ]] && [[ ! -f /etc/systemd/system/guacd.service ]]; then
    cat > /etc/systemd/system/guacd.service <<'EOF'
[Unit]
Description=Guacamole Server Daemon
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/sbin/guacd -b 127.0.0.1 -l 4822
ExecStop=/bin/kill -TERM $MAINPID
PIDFile=/var/run/guacd.pid
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
  fi
  systemctl enable --now guacd 2>/dev/null && log "guacd 已启动（仅监听 127.0.0.1:4822）" || warn "guacd 启动失败"
else
  log "跳过 guacd（如需 RDP：NB_WITH_RDP=1 bash deploy.sh）"
fi

# ---------- 10. 运维脚本 + 定时器 ----------
log "安装运维脚本（LDAP 同步 / 日志清理）"
if [[ -d "$SRC_DIR/scripts" ]]; then
  \cp -f "$SRC_DIR/scripts/nb_ldap_sync.sh" "$SRC_DIR/scripts/nb_cleanup.sh" "$APP_DIR/" 2>/dev/null || true
  chmod +x "$APP_DIR"/nb_*.sh 2>/dev/null || true
  # LDAP 每日 02:30 全量同步
  cat > /etc/systemd/system/nb-ldap-sync.service <<EOF
[Unit]
Description=NextBastion LDAP daily sync

[Service]
Type=oneshot
ExecStart=$APP_DIR/nb_ldap_sync.sh
EOF
  cat > /etc/systemd/system/nb-ldap-sync.timer <<EOF
[Unit]
Description=Run NextBastion LDAP sync daily

[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  # 录像/审计日志保留清理（每日 03:30，保留 180 天）
  cat > /etc/systemd/system/nb-cleanup.service <<EOF
[Unit]
Description=NextBastion records & audit cleanup

[Service]
Type=oneshot
ExecStart=$APP_DIR/nb_cleanup.sh
EOF
  cat > /etc/systemd/system/nb-cleanup.timer <<EOF
[Unit]
Description=Run NextBastion cleanup daily

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now nb-ldap-sync.timer nb-cleanup.timer >/dev/null 2>&1 || warn "定时器注册失败（可手动配置 cron）"
fi

# ---------- 11. 健康检查 ----------
log "健康检查"
sleep 2
curl -sf "http://127.0.0.1:$PORT/api/v1/health" && echo "" || { warn "健康检查失败，查看: journalctl -u nextbastion -n 50"; }

IP=$(hostname -I | awk '{print $1}')
echo ""
echo "============================================================"
echo "  NextBastion 部署完成"
echo "  登录页面 : http://$IP  (直连: http://$IP:$PORT)"
echo "  初始账号 : admin / $ADMIN_PASS"
echo "  TOTP     : 见 $APP_DIR/INITIAL_CREDENTIALS.txt（Google Authenticator 扫码）"
echo "  服务管理 : systemctl {status|restart} nextbastion"
echo "  日志     : journalctl -u nextbastion -f"
[[ "$WITH_RDP" == "1" ]] && echo "  RDP      : guacd 已就绪（systemctl status guacd）"
echo "============================================================"
echo "  ⚠️  上线前必做：修改 admin 初始密码 / 更换 MySQL 默认口令 / 挂 HTTPS 证书"
echo "============================================================"
