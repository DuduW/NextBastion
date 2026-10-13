#!/bin/bash
# NextBastion LDAP 每日全量同步（由 nb-ldap-sync.timer 调用）
# 数据库密码从 /opt/nextbastion/.db.env 读取（部署时生成）
APP_DIR=/opt/nextbastion
source "$APP_DIR/.db.env" 2>/dev/null || true
cd "$APP_DIR/app"
"$APP_DIR/venv/bin/python" - <<'EOF' >> "$APP_DIR/logs/ldap_sync.log" 2>&1
import os, sys
sys.path.insert(0, '/opt/nextbastion/app')
import ldap_auth
report = ldap_auth.sync_full(actor='timer')
print(f"[{__import__('datetime').datetime.now():%F %T}] sync: {report}")
EOF
