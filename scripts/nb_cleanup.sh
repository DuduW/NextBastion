#!/bin/bash
# NextBastion 录像/日志保留清理（由 nb-cleanup.timer 调用，保留 180 天）
# 数据库密码从 /opt/nextbastion/.db.env 读取（部署时生成）
APP_DIR=/opt/nextbastion
source "$APP_DIR/.db.env" 2>/dev/null || true
RECORD_DIR=$APP_DIR/records
find "$RECORD_DIR" -name "*.cast" -mtime +180 -delete 2>/dev/null
find "$RECORD_DIR" -name "*.mkb" -mtime +180 -delete 2>/dev/null
mysql -unextbastion -p"$NB_DB_PASS" nextbastion -e "
DELETE FROM command_logs WHERE executed_at < DATE_SUB(NOW(), INTERVAL 180 DAY);
DELETE FROM login_logs WHERE logged_at < DATE_SUB(NOW(), INTERVAL 180 DAY);
DELETE FROM audit_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 180 DAY) AND action IN ('totp_used','rdp_token_used');
" >/dev/null 2>&1
echo "$(date '+%F %T') cleanup done" >> "$APP_DIR/logs/cleanup.log"
