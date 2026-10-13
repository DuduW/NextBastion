-- M2：F8 totp_bound 列（目录用户首登引导）
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='totp_bound');
SET @s := IF(@c=0, 'ALTER TABLE users ADD COLUMN totp_bound TINYINT DEFAULT 1', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
UPDATE users SET totp_bound=1 WHERE totp_bound IS NULL;
