-- NextBastion LDAP 迁移（MySQL 8 幂等版）
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='auth_source');
SET @s := IF(@c=0, 'ALTER TABLE users ADD COLUMN auth_source VARCHAR(16) NOT NULL DEFAULT ''local''', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='email');
SET @s := IF(@c=0, 'ALTER TABLE users ADD COLUMN email VARCHAR(128) DEFAULT ''''', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

CREATE TABLE IF NOT EXISTS ldap_config (
  id INT AUTO_INCREMENT PRIMARY KEY,
  enabled TINYINT DEFAULT 0,
  url VARCHAR(128) DEFAULT '',
  base_dn VARCHAR(255) DEFAULT '',
  bind_dn VARCHAR(255) DEFAULT '',
  bind_pw_enc TEXT,
  starttls TINYINT DEFAULT 0,
  insecure TINYINT DEFAULT 0,
  login_attr VARCHAR(32) DEFAULT 'uid',
  name_attr VARCHAR(32) DEFAULT 'cn',
  mail_attr VARCHAR(32) DEFAULT 'mail',
  user_filter VARCHAR(255) DEFAULT '(objectClass=inetOrgPerson)',
  map_admin VARCHAR(255) DEFAULT '',
  map_auditor VARCHAR(255) DEFAULT '',
  default_role VARCHAR(16) DEFAULT 'user',
  group_maps TEXT
);
