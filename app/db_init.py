"""NextBastion - 数据库初始化（DDL + 种子数据）"""
import pymysql
from config import DB_CONFIG

DDL = """
CREATE DATABASE IF NOT EXISTS nextbastion DEFAULT CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE nextbastion;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(128) NOT NULL,
  totp_secret VARCHAR(64) DEFAULT '',
  display_name VARCHAR(64) DEFAULT '',
  role VARCHAR(20) DEFAULT 'user',
  is_active TINYINT DEFAULT 1,
  is_mfa_enabled TINYINT DEFAULT 1,
  locked_until DATETIME DEFAULT NULL,
  fail_count INT DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_groups (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE,
  description VARCHAR(255) DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_group_map (
  user_id INT NOT NULL,
  group_id INT NOT NULL,
  PRIMARY KEY (user_id, group_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS asset_nodes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  parent_id INT DEFAULT NULL,
  name VARCHAR(128) NOT NULL,
  sort INT DEFAULT 0
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS assets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  node_id INT DEFAULT 1,
  hostname VARCHAR(128) NOT NULL,
  ip VARCHAR(64) NOT NULL,
  os_type VARCHAR(64) DEFAULT 'Linux',
  ssh_port INT DEFAULT 22,
  rdp_port INT DEFAULT 3389,
  protocol VARCHAR(10) DEFAULT 'ssh',
  labels JSON,
  status VARCHAR(20) DEFAULT 'online',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_node (node_id), INDEX idx_ip (ip)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS asset_accounts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  asset_id INT NOT NULL,
  username VARCHAR(64) NOT NULL,
  cred_type VARCHAR(10) DEFAULT 'password',
  secret_encrypted VARBINARY(512),
  become_user VARCHAR(64) DEFAULT '',
  become_mode VARCHAR(10) DEFAULT '',
  last_verified_at DATETIME DEFAULT NULL,
  status VARCHAR(20) DEFAULT 'active',
  INDEX idx_asset (asset_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS access_policies (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  user_or_group_type VARCHAR(10) DEFAULT 'group',
  user_or_group_id INT NOT NULL,
  asset_or_node_type VARCHAR(10) DEFAULT 'node',
  asset_or_node_id INT NOT NULL,
  account_pattern VARCHAR(128) DEFAULT '*',
  allowed_periods JSON,
  command_filter_id INT DEFAULT NULL,
  rdp_session_config JSON,
  valid_from DATETIME DEFAULT NULL,
  valid_until DATETIME DEFAULT NULL,
  is_enabled TINYINT DEFAULT 1,
  created_by VARCHAR(64) DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS field_options (
  id INT AUTO_INCREMENT PRIMARY KEY,
  field_key VARCHAR(32) NOT NULL COMMENT '字段: os_type=操作系统 / label=分组',
  opt_value VARCHAR(64) NOT NULL COMMENT '选项值',
  opt_group VARCHAR(32) DEFAULT '' COMMENT '选项分组(如 Linux/Windows)',
  sort_no INT DEFAULT 99,
  enabled TINYINT DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_key_val (field_key, opt_value)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sessions (
  id VARCHAR(40) PRIMARY KEY,
  user_id INT NOT NULL,
  asset_id INT NOT NULL,
  protocol VARCHAR(10) DEFAULT 'ssh',
  account_name VARCHAR(64),
  client_ip VARCHAR(64),
  started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  ended_at DATETIME DEFAULT NULL,
  duration_s INT DEFAULT 0,
  status VARCHAR(20) DEFAULT 'active',
  cast_file_path VARCHAR(255) DEFAULT '',
  video_file_path VARCHAR(255) DEFAULT '',
  is_high_risk TINYINT DEFAULT 0,
  INDEX idx_user (user_id), INDEX idx_asset (asset_id), INDEX idx_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS command_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  session_id VARCHAR(40) NOT NULL,
  user_id INT NOT NULL,
  asset_id INT NOT NULL,
  command_text TEXT,
  matched_rule VARCHAR(128) DEFAULT '',
  action VARCHAR(10) DEFAULT 'allow',
  executed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  risk_level VARCHAR(10) DEFAULT 'low',
  INDEX idx_session (session_id), INDEX idx_user (user_id),
  FULLTEXT KEY ft_cmd (command_text)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS file_transfer_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  session_id VARCHAR(40) NOT NULL,
  user_id INT NOT NULL,
  asset_id INT NOT NULL,
  direction VARCHAR(10),
  file_name VARCHAR(255),
  file_size BIGINT DEFAULT 0,
  transferred_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS command_filters (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  rules JSON,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64),
  client_ip VARCHAR(64),
  result VARCHAR(10),
  reason VARCHAR(255) DEFAULT '',
  logged_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (username)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  actor VARCHAR(64),
  action VARCHAR(64),
  target_type VARCHAR(32) DEFAULT '',
  target_id VARCHAR(64) DEFAULT '',
  detail JSON,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============ 种子数据 ============
-- 资产字段选项字典
INSERT IGNORE INTO field_options (field_key, opt_value, opt_group, sort_no) VALUES
 ('os_type', 'CentOS 7', 'Linux', 1), ('os_type', 'CentOS 8', 'Linux', 2),
 ('os_type', 'Rocky Linux 8', 'Linux', 3), ('os_type', 'Rocky Linux 9', 'Linux', 4),
 ('os_type', 'Ubuntu 20.04', 'Linux', 5), ('os_type', 'Ubuntu 22.04', 'Linux', 6),
 ('os_type', 'Ubuntu 24.04', 'Linux', 7), ('os_type', 'Debian 11', 'Linux', 8),
 ('os_type', 'Debian 12', 'Linux', 9), ('os_type', 'AlmaLinux 9', 'Linux', 10),
 ('os_type', 'openEuler 22.03', 'Linux', 11), ('os_type', 'Anolis OS 8', 'Linux', 12),
 ('os_type', 'Windows Server 2016', 'Windows', 13), ('os_type', 'Windows Server 2019', 'Windows', 14),
 ('os_type', 'Windows Server 2022', 'Windows', 15), ('os_type', 'Windows 10', 'Windows', 16),
 ('os_type', 'Windows 11', 'Windows', 17),
 ('os_type', 'Huawei VRP', '网络设备', 18), ('os_type', 'H3C Comware', '网络设备', 19),
 ('os_type', 'Cisco IOS', '网络设备', 20),
 ('label', '生产', '', 1), ('label', '测试', '', 2), ('label', '数据库', '', 3),
 ('label', '办公', '', 4), ('label', '开发', '', 5);

INSERT IGNORE INTO asset_nodes (id, parent_id, name, sort) VALUES
 (1, NULL, '全部资产', 0), (2, 1, '苏州 IDC', 1), (3, 2, '生产区', 1),
 (4, 2, '测试区', 2), (5, 1, '上海 IDC', 2), (6, 1, '公有云', 3);

INSERT IGNORE INTO user_groups (id, name, description) VALUES
 (1, 'infra', '基础设施组'), (2, 'dba', '数据库组'), (3, 'dev', '开发组');

INSERT IGNORE INTO command_filters (id, name, rules) VALUES
 (1, '默认高危库', NULL);
"""


def init_db(root_host='127.0.0.1', root_port=3306, root_user='root', root_pass=''):
    """用 root 连接执行 DDL 与授权"""
    conn = pymysql.connect(host=root_host, port=root_port, user=root_user,
                           password=root_pass, charset='utf8mb4', autocommit=True)
    cur = conn.cursor()
    for stmt in DDL.strip().split(';'):
        s = stmt.strip()
        if s:
            cur.execute(s)
    # 应用账号授权
    cur.execute("CREATE USER IF NOT EXISTS 'nextbastion'@'localhost' IDENTIFIED BY %s", (DB_CONFIG['password'],))
    cur.execute("CREATE USER IF NOT EXISTS 'nextbastion'@'127.0.0.1' IDENTIFIED BY %s", (DB_CONFIG['password'],))
    cur.execute("GRANT ALL PRIVILEGES ON nextbastion.* TO 'nextbastion'@'localhost'")
    cur.execute("GRANT ALL PRIVILEGES ON nextbastion.* TO 'nextbastion'@'127.0.0.1'")
    cur.execute("FLUSH PRIVILEGES")
    cur.close()
    conn.close()
    print('[init_db] schema + grants OK')


if __name__ == '__main__':
    import sys, os
    rp = os.environ.get('NB_MYSQL_ROOT_PASS', sys.argv[1] if len(sys.argv) > 1 else '')
    init_db(root_pass=rp)
