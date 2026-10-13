"""NextBastion - 种子数据：admin 用户 + 本机资产 + 演示授权策略
初始账号: admin / Admin@2026  （TOTP 由首次部署打印，可用 -–no-mfa 关闭）
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pyotp, pymysql, secrets
import utils
from config import DB_CONFIG

def seed(admin_password='Admin@2026', enable_mfa=True):
    conn = pymysql.connect(**DB_CONFIG, autocommit=True)
    cur = conn.cursor()
    # admin 用户
    secret = pyotp.random_base32()
    cur.execute("""INSERT INTO users (username, password_hash, totp_secret, display_name, role, is_mfa_enabled)
                   VALUES ('admin', %s, %s, '系统管理员', 'admin', %s)
                   ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), totp_secret=VALUES(totp_secret), is_mfa_enabled=VALUES(is_mfa_enabled)""",
                (utils.hash_password(admin_password), secret if enable_mfa else '', 1 if enable_mfa else 0))
    cur.execute("INSERT IGNORE INTO user_group_map (user_id, group_id) SELECT id, 1 FROM users WHERE username='admin'")

    # 演示资产：本机（self）——部署后可直接做真实 SSH 终端测试
    cur.execute("""INSERT INTO assets (node_id, hostname, ip, os_type, ssh_port, protocol, labels)
                   SELECT 4, 'self-bastion', '127.0.0.1', 'Linux', 22, 'ssh', '"demo"'
                   WHERE NOT EXISTS (SELECT 1 FROM assets WHERE hostname='self-bastion')""")
    cur.execute("""INSERT INTO asset_accounts (asset_id, username, cred_type, secret_encrypted)
                   SELECT a.id, 'root', 'password', %s FROM assets a WHERE a.hostname='self-bastion'
                     AND NOT EXISTS (SELECT 1 FROM asset_accounts x WHERE x.asset_id=a.id)""",
                (utils.encrypt_secret(os.environ.get('NB_SELF_SSH_PASS', 'SelfHost@2026')),))

    # 演示 Windows 资产（RDP 通道演示，无需真实 Windows）
    cur.execute("""INSERT INTO assets (node_id, hostname, ip, os_type, rdp_port, protocol, labels)
                   SELECT 4, 'win-demo', '127.0.0.1', 'Windows Server 2019', 3389, 'rdp', '"demo"'
                   WHERE NOT EXISTS (SELECT 1 FROM assets WHERE hostname='win-demo')""")
    cur.execute("""INSERT INTO asset_accounts (asset_id, username, cred_type, secret_encrypted)
                   SELECT a.id, 'administrator', 'password', %s FROM assets a WHERE a.hostname='win-demo'
                     AND NOT EXISTS (SELECT 1 FROM asset_accounts x WHERE x.asset_id=a.id)""",
                (utils.encrypt_secret('Demo@Pass1'),))

    # 授权策略：infra 组 → 测试区节点 → 全账号（全天）
    cur.execute("""INSERT INTO access_policies (name, user_or_group_type, user_or_group_id, asset_or_node_type,
                     asset_or_node_id, account_pattern, command_filter_id, rdp_session_config, created_by)
                   SELECT 'INFRA-测试区-全时', 'group', 1, 'node', 4, '*', 1,
                          '{"clipboard": false, "drive": false, "watermark": true}', 'seed'
                   WHERE NOT EXISTS (SELECT 1 FROM access_policies WHERE name='INFRA-测试区-全时')""")

    # 默认高危命令过滤库内容
    import json
    from config import DEFAULT_FILTER_RULES
    cur.execute("UPDATE command_filters SET rules=%s WHERE id=1 AND (rules IS NULL OR JSON_LENGTH(rules)=0)",
                (json.dumps(DEFAULT_FILTER_RULES, ensure_ascii=False),))
    cur.close(); conn.close()

    print('=' * 62)
    print('  NextBastion 初始化完成')
    print(f'  初始账号  : admin')
    print(f'  初始密码  : {admin_password}')
    if enable_mfa:
        print(f'  TOTP Secret : {secret}')
        print(f'  OTPAuth URI : {pyotp.totp.TOTP(secret).provisioning_uri(name="admin", issuer_name="NextBastion")}')
        print('  >> 用 Google Authenticator 扫码/手输 Secret 后，登录需填 6 位动态码')
    print('=' * 62)
    return secret

if __name__ == '__main__':
    pw = os.environ.get('NB_ADMIN_PASS', 'Admin@2026')
    mfa = os.environ.get('NB_NO_MFA', '') != '1'
    seed(pw, mfa)
