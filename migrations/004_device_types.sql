-- 004: 网络设备 SSH + MySQL 远程接入（V1.4）
-- 1) 资产设备类型（linux/windows/huawei/h3c/cisco/ruijie/juniper/mysql）
ALTER TABLE assets ADD COLUMN device_type VARCHAR(32) NOT NULL DEFAULT 'linux';

-- 2) 托管账号 enable 密码（网络设备双重认证；AES-GCM 与 secret_encrypted 同体系）
ALTER TABLE asset_accounts ADD COLUMN enable_secret_enc BLOB NULL;

-- 3) 授权能力：MySQL 写权限（能力并集语义：任一命中策略勾选即生效）
ALTER TABLE access_policies ADD COLUMN allow_sql_write TINYINT(1) NOT NULL DEFAULT 0;

-- 4) 预置高危规则集（command_filters 为行式：name + rules JSON[{regex,action,name,icase}]）
--    规则集内容见 seed（deploy 时由 db_init 注入）；此处仅示意，幂等插入：
INSERT INTO command_filters (name, rules)
SELECT '网络设备高危', JSON_ARRAY(
  JSON_OBJECT('name','清空配置','regex','reset\\s+saved-configuration','action','block','icase',TRUE),
  JSON_OBJECT('name','删除系统文件','regex','delete\\s+(unreserved\\s+)?flash:','action','block','icase',TRUE),
  JSON_OBJECT('name','格式化存储','regex','^format\\s+','action','block','icase',TRUE),
  JSON_OBJECT('name','重启设备','regex','^reload\\b','action','block','icase',TRUE),
  JSON_OBJECT('name','思科清配置','regex','(erase\\s+startup-config|write\\s+erase)','action','block','icase',TRUE),
  JSON_OBJECT('name','配置回退','regex','^undo\\s+','action','alert','icase',TRUE),
  JSON_OBJECT('name','接口断启','regex','^shutdown$','action','alert','icase',FALSE))
WHERE NOT EXISTS (SELECT 1 FROM (SELECT 1 FROM command_filters WHERE name='网络设备高危') t);

INSERT INTO command_filters (name, rules)
SELECT 'MySQL 高危', JSON_ARRAY(
  JSON_OBJECT('name','删库','regex','^\\s*DROP\\s+(DATABASE|SCHEMA)\\b','action','block','icase',TRUE),
  JSON_OBJECT('name','清表','regex','^\\s*TRUNCATE\\s+(TABLE\\s+)?[\\w`.]+','action','block','icase',TRUE),
  JSON_OBJECT('name','DELETE无WHERE','regex','^\\s*DELETE\\s+FROM\\s+[\\w`.]+\\s*;?\\s*$','action','block','icase',TRUE),
  JSON_OBJECT('name','表结构变更','regex','^\\s*(DROP|ALTER)\\s+TABLE\\b','action','alert','icase',TRUE),
  JSON_OBJECT('name','授权语句','regex','^\\s*GRANT\\s+','action','alert','icase',TRUE),
  JSON_OBJECT('name','权限变更','regex','^\\s*(REVOKE|RENAME\\s+USER)\\b','action','alert','icase',TRUE))
WHERE NOT EXISTS (SELECT 1 FROM (SELECT 1 FROM command_filters WHERE name='MySQL 高危') t);
