-- 008: 资产分组与授权模型重构（V2.2）
-- 需求：①一个资产只能在一个节点 ②一个资产可在多个分组 ③资产/组可授权多用户 ④授权目标=组+单个资产
-- 变更：节点回归纯树（授权不再看节点）；新增资产组（多对多）；授权目标 node→group 迁移

-- 1) 资产组表
CREATE TABLE IF NOT EXISTS asset_groups (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(128) NOT NULL UNIQUE,
  comment    VARCHAR(255) DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2) 资产↔组 多对多映射
CREATE TABLE IF NOT EXISTS asset_group_map (
  id       BIGINT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  asset_id INT NOT NULL,
  UNIQUE KEY uk_group_asset (group_id, asset_id),
  KEY idx_asset (asset_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3a. labels → 资产组（labels 保留作展示；授权语义归组）
INSERT INTO asset_groups (name, comment)
SELECT DISTINCT j.label, CONCAT('由资产标签「', j.label, '」自动创建（V2.2 迁移）')
FROM assets a,
     JSON_TABLE(a.labels, '$[*]' COLUMNS (label VARCHAR(128) PATH '$')) j
WHERE a.labels IS NOT NULL AND JSON_LENGTH(a.labels) > 0
ON DUPLICATE KEY UPDATE comment = VALUES(comment);

INSERT IGNORE INTO asset_group_map (group_id, asset_id)
SELECT g.id, a.id
FROM assets a
JOIN asset_groups g ON g.name IN (SELECT j.label FROM JSON_TABLE(a.labels, '$[*]' COLUMNS (label VARCHAR(128) PATH '$')) j)
WHERE a.labels IS NOT NULL AND JSON_LENGTH(a.labels) > 0;

-- 3b. 存量 node 授权策略 → 资产组：为每个被引用节点建组（名称「节点: X」）
INSERT INTO asset_groups (name, comment)
SELECT DISTINCT CONCAT('节点: ', n.name), CONCAT('由节点「', n.name, '」授权策略自动迁移（V2.2，节点不再参与授权）')
FROM access_policies p JOIN asset_nodes n ON p.asset_or_node_type = 'node' AND p.asset_or_node_id = n.id
ON DUPLICATE KEY UPDATE comment = VALUES(comment);

-- 3c. 组员收录 = 节点子树全部资产（用递归 CTE 展开祖先链——策略指父节点时子树资产同样继承授权）
INSERT IGNORE INTO asset_group_map (group_id, asset_id)
WITH RECURSIVE sub(node_root, node_id) AS (
  SELECT n.id, n.id FROM asset_nodes n
  WHERE EXISTS (SELECT 1 FROM access_policies p WHERE p.asset_or_node_type='node' AND p.asset_or_node_id=n.id)
  UNION ALL
  SELECT s.node_root, c.id FROM sub s JOIN asset_nodes c ON c.parent_id = s.node_id
)
SELECT DISTINCT g.id, a.id
FROM sub s
JOIN asset_groups g ON g.name = CONCAT('节点: ', (SELECT n2.name FROM asset_nodes n2 WHERE n2.id = s.node_root))
JOIN assets a ON a.node_id = s.node_id;

-- 3d. 策略目标 node→group
UPDATE access_policies p
JOIN asset_nodes n ON p.asset_or_node_type='node' AND p.asset_or_node_id=n.id
JOIN asset_groups g ON g.name = CONCAT('节点: ', n.name)
SET p.asset_or_node_type = 'group', p.asset_or_node_id = g.id;

-- 4) 附属节点表退役（保留表供回滚；业务代码停用——资产只归一个节点）
