-- 005: 资产多节点归属（方案B：主节点锚点 + 附属节点映射）
-- 主锚点保留 assets.node_id；本表承载附属节点（授权 = 主链 ∪ 各附属链 命中）
CREATE TABLE IF NOT EXISTS asset_extra_nodes (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  asset_id INT NOT NULL,
  node_id INT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_asset_node (asset_id, node_id),
  KEY idx_node (node_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
