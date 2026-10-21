-- 009: 授权策略多目标（V2.3）· 一条策略可指多个资产组/多个资产
ALTER TABLE access_policies
  ADD COLUMN asset_ids_json JSON NULL AFTER asset_or_node_id,
  ADD KEY idx_targets ((CAST(asset_ids_json AS UNSIGNED ARRAY)));

-- 存量单目标策略：asset_ids_json 回填（保持列表口径统一）
UPDATE access_policies
SET asset_ids_json = JSON_ARRAY(asset_or_node_id)
WHERE asset_ids_json IS NULL;
