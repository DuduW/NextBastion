-- 007: 交换机备份/巡检增强（V2.1）· 对齐 PRD-交换机管理-备份与巡检
-- 1) tasks 表：备份/巡检任务附加保留策略与执行触发
ALTER TABLE tasks
  ADD COLUMN retention_count INT NULL DEFAULT NULL,   -- 每资产保留最近 N 份（NULL=不限）
  ADD COLUMN retention_daily TINYINT NOT NULL DEFAULT 0; -- 1=每日末份永久保留

-- 2) config_snapshots：备份触发来源（manual/scheduled）+ 版本号（每资产连续可比，失败不回退）
ALTER TABLE config_snapshots
  ADD COLUMN trigger_type VARCHAR(12) NOT NULL DEFAULT 'manual',  -- manual | scheduled | auto_snapshot
  ADD COLUMN version_no   INT NULL,                               -- 每资产自增版本号
  ADD COLUMN diff_added   INT NULL,                               -- 与上一成功版 +行数
  ADD COLUMN diff_removed INT NULL,                               -- 与上一成功版 -行数
  ADD COLUMN fail_reason  VARCHAR(32) NULL,                       -- 备份失败归类（auth_failed/timeout/unreachable/session）
  ADD KEY idx_asset_vno (asset_id, owner_id, version_no);

-- 3) 巡检快照表（结构化指标，30 天滚动由应用层清理）
CREATE TABLE IF NOT EXISTS health_snapshots (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  asset_id      INT NOT NULL,
  owner_id      INT NOT NULL,
  task_id       INT NOT NULL,
  vrp           VARCHAR(64) NULL,          -- display version 解析
  uptime        VARCHAR(128) NULL,
  cpu_pct       FLOAT NULL,
  mem_pct       FLOAT NULL,
  temp_max      FLOAT NULL,                -- °C
  ports_down    INT NULL,                  -- 物理口 DOWN 数
  ports_total   INT NULL,
  interfaces_json JSON NULL,               -- [{name,phy,protocol,in_uti,out_uti,in_errors,out_errors}]
  alarms_json   JSON NULL,                 -- 告警列表
  items_json    JSON NULL,                 -- 解析条目（含 ok/warn 级别）
  healthy       TINYINT NOT NULL DEFAULT 0,
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  KEY idx_asset_time (asset_id, owner_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4) 离线防抖：资产维度 streak 计数（连续失败次数；最新成功即复位）
CREATE TABLE IF NOT EXISTS asset_health_streak (
  asset_id    INT PRIMARY KEY,
  owner_id    INT NOT NULL,
  fail_streak INT NOT NULL DEFAULT 0,      -- 连续失败次数
  last_ok_at  DATETIME NULL,               -- 最近一次成功时刻
  updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
