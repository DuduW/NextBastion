-- 006 任务管理（V2.0）：Linux 脚本任务 + 交换机定时备份/巡检
-- 权限模型：每人私有任务（owner_id 全查询过滤）；数据入口在「我的资产」主机名抽屉

CREATE TABLE IF NOT EXISTS tasks (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(128) NOT NULL,
  type          VARCHAR(16)  NOT NULL,            -- script | backup | inspect
  asset_ids     JSON         NOT NULL,            -- [assetId,...]
  script_text   MEDIUMTEXT   NULL,                -- script 类型
  commands      JSON         NULL,                -- inspect 自定义命令集（可选）
  cron_expr     VARCHAR(64)  NOT NULL,            -- 5 段 cron
  enabled       TINYINT      NOT NULL DEFAULT 1,
  timeout_s     INT          NOT NULL DEFAULT 120,
  notify_on     VARCHAR(64)  NOT NULL DEFAULT 'fail',  -- fail|change|alarm 组合(逗号)
  thresholds    JSON         NULL,                -- 巡检阈值 {cpu:80,mem:80,temp:40}
  owner_id      INT          NOT NULL,
  created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
  KEY idx_owner (owner_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS task_runs (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  task_id       INT     NOT NULL,
  owner_id      INT     NOT NULL,
  `trigger`    VARCHAR(10) NOT NULL DEFAULT 'cron',  -- cron | manual
  status        VARCHAR(10) NOT NULL DEFAULT 'running', -- running|success|partial|fail
  summary       VARCHAR(255) DEFAULT '',
  started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  finished_at   DATETIME NULL,
  duration_s    INT DEFAULT 0,
  KEY idx_task (task_id), KEY idx_owner (owner_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS task_run_items (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  run_id        BIGINT NOT NULL,
  asset_id      INT    NOT NULL,
  status        VARCHAR(10) NOT NULL DEFAULT 'running',  -- running|success|fail|skip|blocked
  exit_code     INT    NULL,
  output        MEDIUMTEXT NULL,
  detail        JSON   NULL,                      -- 巡检解析结果 / 备份 snapshot_id 等
  KEY idx_run (run_id), KEY idx_asset (asset_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS config_snapshots (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  asset_id      INT    NOT NULL,
  owner_id      INT    NOT NULL,
  task_id       INT    NOT NULL,
  content       MEDIUMTEXT NOT NULL,
  hash          CHAR(64) NOT NULL,
  size          INT NOT NULL DEFAULT 0,
  changed       TINYINT NOT NULL DEFAULT 0,       -- 与上一版不同
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  KEY idx_asset (asset_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
