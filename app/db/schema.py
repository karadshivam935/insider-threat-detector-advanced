SCHEMA_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  proto TEXT NOT NULL,
  dst_port INTEGER,
  bytes INTEGER NOT NULL,
  score INTEGER NOT NULL,
  reasons TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics_window (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  src_ip TEXT NOT NULL,
  window_seconds INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  unique_dst_ips INTEGER NOT NULL,
  unique_dst_ports INTEGER NOT NULL,
  top_dst_ip TEXT,
  top_dst_port INTEGER
);

CREATE TABLE IF NOT EXISTS baseline (
  src_ip TEXT PRIMARY KEY,
  avg_bytes REAL NOT NULL,
  avg_unique_ports REAL NOT NULL,
  avg_unique_dsts REAL NOT NULL,
  last_update_ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  src_ip TEXT NOT NULL,
  seconds INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  reason TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics_window(ts);
"""
