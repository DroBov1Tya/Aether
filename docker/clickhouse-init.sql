-- ============================================================
-- Aether — ClickHouse initialization
-- Database: aether
-- Tables: scan_results_*
-- ============================================================

CREATE DATABASE IF NOT EXISTS aether;

-- -----------------------------------------------------------
-- scan_results_rustscan — list of open ports per target
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS aether.scan_results_rustscan (
    target      String,
    ports       Array(UInt16),
    scanned_at  DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (target, scanned_at);

-- -----------------------------------------------------------
-- scan_results_nmap — service-detection results (one row/port)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS aether.scan_results_nmap (
    target            String,
    port              UInt16,
    protocol          String,
    state             String,
    state_reason      Nullable(String),
    service           Nullable(String),
    product           Nullable(String),
    version           Nullable(String),
    extra_info        Nullable(String),
    os_type           Nullable(String),
    detection_method  Nullable(String),
    confidence        Nullable(UInt8),
    scanned_at        DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (target, port, scanned_at);

-- -----------------------------------------------------------
-- scan_results_whatweb — technology detection (one row/page)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS aether.scan_results_whatweb (
    target        String,
    port          UInt16,
    url           String,
    http_status   Nullable(UInt16),
    title         Nullable(String),
    technologies  Array(String),
    scanned_at    DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (target, port, scanned_at);

-- -----------------------------------------------------------
-- scan_screenshots — screenshot metadata (image stored in S3)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS aether.scan_screenshots (
    target      String,
    port        UInt16,
    s3_key      String,
    file_size   UInt32,
    taken_at    DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (target, port, taken_at);
