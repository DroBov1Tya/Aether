CREATE DATABASE IF NOT EXISTS aether;

CREATE TABLE IF NOT EXISTS aether.scan_results_rustscan (
    target      String,
    ports       Array(UInt16),
    scanned_at  DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (target, scanned_at);

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
    banner            Nullable(String),
    cpe               Nullable(String),
    scripts           Nullable(String),
    os_name           Nullable(String),
    os_accuracy       Nullable(UInt8),
    ttl               Nullable(UInt8),
    scanned_at        DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (target, port, scanned_at);

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

CREATE TABLE IF NOT EXISTS aether.scan_screenshots (
    target      String,
    port        UInt16,
    s3_key      String,
    file_size   UInt32,
    taken_at    DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (target, port, taken_at);

CREATE TABLE IF NOT EXISTS aether.scan_results_dns (
    target      String,
    a           Array(String),
    aaaa        Array(String),
    cname       Array(String),
    mx          Array(String),
    ns          Array(String),
    txt         Array(String),
    ptr         Array(String),
    scanned_at  DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (target, scanned_at);

CREATE TABLE IF NOT EXISTS aether.scan_results_ssl (
    host          String,
    port          UInt16,
    subject       String,
    issuer        String,
    not_before    String,
    not_after     String,
    serial        String,
    san           Array(String),
    ssl_version   String,
    cipher        String,
    chain_length  UInt8,
    scanned_at    DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (host, port, scanned_at);
