CREATE DATABASE IF NOT EXISTS aether;

CREATE TABLE IF NOT EXISTS aether.agent_tokens (
    agent_id    String,
    token_hash  String,
    name        String,
    ip          String DEFAULT '',
    port        UInt16 DEFAULT 0,
    version     String DEFAULT '',
    os          String DEFAULT '',
    arch        String DEFAULT '',
    kernel      String DEFAULT '',
    max_concurrent_tasks UInt8 DEFAULT 10,
    busy_tasks  UInt8 DEFAULT 0,
    status      String DEFAULT 'active',
    created_at  DateTime DEFAULT now(),
    last_seen_at DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(last_seen_at)
PARTITION BY agent_id
ORDER BY (agent_id, last_seen_at)
TTL created_at + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS aether.task_queue (
    id           UInt64,
    task_id      String,
    target       String,
    payload      String,
    status       String DEFAULT 'queued',
    agent_id     String DEFAULT '',
    attempts     UInt8 DEFAULT 0,
    error        String DEFAULT '',
    created_at   DateTime DEFAULT now(),
    assigned_at  Nullable(DateTime),
    finished_at  Nullable(DateTime),
    lease_until  Nullable(DateTime),
    updated_at   DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toUInt32(id % 64)
ORDER BY (id)
TTL created_at + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS aether.agents (
    id                    String,
    ip                    String,
    name                  String,
    version               String,
    port                  UInt16,
    os                    String,
    arch                  String,
    kernel                String,
    max_concurrent_tasks  UInt8,
    status                String,
    last_seen_at          DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY id;

-- ============================================================
-- Scan result tables.
-- `project` isolates imported / client-network scans from the
-- public index. Default 'global' = the open recon surface shown
-- everywhere; named projects are surfaced only under /projects.
-- `project` is the leading ORDER BY key so per-project reads prune.
-- ============================================================

CREATE TABLE IF NOT EXISTS aether.scan_results_rustscan (
    target      String,
    ports       Array(UInt16),
    country     Nullable(String),
    project     String DEFAULT 'global',
    scan_uid    String,
    scanned_at  DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (project, target, scanned_at);

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
    country           Nullable(String),
    os_type           Nullable(String),
    detection_method  Nullable(String),
    confidence        Nullable(UInt8),
    banner            Nullable(String),
    cpe               Nullable(String),
    scripts           Nullable(String),
    os_name           Nullable(String),
    os_accuracy       Nullable(UInt8),
    ttl               Nullable(UInt8),
    project           String DEFAULT 'global',
    scan_uid          String,
    scanned_at        DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (project, target, port, scanned_at);

-- Shared HTTP-probe table. Written by httpx (and legacy whatweb).
-- httpx fills the richer columns (webserver/cdn/favicon_hash/content_length);
-- whatweb leaves them NULL. All search/host/stats queries read this table.
CREATE TABLE IF NOT EXISTS aether.scan_results_whatweb (
    target          String,
    port            UInt16,
    url             String,
    http_status     Nullable(UInt16),
    title           Nullable(String),
    technologies    Array(String),
    webserver       Nullable(String),
    cdn             Nullable(String),
    favicon_hash    Nullable(String),
    content_length  Nullable(UInt32),
    headers         String DEFAULT '',
    country         Nullable(String),
    project         String DEFAULT 'global',
    scan_uid        String,
    scanned_at      DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (project, target, port, scanned_at);

CREATE TABLE IF NOT EXISTS aether.scan_screenshots (
    target      String,
    port        UInt16,
    s3_key      String,
    file_size   UInt32,
    country     Nullable(String),
    project     String DEFAULT 'global',
    scan_uid    String,
    taken_at    DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (project, target, port, taken_at);

CREATE TABLE IF NOT EXISTS aether.scan_results_dns (
    target      String,
    a           Array(String),
    aaaa        Array(String),
    cname       Array(String),
    mx          Array(String),
    ns          Array(String),
    txt         Array(String),
    ptr         Array(String),
    country     Nullable(String),
    project     String DEFAULT 'global',
    scan_uid    String,
    scanned_at  DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (project, target, scanned_at);

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
    jarm          String DEFAULT '',
    chain_length  UInt8,
    country       Nullable(String),
    project       String DEFAULT 'global',
    scan_uid      String,
    scanned_at    DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (project, host, port, scanned_at);

CREATE TABLE IF NOT EXISTS aether.scan_results_fuzzing (
    target      String,
    port        UInt16,
    path        String,
    url         String,
    http_status UInt16,
    project     String DEFAULT 'global',
    scan_uid    String,
    scanned_at  DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (project, target, port, scanned_at);

CREATE TABLE IF NOT EXISTS aether.scan_results_whois (
    target          String,
    registrar       Nullable(String),
    creation_date   Nullable(String),
    expiration_date Nullable(String),
    name_servers    Array(String),
    organization    Nullable(String),
    country         Nullable(String),
    emails          Array(String),
    project         String DEFAULT 'global',
    scan_uid        String,
    raw             String,
    scanned_at      DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (project, target, scanned_at);

-- Nuclei findings: the "hunt" layer (exposed panels, misconfig, CVEs,
-- default creds, info leaks). One row per matched template.
CREATE TABLE IF NOT EXISTS aether.scan_results_nuclei (
    target        String,
    port          UInt16,
    url           String,
    template_id   String,
    name          String,
    severity      String,
    protocol_type String,
    matched_at    String,
    tags          Array(String),
    description   Nullable(String),
    reference     Array(String),
    extracted     Array(String),
    country       Nullable(String),
    project       String DEFAULT 'global',
    scan_uid      String,
    found_at      DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (project, severity, target, scan_uid);

CREATE TABLE IF NOT EXISTS aether.proxies (
    url        String,
    added_at   DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(added_at)
ORDER BY url;

CREATE TABLE IF NOT EXISTS aether.host_geo (
    target        String,
    country       String DEFAULT '',
    country_code  String DEFAULT '',
    city          String DEFAULT '',
    lat           Float64 DEFAULT 0,
    lon           Float64 DEFAULT 0,
    asn           String DEFAULT '',
    org           String DEFAULT '',
    isp           String DEFAULT '',
    updated_at    DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY target;
