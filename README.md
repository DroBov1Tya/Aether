# Aether

A self-hosted internet reconnaissance platform: point it at IPs, domains or CIDR ranges, and it scans them, stores every result, and gives you a Shodan-style search over your own data.

Built in Rust end to end. The scanning agents are distributed — run one on your laptop or scale a fleet on VPS hosts behind a central backend. No SaaS, no data leaving your box.

## Contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Standalone scans](#standalone-scans)
- [Distributed agents](#distributed-agents)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [API](#api)
- [Limitations and honest caveats](#limitations-and-honest-caveats)
- [License](#license)

## What it does

**Scanning pipeline.** Each target goes through a chain of proven tools; every stage feeds the next:

```
target (IP / domain / CIDR)
  masscan    optional line-rate port discovery (raw sockets, VPS only)
  rustscan   port sweep
  nmap       service and version detection
  httpx      live web probe, tech detection, screenshots
  nuclei     vulnerability hunt over confirmed URLs
  fuzz       path and content fuzzing
  tlsx       TLS versions, ciphers, SAN, JARM
  dnsx       resolution
  whois      registration data
```

**Passive discovery.** For domains, Aether enumerates subdomains from keyless sources (crt.sh, CertSpotter, OTX, HackerTarget, RapidDNS, Wayback CDX), filters wildcard DNS records, then recursively pivots through resolved IPs and InternetDB before the active stages run.

**Search and history.** Query your corpus by IP, domain, port, title, HTTP header, service, DNS record, SSL certificate or screenshot. Host pages keep every past scan as a snapshot — a time rail lets you compare what changed between scans.

**Projects.** Import external results (or Shodan exports) into named projects that stay separate from the public search index.

**Proxy pool.** Maintain a pool server-side; agents retry each stage direct-first, then through proxies in order.

## Quick start

Requirements: Docker with the compose plugin. 4 GB RAM is enough to start.

```sh
git clone https://github.com/DroBov1Tya/Aether.git
cd Aether
cp .env.example .env    # then edit: API_KEY, AUTH_CODE, passwords
docker compose up -d --build
```

- Web UI: <http://localhost:3000> (unlock with `AUTH_CODE`)
- API: <http://localhost:8080> (requests carry `X-API-KEY`)

Create a scan from the UI, watch it in the queue, open the host page when it finishes.

> One warning before large scans from home: the agent's traffic is NAT'd through your router, and a few thousand concurrent half-open connections can overflow a consumer router's conntrack table and take your whole LAN offline. Keep `MAX_CONCURRENT_SCANS` low and never use `port_mode: all` on big CIDRs locally — or run agents on a VPS (see below).

## Standalone scans

The agent binary also works with no backend, no registration, no database:

```sh
cd agent
cargo run --release -- scan https://example.com --out ./recon
```

It runs the same pipeline and writes a JSON report plus screenshots to the output directory.

| Flag | Meaning |
| --- | --- |
| `--portscan` | enable masscan/rustscan/nmap port scanning (off by default) |
| `--aggressive` | portscan plus noisier active checks |
| `--deep-tls` | extra TLS enumeration pass (versions, ciphers, chain) |
| `--proxy URL` | repeatable; used instead of a backend proxy pool |
| `--concurrency N` | targets scanned in parallel (default 3) |
| `--screenshots false` | disable browser screenshots |

## Distributed agents

To run scanning on separate machines against a central backend:

```sh
cp .env.agent.example .env
# set EXTERNAL_SERVER_PATH to the backend's public URL,
# plus API_KEY and a one-time ENROLL_TOKEN (POST /api/enroll-tokens)
docker compose -f compose.agent.yml up -d --scale agent=4
```

Agents self-register over outbound connections only, heartbeat every 15 seconds, and lease tasks from the backend queue. Per-agent concurrency is adjustable live from the agents page — no restart needed. Enrollment requires a one-time token (or an explicit `ALLOW_APIKEY_ENROLL=true`), so the registration endpoint is not open to strangers.

## Architecture

```
 frontend (Next.js 15)          agents ×N (Rust)
        │ HTTP                         │ claim tasks / POST results
        ▼                              ▼
 backend (Rust, axum) ──── task queue, dedup, search, stats
        │
 ├── ClickHouse   all scan results, history, agents, proxies
 └── MinIO/S3     screenshots (optional)
```

| Component | Role |
| --- | --- |
| `backend/` | axum API: task queue, result ingestion, search, stats, projects, Shodan import |
| `agent/` | runs the scanner tools; daemon mode (queue) and standalone mode (`scan` subcommand) |
| `frontend/` | search, host pages with time machine, scans, agents, proxies, import, Shodan |
| `compose.yml` | full stack: ClickHouse, MinIO, backend, frontend, local agent |
| `compose.agent.yml` | agent-only stack for remote scanning hosts |

Storage is ClickHouse because recon data is append-heavy, analytical, and wants history for free — every scan writes new rows, nothing is ever overwritten.

## Configuration

Everything is driven by `.env` (see `.env.example` for the annotated list). The knobs you are most likely to touch:

| Variable | Default | Purpose |
| --- | --- | --- |
| `API_KEY` | — | shared secret between backend and agents |
| `AUTH_CODE` | — | unlocks the web UI |
| `MAX_CONCURRENT_SCANS` | 3 | parallel targets per agent |
| `RUSTSCAN_MAX_BATCH` | 100 | hard cap on concurrent sockets |
| `MASSCAN_ENABLED` | false | line-rate discovery (VPS only, needs `NET_RAW`) |
| `NUCLEI_SEVERITY` | critical,high,medium | noise filter for the hunt layer |
| `SHODAN_API_KEY` | empty | enables the server-side Shodan import tab |

## API

All endpoints require `X-API-KEY`. The main groups:

| Group | Endpoints |
| --- | --- |
| Search | `/api/search/{ip,domain,port,title,header,service,dns,ssl,image}` |
| Hosts | `/api/host/{ip}`, `/api/host/{ip}/snapshots` |
| Scans | `/api/tasks/create`, `/api/tasks`, `/api/getlast` |
| Agents | `/api/agents`, `/api/enroll-tokens` |
| Data | `/api/import`, `/api/projects`, `/api/proxies`, `/api/shodan/*`, `/api/stats/*` |

## Limitations and honest caveats

- Aether is an asset-discovery and monitoring tool, not a crawler or a pentest suite. nuclei findings are leads, not verdicts.
- The web UI is gated by a shared `AUTH_CODE`, not per-user accounts. Put it behind TLS and a reverse proxy before exposing it anywhere.
- `docker/clickhouse-init.sql` runs only on an empty volume; schema changes after that need manual `ALTER`s.
- Standalone passive mode caps the active resolve set (wildcard filtering thousands of passive results is unbounded otherwise); the full passive list still lands in the report.

## License

MIT — see [LICENSE](LICENSE).
