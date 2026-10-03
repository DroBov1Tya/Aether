const IS_SERVER = typeof window === "undefined";
const API_BASE = IS_SERVER
  ? process.env.BACKEND_URL || "http://backend:8080"
  : "/api/proxy";
const API_KEY = process.env.API_KEY || "";

export interface HostSummary {
  target: string;
  port?: number;
  url?: string;
  http_status?: number;
  title?: string;
  technologies: string[];
  scanned_at: string;
}

export interface StatsSummary {
  total_hosts: number;
  total_ports: number;
  total_services: number;
  total_technologies: number;
}

export interface PortStat {
  port: number;
  count: number;
}
export interface ServiceStat {
  service: string;
  count: number;
}
export interface TechStat {
  technology: string;
  count: number;
}

export interface SearchResult {
  target: string;
  port?: number;
  protocol?: string;
  state?: string;
  service?: string;
  product?: string;
  version?: string;
  url?: string;
  http_status?: number;
  title?: string;
  technologies?: string[];
  headers?: string;
  scanned_at: string;
}

export interface NmapResult {
  port: number;
  protocol: string;
  state: string;
  service?: string;
  product?: string;
  version?: string;
  confidence?: number;
  detection_method?: string;
  extra_info?: string;
  os_type?: string;
  state_reason?: string;
  banner?: string;
  cpe?: string;
  scripts?: string;
  os_name?: string;
  os_accuracy?: number;
  ttl?: number;
  scanned_at: string;
}

export interface WhatWebResult {
  port: number;
  url?: string;
  http_status?: number;
  title?: string;
  technologies: string[];
  scanned_at: string;
}

export interface Screenshot {
  port: number;
  s3_key: string;
  file_size: number;
  taken_at: string;
  image_base64?: string;
  scan_uid?: string;
}

export interface HostSummaryData {
  open_ports: number;
  first_seen: string;
  last_seen: string;
  total_services?: number;
}

export interface HostData {
  nmap?: NmapResult[];
  whatweb?: WhatWebResult[];
  screenshots?: Screenshot[];
  dns?: DnsRecord | null;
  ssl?: SslCert[];
  fuzzing?: FuzzFinding[];
  summary?: HostSummaryData;
}

export interface FuzzFinding {
  port: number;
  path: string;
  url: string;
  http_status: number;
  scanned_at: string;
}

export interface DnsRecord {
  a?: string[];
  aaaa?: string[];
  cname?: string[];
  mx?: string[];
  ns?: string[];
  txt?: string[];
  ptr?: string[];
  scanned_at: string;
}

export interface SslCert {
  port: number;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  serial: string;
  san: string[];
  ssl_version: string;
  cipher: string;
  chain_length: number;
  scanned_at: string;
}

export interface AggregatedHost {
  target: string;
  ports: number[];
  technologies: string[];
  titles: string[];
  url?: string;
  http_status?: number;
  country?: string;
  country_code?: string;
  asn?: string;
  org?: string;
  first_seen: string;
  last_seen: string;
  scan_count: number;
  scan_uids: string[];
}

export interface GeoInfo {
  target: string;
  country: string;
  country_code: string;
  city: string;
  lat: number;
  lon: number;
  asn: string;
  org: string;
  isp: string;
}

export interface GeoStat {
  country?: string;
  country_code?: string;
  asn?: string;
  org?: string;
  count: number;
}

export interface SearchResponse<T> {
  status: string;
  page: number;
  per_page: number;
  total: number;
  data: T[];
}

export interface ScreenshotWithMeta {
  target: string;
  port: number;
  s3_key: string;
  file_size: number;
  taken_at: string;
  title?: string;
  http_status?: number;
  technologies?: string[];
  image_base64?: string;
}

export interface HostScanSnapshot {
  scan_uid: string;
  scanned_at: string;
  ports: number[];
  port_count: number;
  services: string[];
  products: string[];
}

export interface HostHistoryData {
  nmap: HostScanSnapshot[];
  whatweb: any[];
}

export interface HostSnapshot {
  scanned_at: string;
  nmap: any[];
  whatweb: any[];
  screenshots: any[];
  ssl: any[];
}

export interface HostSnapshotsResponse {
  target: string;
  snapshots: HostSnapshot[];
}

async function fetchJson<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers);
  headers.set("Content-Type", "application/json");
  if (IS_SERVER && API_KEY) headers.set("X-API-KEY", API_KEY);
  const url = `${API_BASE}${path.startsWith("/") ? path : "/" + path}`;
  const res = await fetch(url, { ...options, headers, cache: "no-store" });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text || res.statusText}`);
  }
  return res.json();
}

export async function fetchApi<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers);
  headers.set("Content-Type", "application/json");
  if (IS_SERVER && API_KEY) headers.set("X-API-KEY", API_KEY);
  const url = `${API_BASE}${path.startsWith("/") ? path : "/" + path}`;
  const res = await fetch(url, { ...options, headers, cache: "no-store" });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text || res.statusText}`);
  }
  const json = await res.json();
  return json.data ?? json;
}

export const getStatsSummary = async (): Promise<StatsSummary> => {
  const raw = await fetchApi<any[]>("/api/stats/summary");
  const d = raw[0] || {};
  return {
    total_hosts: d.total_hosts ?? 0,
    total_ports: d.unique_ports ?? 0,
    total_services: d.unique_services ?? 0,
    total_technologies: d.unique_technologies ?? 0,
  };
};
export const getTopPorts = (l = 10) =>
  fetchApi<PortStat[]>(`/api/stats/ports?limit=${l}`);
export const getTopServices = (l = 10) =>
  fetchApi<ServiceStat[]>(`/api/stats/services?limit=${l}`);
export const getTopTechnologies = (l = 20) =>
  fetchApi<TechStat[]>(`/api/stats/technologies?limit=${l}`);
export const getTopCountries = (l = 15) =>
  fetchApi<GeoStat[]>(`/api/stats/countries?limit=${l}`);
export const getTopAsns = (l = 15) =>
  fetchApi<GeoStat[]>(`/api/stats/asns?limit=${l}`);
export const getTopOrgs = (l = 15) =>
  fetchApi<GeoStat[]>(`/api/stats/orgs?limit=${l}`);
export const getRecentScans = () =>
  fetchApi<HostSummary[]>("/api/getlast?limit=12");

export const getHostDetails = async (ip: string): Promise<HostData> => {
  const raw = await fetchApi<any>(`/api/host/${encodeURIComponent(ip)}`);
  return {
    nmap: raw.open_ports || [],
    whatweb: raw.web_services || [],
    screenshots: raw.screenshots || [],
    dns: raw.dns || null,
    ssl: raw.ssl || [],
    summary: raw.summary || null,
  };
};

export const getHostHistory = (ip: string) =>
  fetchApi<HostHistoryData>(`/api/host/${encodeURIComponent(ip)}/history`);
export const getHostSnapshots = (ip: string) =>
  fetchApi<HostSnapshotsResponse>(
    `/api/host/${encodeURIComponent(ip)}/snapshots`,
  );

export const searchByIp = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(
    `/api/search/ip?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const searchByDomain = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(
    `/api/search/domain?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const searchByPort = (q: number, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(`/api/search/port?q=${q}&page=${p}&per_page=${pp}`);
export const searchByTitle = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(
    `/api/search/title?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const searchByHeader = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(
    `/api/search/header?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const searchByTechnology = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(
    `/api/search/technology?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const searchByProtocol = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(
    `/api/search/protocol?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const searchByService = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(
    `/api/search/service?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const searchByDns = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(
    `/api/search/dns?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const searchBySsl = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<SearchResult>>(
    `/api/search/ssl?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const searchAggregated = (q: string, p = 1, pp = 20) =>
  fetchJson<SearchResponse<AggregatedHost>>(
    `/api/search/aggregated?q=${encodeURIComponent(q)}&page=${p}&per_page=${pp}`,
  );
export const listScreenshots = (p = 1, pp = 20) =>
  fetchApi<ScreenshotWithMeta[]>(`/api/screenshots?page=${p}&per_page=${pp}`);
export const countScreenshots = () =>
  fetchApi<{ total: number }>(`/api/screenshots/count`);

export async function launchScan(payload: any) {
  if (IS_SERVER) throw new Error("launchScan can only be called from client");
  const res = await fetch(`${API_BASE}/api/scan/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Scan launch failed: ${res.status}`);
  return res.json();
}

// ---- Projects & import ----

export interface ProjectSummary {
  project: string;
  hosts: number;
  last_seen: string;
}

export interface ImportCounts {
  hosts: number;
  ports: number;
  http: number;
  tls: number;
  dns: number;
}

export const listProjects = () =>
  fetchApi<ProjectSummary[]>(`/api/projects`);

export const getProjectHosts = (project: string) =>
  fetchApi<AggregatedHost[]>(
    `/api/projects/hosts?project=${encodeURIComponent(project)}`,
  );

/** Import a normalized JSON payload into a named project (client-side). */
export async function importProject(payload: any) {
  if (IS_SERVER) throw new Error("importProject can only be called from client");
  const res = await fetch(`${API_BASE}/api/import`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(json?.error || `Import failed: ${res.status}`);
  }
  return json;
}

// ---- Proxy pool ----

export interface ProxyEntry {
  url: string;
  added_at: string;
}

export const listProxies = () => fetchApi<ProxyEntry[]>(`/api/proxies`);

/** Add proxies (one per line in `raw`). Client-side only. */
export async function addProxies(raw: string) {
  if (IS_SERVER) throw new Error("addProxies can only be called from client");
  const res = await fetch(`${API_BASE}/api/proxies`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json?.error || `Add failed: ${res.status}`);
  return json;
}

/** Remove a single proxy by exact URL. */
export async function deleteProxy(url: string) {
  if (IS_SERVER) throw new Error("deleteProxy can only be called from client");
  const res = await fetch(`${API_BASE}/api/proxies/one`, {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`Delete failed: ${res.status}`);
  return res.json().catch(() => ({}));
}

/** Clear the entire proxy pool. */
export async function deleteAllProxies() {
  if (IS_SERVER) throw new Error("deleteAllProxies can only be called from client");
  const res = await fetch(`${API_BASE}/api/proxies`, { method: "DELETE" });
  if (!res.ok) throw new Error(`Clear failed: ${res.status}`);
  return res.json().catch(() => ({}));
}

/** Update an agent's max concurrent scan capacity (applied live via heartbeat). */
export async function updateAgentConcurrency(agentId: string, max: number) {
  if (IS_SERVER) throw new Error("updateAgentConcurrency can only be called from client");
  const res = await fetch(`${API_BASE}/api/agents/${encodeURIComponent(agentId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ max_concurrent_tasks: max }),
  });
  if (!res.ok) throw new Error(`Update failed: ${res.status}`);
  return res.json().catch(() => ({}));
}

// ---- Geo / country → ASN → CIDR ----

export interface CountryAsn {
  asn: number;
  holder: string;
}

export interface CountryAsnsResponse {
  status: string;
  country: string;
  total: number;
  page: number;
  size: number;
  asns: CountryAsn[];
}

export const getCountryAsns = (
  country: string,
  q = "",
  page = 0,
  size = 40,
) =>
  fetchJson<CountryAsnsResponse>(
    `/api/geo/country-asns?country=${encodeURIComponent(country)}&q=${encodeURIComponent(q)}&page=${page}&size=${size}`,
  );

export interface AsnPrefixesResponse {
  status: string;
  count: number;
  cidrs: string[];
  per_asn: { asn: number; cidrs: string[] }[];
}

export const getAsnPrefixes = (asns: number[]) =>
  fetchJson<AsnPrefixesResponse>(
    `/api/geo/asn-prefixes?asns=${asns.join(",")}`,
  );

// ---- Shodan ----

export interface ShodanUsage {
  query_credits: number;
  scan_credits: number;
  monitored_ips: number | null;
  plan: string;
  https: boolean;
  unlocked: boolean;
  telnet: boolean;
  usage_limits?: Record<string, number>;
}

export const getShodanInfo = () =>
  fetchJson<{ status: string; info: ShodanUsage }>(`/api/shodan/info`);

export interface ShodanMatch {
  ip: string;
  port: number;
  transport: string;
  product: string;
  org: string;
  hostnames: string[];
  country_code: string;
}

export interface ShodanSearchResponse {
  status: string;
  total: number;
  page: number;
  returned: number;
  matches: ShodanMatch[];
}

export async function shodanSearch(query: string, page = 1) {
  if (IS_SERVER) throw new Error("shodanSearch can only be called from client");
  const res = await fetch(
    `${API_BASE}/api/shodan/search?query=${encodeURIComponent(query)}&page=${page}`,
  );
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json?.error || `Shodan search failed: ${res.status}`);
  return json as ShodanSearchResponse;
}

export async function shodanImport(
  query: string,
  pages: number,
  project?: string,
) {
  if (IS_SERVER) throw new Error("shodanImport can only be called from client");
  const res = await fetch(`${API_BASE}/api/shodan/import`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query, pages, project }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json?.error || `Shodan import failed: ${res.status}`);
  return json;
}

export interface ShodanHostInfo {
  status: string;
  ip: string;
  ports: number[];
  hostnames: string[];
  org: string;
  asn: string;
  country_code: string;
  os: string;
  last_update: string;
}

export async function shodanHostLookup(ip: string) {
  if (IS_SERVER) throw new Error("shodanHostLookup can only be called from client");
  const res = await fetch(`${API_BASE}/api/shodan/host?ip=${encodeURIComponent(ip)}`);
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json?.error || `Shodan host lookup failed: ${res.status}`);
  return json as ShodanHostInfo;
}

export async function shodanImportHosts(ips: string[], project?: string) {
  if (IS_SERVER) throw new Error("shodanImportHosts can only be called from client");
  const res = await fetch(`${API_BASE}/api/shodan/import-hosts`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips, project }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json?.error || `Shodan host import failed: ${res.status}`);
  return json;
}
