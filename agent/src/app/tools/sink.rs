use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::sync::Mutex;

use colored::Colorize;
use serde_json::{Map, Value};

use super::common::ExternalReq;

#[derive(Clone, Copy)]
pub enum Stage {
    Rustscan,
    Masscan,
    Nmap,
    Httpx,
    Nuclei,
    Fuzzing,
    Ssl,
    Dns,
    Whois,
    Geo,
    Hxn,
    Subdomain,
    CtLog,
    DnsRecords,
    DeepTls,
}

impl Stage {
    pub fn checkout_path(self) -> &'static str {
        match self {
            Stage::Rustscan => "/api/checkout/rustscan",
            Stage::Masscan => "/api/checkout/masscan",
            Stage::Nmap => "/api/checkout/nmap",
            Stage::Httpx => "/api/checkout/httpx",
            Stage::Nuclei => "/api/checkout/nuclei",
            Stage::Fuzzing => "/api/checkout/fuzzing",
            Stage::Ssl => "/api/checkout/ssl",
            Stage::Dns => "/api/checkout/dns",
            Stage::Whois => "/api/checkout/whois",
            Stage::Geo => "/api/checkout/geo",
            Stage::Hxn => "/api/checkout/hxn",
            Stage::Subdomain => "/api/checkout/subdomain",
            Stage::CtLog => "/api/checkout/ctlog",
            Stage::DnsRecords => "/api/checkout/dnsrecords",
            Stage::DeepTls => "/api/checkout/deeptls",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Stage::Rustscan => "rustscan",
            Stage::Masscan => "masscan",
            Stage::Nmap => "nmap",
            Stage::Httpx => "httpx",
            Stage::Nuclei => "nuclei",
            Stage::Fuzzing => "fuzzing",
            Stage::Ssl => "ssl",
            Stage::Dns => "dns",
            Stage::Whois => "whois",
            Stage::Geo => "geo",
            Stage::Hxn => "hxn",
            Stage::Subdomain => "subdomain",
            Stage::CtLog => "ctlog",
            Stage::DnsRecords => "dnsrecords",
            Stage::DeepTls => "deeptls",
        }
    }
}

#[derive(Default)]
pub struct LocalReport {
    pub entries: Vec<(Stage, ExternalReq)>,
    pub screenshots: Vec<String>,
}

impl LocalReport {
    pub fn push(&mut self, stage: Stage, req: ExternalReq) {
        self.entries.push((stage, req));
    }

    pub fn note_screenshot(&mut self, path: &str) {
        if !path.is_empty() {
            self.screenshots.push(path.to_string());
        }
    }

    fn grouped(&self) -> BTreeMap<String, Map<String, Value>> {
        let mut targets: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        for (stage, req) in &self.entries {
            let parsed = serde_json::from_str::<Value>(&req.body)
                .unwrap_or_else(|_| Value::String(req.body.clone()));
            let t = targets.entry(req.target.clone()).or_default();
            let arr = t
                .entry(stage.name().to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(a) = arr {
                a.push(parsed);
            }
        }
        targets
    }

    pub fn to_json(&self) -> Value {
        let targets = self.grouped();
        let targets_val: Map<String, Value> = targets
            .into_iter()
            .map(|(k, v)| (k, Value::Object(v)))
            .collect();
        serde_json::json!({
            "tool": "aether-agent",
            "version": crate::config::VERSION,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "targets": Value::Object(targets_val),
        })
    }

    pub fn summary(&self) -> String {
        let targets = self.grouped();
        let mut out = String::new();
        out.push_str(&format!(
            "\n{}\n",
            "══ Aether recon summary ══".bold().cyan()
        ));
        if targets.is_empty() {
            out.push_str(&format!("{}\n", "  (no results collected)".dimmed()));
            return out;
        }
        for (target, stages) in &targets {
            out.push_str(&format!("\n{} {}\n", "▸".cyan(), target.bold()));

            let ports = collect_ports(stages);
            if !ports.is_empty() {
                let shown: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                out.push_str(&format!(
                    "  {} {}\n",
                    "open ports:".green(),
                    shown.join(", ")
                ));
            }

            let urls = collect_strings(stages, "httpx", "url");
            if !urls.is_empty() {
                out.push_str(&format!(
                    "  {} {}\n",
                    "live urls:".green(),
                    urls.len()
                ));
                for u in urls.iter().take(10) {
                    out.push_str(&format!("    {}\n", u.dimmed()));
                }
            }

            let techs = collect_array_strings(stages, "httpx", "technologies");
            if !techs.is_empty() {
                out.push_str(&format!(
                    "  {} {}\n",
                    "techs:".green(),
                    techs.into_iter().collect::<Vec<_>>().join(", ")
                ));
            }

            let sans = collect_array_strings(stages, "ssl", "san");
            if !sans.is_empty() {
                let n = sans.len();
                let shown: Vec<String> = sans.into_iter().take(12).collect();
                out.push_str(&format!(
                    "  {} {} ({})\n",
                    "cert SANs:".green(),
                    shown.join(", "),
                    n
                ));
            }

            let dns = dns_counts(stages);
            if !dns.is_empty() {
                out.push_str(&format!("  {} {}\n", "dns:".green(), dns));
            }

            let whois = whois_line(stages);
            if let Some(w) = whois {
                out.push_str(&format!("  {} {}\n", "whois:".green(), w));
            }

            let nuclei = flat_rows(stages, "nuclei").len();
            if nuclei > 0 {
                out.push_str(&format!(
                    "  {} {}\n",
                    "nuclei findings:".yellow(),
                    nuclei
                ));
            }
        }
        if !self.screenshots.is_empty() {
            out.push_str(&format!(
                "\n  {} {}\n",
                "screenshots:".green(),
                self.screenshots.len()
            ));
        }
        out
    }
}

fn flat_rows<'a>(stages: &'a Map<String, Value>, stage: &str) -> Vec<&'a Value> {
    let mut out = Vec::new();
    if let Some(Value::Array(entries)) = stages.get(stage) {
        for e in entries {
            match e {
                Value::Array(inner) => out.extend(inner.iter()),
                other => out.push(other),
            }
        }
    }
    out
}

fn collect_ports(stages: &Map<String, Value>) -> BTreeSet<i64> {
    let mut ports: BTreeSet<i64> = BTreeSet::new();
    for stage in ["rustscan", "masscan"] {
        for row in flat_rows(stages, stage) {
            if let Some(n) = row.as_i64() {
                ports.insert(n);
            }
        }
    }
    for row in flat_rows(stages, "nmap") {
        if let Some(p) = row.get("port").and_then(|v| v.as_str()) {
            if let Ok(n) = p.parse::<i64>() {
                ports.insert(n);
            }
        }
    }
    ports
}

fn collect_strings(stages: &Map<String, Value>, stage: &str, key: &str) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for row in flat_rows(stages, stage) {
        if let Some(v) = row.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() && seen.insert(v.to_string()) {
                out.push(v.to_string());
            }
        }
    }
    out
}

fn collect_array_strings(stages: &Map<String, Value>, stage: &str, key: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for row in flat_rows(stages, stage) {
        if let Some(Value::Array(arr)) = row.get(key) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    if !s.is_empty() {
                        out.insert(s.to_string());
                    }
                }
            }
        }
    }
    out
}

fn dns_counts(stages: &Map<String, Value>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for key in ["a", "aaaa", "cname", "mx", "ns", "txt", "ptr"] {
        let mut set: BTreeSet<String> = BTreeSet::new();
        for row in flat_rows(stages, "dns") {
            if let Some(Value::Array(arr)) = row.get(key) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        if !s.is_empty() {
                            set.insert(s.to_string());
                        }
                    }
                }
            }
        }
        if !set.is_empty() {
            parts.push(format!("{}={}", key, set.len()));
        }
    }
    parts.join(" ")
}

fn whois_line(stages: &Map<String, Value>) -> Option<String> {
    for row in flat_rows(stages, "whois") {
        let registrar = row.get("registrar").and_then(|v| v.as_str()).unwrap_or("");
        let org = row.get("organization").and_then(|v| v.as_str()).unwrap_or("");
        let parts: Vec<&str> = [registrar, org].into_iter().filter(|s| !s.is_empty()).collect();
        if !parts.is_empty() {
            return Some(parts.join(" / "));
        }
    }
    None
}

#[derive(Clone)]
pub enum Sink {
    Backend { base: String, api_key: String },
    Local(Arc<Mutex<LocalReport>>),
}

impl Sink {
    pub fn is_local(&self) -> bool {
        matches!(self, Sink::Local(_))
    }

    pub async fn note_screenshot(&self, path: &str) {
        if let Sink::Local(rep) = self {
            rep.lock().await.note_screenshot(path);
        }
    }

    pub async fn emit(&self, stage: Stage, req: ExternalReq) -> anyhow::Result<()> {
        match self {
            Sink::Backend { base, api_key } => {
                let url = format!("{}{}", base.trim_end_matches('/'), stage.checkout_path());
                let r = super::common::post_json(&url, &req, api_key).await?;
                if !r.status().is_success() {
                    tracing::warn!(status = %r.status(), path = stage.checkout_path(), "checkout non-200");
                }
                Ok(())
            }
            Sink::Local(rep) => {
                rep.lock().await.push(stage, req);
                Ok(())
            }
        }
    }
}
