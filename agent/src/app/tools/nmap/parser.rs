use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "host", default)]
    hosts: Vec<Host>,
}

#[derive(Debug, Deserialize)]
struct Host {
    #[serde(rename = "address")]
    address: Option<Vec<Address>>,
    #[serde(rename = "ports")]
    ports: Option<PortsContainer>,
    #[serde(rename = "os")]
    os: Option<Os>,
}

#[derive(Debug, Deserialize)]
struct Address {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addr_type: String,
}

#[derive(Debug, Deserialize)]
struct PortsContainer {
    #[serde(rename = "port", default)]
    port: Vec<Port>,
}

#[derive(Debug, Deserialize)]
pub struct Port {
    #[serde(rename = "@protocol")]
    protocol: String,
    #[serde(rename = "@portid")]
    portid: String,
    #[serde(rename = "state")]
    state: State,
    #[serde(rename = "service")]
    service: Option<Service>,
    #[serde(rename = "script", default)]
    scripts: Vec<Script>,
}

#[derive(Debug, Deserialize)]
struct State {
    #[serde(rename = "@state")]
    state: String,
    #[serde(rename = "@reason")]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(rename = "@extrainfo")]
    extra_info: Option<String>,
    #[serde(rename = "@ostype")]
    os_type: Option<String>,
    #[serde(rename = "@method")]
    method: Option<String>,
    #[serde(rename = "@conf")]
    conf: Option<String>,
    #[serde(rename = "@tunnel")]
    tunnel: Option<String>,
    #[serde(rename = "cpe", default)]
    cpe: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Script {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@output")]
    output: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Os {
    #[serde(rename = "osmatch", default)]
    osmatch: Vec<OsMatch>,
}

#[derive(Debug, Deserialize)]
struct OsMatch {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@accuracy")]
    accuracy: Option<String>,
}

pub fn parse_nmap_xml(path: &str) -> Result<Vec<HashMap<String, String>>> {
    let content = std::fs::read_to_string(path).context("failed to read nmap xml")?;
    let run: NmapRun = quick_xml::de::from_str(&content).context("failed to parse nmap xml")?;

    let mut results = Vec::new();

    for host in run.hosts.iter() {
        let ip = host
            .address
            .as_ref()
            .and_then(|addrs| addrs.iter().find(|a| a.addr_type == "ipv4"))
            .map(|a| a.addr.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let os_name = host
            .os
            .as_ref()
            .and_then(|os| os.osmatch.first())
            .map(|m| m.name.clone());
        let os_accuracy = host
            .os
            .as_ref()
            .and_then(|os| os.osmatch.first())
            .and_then(|m| m.accuracy.clone());

        if let Some(ports) = &host.ports {
            for port in &ports.port {
                let mut port_info = HashMap::new();

                port_info.insert("host".to_string(), ip.clone());
                port_info.insert("port".to_string(), port.portid.clone());
                port_info.insert("protocol".to_string(), port.protocol.clone());
                port_info.insert("state".to_string(), port.state.state.clone());

                if let Some(reason) = &port.state.reason {
                    port_info.insert("state_reason".to_string(), reason.clone());
                }

                if let Some(svc) = &port.service {
                    port_info.insert("service".to_string(), svc.name.clone());

                    if let Some(product) = &svc.product {
                        port_info.insert("product".to_string(), product.clone());
                    }
                    if let Some(version) = &svc.version {
                        port_info.insert("version".to_string(), version.clone());
                    }
                    if let Some(extra) = &svc.extra_info {
                        port_info.insert("extra_info".to_string(), extra.clone());
                    }
                    if let Some(os_type) = &svc.os_type {
                        port_info.insert("os_type".to_string(), os_type.clone());
                    }
                    if let Some(method) = &svc.method {
                        port_info.insert("detection_method".to_string(), method.clone());
                    }
                    if let Some(conf) = &svc.conf {
                        port_info.insert("confidence".to_string(), conf.clone());
                    }
                    if let Some(tunnel) = &svc.tunnel {
                        port_info.insert("tunnel".to_string(), tunnel.clone());
                    }

                    if !svc.cpe.is_empty() {
                        port_info.insert("cpe".to_string(), svc.cpe.join(", "));
                    }
                }

                if !port.scripts.is_empty() {
                    let scripts_json: Vec<String> = port
                        .scripts
                        .iter()
                        .map(|s| {
                            let output = s
                                .output
                                .as_deref()
                                .unwrap_or("")
                                .replace('\\', "\\\\")
                                .replace('"', "\\\"")
                                .replace('\n', "\\n")
                                .replace('\r', "");
                            format!("\"{}\":\"{}\"", s.id, output)
                        })
                        .collect();
                    port_info.insert(
                        "scripts".to_string(),
                        format!("{{{}}}", scripts_json.join(",")),
                    );
                }

                if let Some(ref name) = os_name {
                    port_info.insert("os_name".to_string(), name.clone());
                }
                if let Some(ref acc) = os_accuracy {
                    port_info.insert("os_accuracy".to_string(), acc.clone());
                }

                results.push(port_info);
            }
        }
    }

    Ok(results)
}
