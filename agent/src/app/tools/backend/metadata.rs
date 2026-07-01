use std::fs;
use std::net::UdpSocket;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct AgentMetadata {
    pub hostname: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub kernel: Option<String>,
    pub ip: String,
}

impl AgentMetadata {
    pub fn collect(version: &str) -> Self {
        let hostname = Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".into());

        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_string());

        let ip = match std::env::var("AGENT_ADDRESS")
            .ok()
            .filter(|v| !v.is_empty())
        {
            Some(v) => v,
            None => (|| {
                let s = UdpSocket::bind("0.0.0.0:0").ok()?;
                s.connect("8.8.8.8:53").ok()?;
                Some(s.local_addr().ok()?.ip().to_string())
            })()
            .unwrap_or_else(|| "unknown".into()),
        };

        Self {
            hostname,
            version: version.to_string(),
            os,
            arch,
            kernel,
            ip,
        }
    }
}
