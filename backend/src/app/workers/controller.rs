use std::net::Ipv4Addr;

pub fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

pub fn u32_to_ipv4(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n)
}

pub fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let base = ipv4_to_u32(ip);
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let network = base & mask;
    let broadcast = network | (!0u32 >> prefix);
    Some((network, broadcast))
}

pub fn parse_range(range: &str) -> Option<(u32, u32)> {
    let (start_str, end_str) = range.split_once('-')?;
    let start: Ipv4Addr = start_str.trim().parse().ok()?;
    let end: Ipv4Addr = end_str.trim().parse().ok()?;
    let s = ipv4_to_u32(start);
    let e = ipv4_to_u32(end);
    if s > e {
        return None;
    }
    Some((s, e))
}
