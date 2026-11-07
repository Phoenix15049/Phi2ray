//! sing-box config for VPN mode. sing-box only owns the TUN adapter, routes and DNS;
//! all traffic is handed to xray's local SOCKS inbound, so every xray transport
//! (XHTTP, REALITY, ...) works in VPN mode too.

use std::net::IpAddr;
use std::path::Path;

use serde_json::{json, Value};
use url::Url;

use crate::helper_protocol::TUN_NAME;
use crate::split::{Rules as SplitRules, SplitMode};
use crate::store::Settings;

/// The VPN adapter's own IPv4 address (must match the kill switch's TUN range in firewall.rs).
pub const ADAPTER_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(172, 19, 0, 1);

pub struct TunInput<'a> {
    pub socks_port: u16,
    pub socks_user: &'a str,
    pub socks_pass: &'a str,
    /// The proxy server's resolved IP. It is routed outside the tunnel at the OS level,
    /// so xray's connection to it can never loop back into the tunnel.
    pub server_ip: IpAddr,
    /// Phi2ray's own xray, the only program that skips the tunnel by itself.
    pub xray_exe: &'a Path,
    /// On Linux, the account both cores run as. Everything it sends stays outside the tunnel.
    pub core_uid: Option<u32>,
    /// The network's own DNS server, where the system's resolver can't be used for direct lookups.
    pub local_dns: Option<IpAddr>,
    pub settings: &'a Settings,
}

fn xray_rule(exe: &Path) -> Value {
    match crate::split::app_pattern(&exe.to_string_lossy()) {
        Some(pattern) => json!({ "process_path_regex": [pattern], "outbound": "direct" }),
        None => json!({ "process_name": [exe.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()], "outbound": "direct" }),
    }
}

pub fn build(t: &TunInput) -> Result<Value, String> {
    let s = t.settings;

    let mut remote_dns = dns_server(&s.remote_dns)?;
    remote_dns["tag"] = json!("remote");
    // DNS goes through the tunnel, so the ISP never sees lookups.
    remote_dns["detour"] = json!("proxy");

    let server_cidr = match t.server_ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    };

    let mut route_rules = vec![
        json!({ "action": "sniff" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
        json!({ "port": 53, "action": "hijack-dns" }),
        // Second line of defence against loops: xray's own traffic always leaves directly.
        // Matched by full path, so another program named xray.exe stays in the tunnel.
        xray_rule(t.xray_exe),
        json!({ "ip_cidr": [server_cidr], "outbound": "direct" }),
    ];
    let mut dns_rules = Vec::new();

    // Split tunnel rules come right after the safety rules above, so they decide first.
    let mut final_outbound = "proxy";
    let mut block_quic = s.block_quic;
    if let Some(split) = s.split.rules() {
        match s.split.mode {
            SplitMode::Exclude => {
                route_rules.extend(split_rules(&split, json!({ "outbound": "direct" })));
                if !split.domains.is_empty() {
                    // Bypassed sites resolve with the normal DNS, so they get nearby servers.
                    dns_rules.push(json!({ "domain_suffix": split.domains, "server": "local" }));
                }
            }
            SplitMode::Include => {
                if block_quic {
                    route_rules.extend(split_rules(&split, json!({ "network": "udp", "port": 443, "action": "reject" })));
                }
                route_rules.extend(split_rules(&split, json!({ "outbound": "proxy" })));
                // Everything else goes direct, QUIC included (it isn't proxied, so no reason to block it).
                final_outbound = "direct";
                block_quic = false;
            }
        }
    }
    if block_quic {
        // Browsers fall back to TCP right away, which is faster and steadier through the proxy.
        route_rules.push(json!({ "network": "udp", "port": 443, "action": "reject" }));
    }
    if s.bypass_lan {
        route_rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));
    }
    if s.iran_direct {
        route_rules.push(json!({ "domain_suffix": ["ir"], "outbound": "direct" }));
        dns_rules.push(json!({ "domain_suffix": ["ir"], "server": "local" }));
    }

    let log_level = if s.log_level == "warning" { "warn" } else { s.log_level.as_str() };
    // Without IPv6, only ask for IPv4 so apps don't try addresses that can't work.
    let dns_strategy = if s.ipv6 { "prefer_ipv4" } else { "ipv4_only" };

    let local_dns = match t.local_dns {
        Some(ip) => json!({ "type": "udp", "tag": "local", "server": ip.to_string() }),
        None => json!({ "type": "local", "tag": "local" }),
    };

    let mut config = json!({
        "log": { "level": log_level, "timestamp": false },
        "dns": {
            "servers": [
                remote_dns,
                // Resolves DoH/DoT hostnames (e.g. dns.adguard-dns.com) through the tunnel, so the
                // ISP can neither see nor tamper with that lookup.
                { "type": "tcp", "tag": "bootstrap", "server": "1.1.1.1", "detour": "proxy" },
                local_dns
            ],
            "rules": dns_rules,
            "final": "remote",
            "strategy": dns_strategy
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": TUN_NAME,
            // IPv6 is always captured, so it can't leak around the tunnel.
            "address": [format!("{ADAPTER_V4}/30"), "fdfe:dcba:9876::1/126"],
            "mtu": s.tun_mtu,
            "auto_route": true,
            "strict_route": s.strict_route,
            "route_exclude_address": [server_cidr],
            "stack": s.tun_stack
        }],
        "outbounds": [
            {
                "type": "socks",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": t.socks_port,
                "version": "5",
                "username": t.socks_user,
                "password": t.socks_pass
            },
            { "type": "direct", "tag": "direct" }
        ],
        "route": {
            "rules": route_rules,
            "final": final_outbound,
            "auto_detect_interface": true,
            "default_domain_resolver": "local"
        }
    });
    if let Some(uid) = t.core_uid {
        config["inbounds"][0]["exclude_uid"] = json!([uid]);
    }
    Ok(config)
}

/// The first DNS server in a `resolv.conf` that isn't this computer itself.
#[cfg_attr(windows, allow(dead_code))]
pub fn first_nameserver(resolv_conf: &str) -> Option<IpAddr> {
    resolv_conf
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|server| server.trim().parse::<IpAddr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
}

/// One sing-box rule per kind of split entry (apps, domains, IP ranges), each with `action` merged in.
fn split_rules(split: &SplitRules, action: Value) -> Vec<Value> {
    let mut rules = Vec::new();
    let mut add = |field: &str, values: &[String]| {
        if !values.is_empty() {
            let mut rule = action.clone();
            rule[field] = json!(values);
            rules.push(rule);
        }
    };
    add("process_path_regex", &split.app_patterns);
    add("domain_suffix", &split.domains);
    add("ip_cidr", &split.cidrs);
    rules
}

/// Turns a DNS address into a sing-box DNS server object. Accepts a plain IP,
/// `https://host/path` (DoH), `tls://host` (DoT), `tcp://host` or `udp://host`.
pub fn dns_server(address: &str) -> Result<Value, String> {
    let address = address.trim();
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(json!({ "type": "udp", "server": ip.to_string() }));
    }
    let invalid = || format!("Invalid DNS server: {address}");
    let url = Url::parse(address).map_err(|_| invalid())?;
    let host = url.host_str().ok_or_else(invalid)?.trim_start_matches('[').trim_end_matches(']').to_string();

    let mut server = match url.scheme() {
        "https" => {
            let mut v = json!({ "type": "https", "server": host });
            if !matches!(url.path(), "" | "/") {
                v["path"] = json!(url.path());
            }
            v
        }
        scheme @ ("tls" | "tcp" | "udp") => json!({ "type": scheme, "server": host }),
        _ => return Err(format!("Unsupported DNS scheme in {address}. Use https://, tls://, tcp:// or udp://.")),
    };
    if let Some(port) = url.port() {
        server["server_port"] = json!(port);
    }
    if host.parse::<IpAddr>().is_err() {
        // A DoH/DoT hostname must itself be resolved first.
        server["domain_resolver"] = json!("bootstrap");
    }
    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(settings: &Settings) -> TunInput<'_> {
        TunInput {
            socks_port: 9,
            socks_user: "u",
            socks_pass: "p",
            server_ip: "203.0.113.7".parse().unwrap(),
            xray_exe: Path::new(r"C:\Program Files\Phi2ray\core-0.1.0\xray.exe"),
            core_uid: None,
            local_dns: None,
            settings,
        }
    }

    #[test]
    fn excludes_server_and_routes_rest_to_xray() {
        let c = build(&input(&Settings::default())).unwrap();
        assert_eq!(c["route"]["final"], "proxy");
        assert_eq!(c["outbounds"][0]["server_port"], 9);
        assert_eq!(c["inbounds"][0]["route_exclude_address"][0], "203.0.113.7/32");
        assert_eq!(c["dns"]["strategy"], "ipv4_only");
        assert!(c["dns"]["rules"].as_array().unwrap().is_empty());
        assert_eq!(c["log"]["level"], "warn");
        // Only Phi2ray's own xray skips the tunnel, matched by its full path.
        let xray = &c["route"]["rules"][3]["process_path_regex"][0];
        assert_eq!(xray, r"(?i)^C:\\Program Files\\Phi2ray\\core-0\.1\.0\\xray\.exe$");
        assert!(c["route"]["rules"].as_array().unwrap().iter().all(|r| r["process_name"].is_null()));
    }

    #[test]
    fn split_modes() {
        use crate::split::{SplitMode, SplitTunnel};
        let split = |mode| SplitTunnel { enabled: true, mode, apps: vec!["Telegram.exe".into()], sites: vec!["a.com".into()] };
        let exclude = Settings { split: split(SplitMode::Exclude), ..Settings::default() };
        let c = build(&input(&exclude)).unwrap();
        let rules = c["route"]["rules"].as_array().unwrap();
        let app = rules.iter().position(|r| r["process_path_regex"].is_array()).unwrap();
        let quic = rules.iter().position(|r| r["port"] == 443).unwrap();
        assert!(app < quic, "split rules decide before QUIC blocking");
        assert_eq!(rules[app]["outbound"], "direct");
        assert_eq!(c["route"]["final"], "proxy");
        assert_eq!(c["dns"]["rules"][0]["server"], "local");

        let include = Settings { split: split(SplitMode::Include), ..Settings::default() };
        let c = build(&input(&include)).unwrap();
        assert_eq!(c["route"]["final"], "direct");
        let rules = c["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["domain_suffix"][0] == "a.com" && r["outbound"] == "proxy"));
        // QUIC is only blocked for traffic that goes through the server.
        assert!(rules.iter().filter(|r| r["port"] == 443).all(|r| !r["process_path_regex"].is_null() || !r["domain_suffix"].is_null()));
    }

    #[test]
    fn the_helper_accepts_every_config_the_app_builds() {
        use crate::helper_protocol::check_tun_config;
        use crate::split::{SplitMode, SplitTunnel};
        fn linux(settings: &Settings) -> Value {
            let input = TunInput { core_uid: Some(990), local_dns: Some("192.168.1.1".parse().unwrap()), ..input(settings) };
            build(&input).unwrap()
        }
        let plain = Settings::default();
        let c = linux(&plain);
        assert_eq!(c["inbounds"][0]["exclude_uid"], json!([990]));
        assert_eq!(c["dns"]["servers"][2], json!({ "type": "udp", "tag": "local", "server": "192.168.1.1" }));
        check_tun_config(&c, 990).unwrap();

        let split = SplitTunnel { enabled: true, mode: SplitMode::Exclude, apps: vec!["firefox".into()], sites: vec!["a.com".into(), "1.2.3.4".into()] };
        for mode in [SplitMode::Exclude, SplitMode::Include] {
            let settings = Settings {
                split: SplitTunnel { mode, ..split.clone() },
                iran_direct: true,
                remote_dns: "https://dns.adguard-dns.com/dns-query".into(),
                ..Settings::default()
            };
            check_tun_config(&linux(&settings), 990).unwrap();
        }
    }

    #[test]
    fn the_stub_resolver_is_skipped() {
        assert_eq!(first_nameserver("# stub\nnameserver 127.0.0.53\noptions edns0\n"), None);
        let found = first_nameserver("nameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 8.8.8.8\n");
        assert_eq!(found, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn dns_forms() {
        assert_eq!(dns_server("8.8.8.8").unwrap(), json!({ "type": "udp", "server": "8.8.8.8" }));
        let doh = dns_server("https://1.1.1.1/dns-query").unwrap();
        assert_eq!((doh["type"].as_str(), doh["path"].as_str()), (Some("https"), Some("/dns-query")));
        assert!(doh.get("domain_resolver").is_none());
        assert_eq!(dns_server("https://dns.google/dns-query").unwrap()["domain_resolver"], "bootstrap");
        assert_eq!(dns_server("tls://9.9.9.9:853").unwrap()["server_port"], 853);
        assert!(dns_server("ftp://x").is_err());
        assert!(dns_server("not a server").is_err());
    }
}
