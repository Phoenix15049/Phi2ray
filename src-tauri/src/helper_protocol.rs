//! What the app and `phi2ray-helper` (Linux only) say to each other, plus the checks that have to
//! be the same on both sides. The helper includes this same file, the way the console tool
//! includes `ipc.rs`. Nothing here changes the system, so its tests also run on Windows.
//!
//! The app runs as the user. `pkexec` starts the helper as root, with pipes to the app on its
//! stdin and stdout, so nothing else can reach it: there is no socket and no service. The app
//! writes `Request`s as JSON lines; the helper answers with `Message`s.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Bumped when a request or message changes in a way the other side can't read.
pub const VERSION: u32 = 1;
/// Largest request accepted: a config, with room to spare.
pub const MAX_REQUEST: u64 = 8 * 1024 * 1024;
/// The VPN adapter's name.
pub const TUN_NAME: &str = "Phi2ray";
/// The system account both cores run as. The kill switch lets exactly this account out, and
/// only root can start a program under it.
pub const CORE_USER: &str = "phi2ray-core";
/// Exists while the kill switch is on. `/run` is cleared on restart, exactly like the firewall
/// rules, and everyone can read it, so the app can see the state without asking for a password.
pub const KILL_SWITCH_FLAG: &str = "/run/phi2ray/kill-switch";

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Core {
    Xray,
    Tun,
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub command: Command,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "name", rename_all = "kebab-case")]
pub enum Command {
    Hello { version: u32 },
    /// `ports` are xray's local ports: it counts as started once it alone listens on all of them.
    StartXray { config: String, ports: Vec<u16> },
    /// Checked with `check_tun_config` first, since sing-box keeps network rights.
    StartTun { config: String },
    Stop { core: Core },
    /// A throwaway xray for the delay test, listening on `port`.
    StartTest { config: String, port: u16 },
    StopTest { test: u64 },
    KillSwitch { on: bool, allow_lan: bool },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Message {
    Reply { id: u64, outcome: Outcome },
    Log { tag: String, line: String },
    /// A core stopped without being asked to.
    Exited { core: Core, status: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum Outcome {
    Done,
    Hello { core_uid: u32 },
    Test { test: u64 },
    PortTaken { port: u16 },
    Failed { error: String },
}

/// The kill switch as one nftables script, applied in a single transaction, so replacing the
/// rules never leaves a gap. Same rules as the Windows filters in `firewall.rs`: loopback, the
/// cores' account, the VPN adapter, DHCP and IPv6 link-local, and the local network if wanted.
/// `forward` is covered too, so containers and virtual machines can't go around it.
///
/// There's no `ct state` rule on the way out: a connection opened before the kill switch must not
/// keep going over the real network.
pub fn nft_rules(core_uid: u32, allow_lan: bool) -> String {
    const V4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255";
    const V6: &str = "fc00::/7";
    let lan = |direction: &str| {
        if allow_lan {
            format!("        ip {direction} {{ {V4} }} accept\n        ip6 {direction} {{ {V6} }} accept\n")
        } else {
            String::new()
        }
    };
    let (lan_out, lan_in) = (lan("daddr"), lan("saddr"));
    format!(
        r#"table inet phi2ray
delete table inet phi2ray
table inet phi2ray {{
    chain output {{
        type filter hook output priority -10; policy drop;
        oifname "lo" accept
        oifname "{TUN_NAME}" accept
        meta skuid {core_uid} accept
        udp sport 68 udp dport 67 accept
        udp sport 546 udp dport 547 accept
        ip6 daddr {{ fe80::/10, ff00::/8 }} accept
{lan_out}    }}
    chain input {{
        type filter hook input priority -10; policy drop;
        iifname "lo" accept
        iifname "{TUN_NAME}" accept
        ct state established,related accept
        udp sport 67 udp dport 68 accept
        udp sport 547 udp dport 546 accept
        ip6 saddr fe80::/10 accept
{lan_in}    }}
    chain forward {{
        type filter hook forward priority -10; policy drop;
        oifname "{TUN_NAME}" accept
        iifname "{TUN_NAME}" accept
{lan_out}    }}
}}
"#
    )
}

/// Removes the kill switch, whether or not it's there, in one transaction.
pub const NFT_REMOVE: &str = "table inet phi2ray\ndelete table inet phi2ray\n";

/// Accepts only the shape of config `tun.rs` builds. sing-box keeps network rights, and a config
/// can name files (logs, caches, certificates) and open control ports, so the helper doesn't take
/// the app's word for it: if a program ever got hold of the app, this is as far as it gets.
pub fn check_tun_config(config: &Value, core_uid: u32) -> Result<(), String> {
    fn keys(what: &str, value: &Value, allowed: &[&str]) -> Result<(), String> {
        let map = value.as_object().ok_or_else(|| format!("{what} isn't an object"))?;
        match map.keys().find(|k| !allowed.contains(&k.as_str())) {
            Some(key) => Err(format!("{what} has an unexpected field: {key}")),
            None => Ok(()),
        }
    }
    fn list<'a>(what: &str, value: &'a Value) -> Result<&'a Vec<Value>, String> {
        value.as_array().ok_or_else(|| format!("{what} isn't a list"))
    }

    keys("config", config, &["log", "dns", "inbounds", "outbounds", "route"])?;
    keys("log", &config["log"], &["level", "timestamp"])?;

    let dns = &config["dns"];
    keys("dns", dns, &["servers", "rules", "final", "strategy"])?;
    for server in list("dns servers", &dns["servers"])? {
        keys("dns server", server, &["type", "tag", "server", "server_port", "path", "detour", "domain_resolver"])?;
        if !matches!(server["type"].as_str(), Some("https" | "tls" | "tcp" | "udp" | "local")) {
            return Err("unexpected dns server type".into());
        }
    }
    for rule in list("dns rules", &dns["rules"])? {
        keys("dns rule", rule, &["domain_suffix", "server"])?;
    }

    let inbounds = list("inbounds", &config["inbounds"])?;
    let [tun] = inbounds.as_slice() else { return Err("expected one inbound".into()) };
    keys(
        "inbound",
        tun,
        &["type", "tag", "interface_name", "address", "mtu", "auto_route", "strict_route", "route_exclude_address", "stack", "exclude_uid"],
    )?;
    if tun["type"] != "tun" || tun["interface_name"] != TUN_NAME {
        return Err("unexpected inbound".into());
    }
    if tun["exclude_uid"] != serde_json::json!([core_uid]) {
        return Err("the cores' account must stay outside the tunnel".into());
    }

    let outbounds = list("outbounds", &config["outbounds"])?;
    let [proxy, direct] = outbounds.as_slice() else { return Err("expected two outbounds".into()) };
    keys("proxy outbound", proxy, &["type", "tag", "server", "server_port", "version", "username", "password"])?;
    if proxy["type"] != "socks" || proxy["server"] != "127.0.0.1" {
        return Err("the proxy must be xray on this computer".into());
    }
    keys("direct outbound", direct, &["type", "tag"])?;
    if direct["type"] != "direct" {
        return Err("unexpected outbound".into());
    }

    let route = &config["route"];
    keys("route", route, &["rules", "final", "auto_detect_interface", "default_domain_resolver"])?;
    for rule in list("route rules", &route["rules"])? {
        keys(
            "route rule",
            rule,
            &[
                "action", "protocol", "port", "network", "outbound", "process_path_regex", "process_name", "domain_suffix",
                "ip_cidr", "ip_is_private",
            ],
        )?;
    }
    Ok(())
}

/// Sockets listening on this computer or on all addresses, as (port, inode), from the text of
/// `/proc/net/tcp` or `/proc/net/tcp6`.
pub fn parse_listeners(table: &str) -> Vec<(u16, u64)> {
    const LISTEN: &str = "0A";
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (address, state, inode) = (*fields.get(1)?, *fields.get(3)?, *fields.get(9)?);
            let (ip, port) = address.split_once(':')?;
            // Addresses are printed in the machine's byte order; 127.x.x.x has 7F as one end.
            let local = ip.chars().all(|c| c == '0')
                || (ip.len() == 8 && (ip.ends_with("7F") || ip.starts_with("7F")))
                || ip == "00000000000000000000000001000000"
                || ip == "00000000000000000000000000000001";
            (state == LISTEN && local).then_some((u16::from_str_radix(port, 16).ok()?, inode.parse().ok()?))
        })
        .collect()
}

/// For each of `ports`, the processes listening on it, or None when the table can't be read.
/// A socket whose owner can't be seen (another user's) counts as process 0, so it never passes
/// for the one expected.
pub fn listener_pids(ports: &[u16]) -> Option<Vec<Vec<u32>>> {
    let mut sockets = parse_listeners(&std::fs::read_to_string("/proc/net/tcp").ok()?);
    if let Ok(v6) = std::fs::read_to_string("/proc/net/tcp6") {
        sockets.extend(parse_listeners(&v6));
    }
    sockets.retain(|(port, _)| ports.contains(port));
    let mut owners: Vec<(u64, u32)> = Vec::new();
    if !sockets.is_empty() {
        for process in std::fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = process.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
            let Ok(descriptors) = std::fs::read_dir(process.path().join("fd")) else { continue };
            for descriptor in descriptors.flatten() {
                let Ok(target) = std::fs::read_link(descriptor.path()) else { continue };
                let target = target.to_string_lossy();
                let inode = target.strip_prefix("socket:[").and_then(|t| t.strip_suffix(']')).and_then(|t| t.parse().ok());
                if let Some(inode) = inode {
                    if sockets.iter().any(|(_, i)| *i == inode) {
                        owners.push((inode, pid));
                    }
                }
            }
        }
    }
    Some(
        ports
            .iter()
            .map(|port| {
                sockets
                    .iter()
                    .filter(|(p, _)| p == port)
                    .map(|(_, inode)| owners.iter().find(|(i, _)| i == inode).map_or(0, |(_, pid)| *pid))
                    .collect()
            })
            .collect(),
    )
}

/// Whether a process listens on all its ports, and nobody else does.
#[derive(Debug, PartialEq)]
pub enum Ports {
    Ready,
    Waiting,
    Taken(u16),
}

pub fn ports_state(pid: u32, ports: &[u16], owners: &[Vec<u32>]) -> Ports {
    if let Some((port, _)) = ports.iter().zip(owners).find(|(_, pids)| pids.iter().any(|&p| p != pid)) {
        return Ports::Taken(*port);
    }
    if owners.iter().all(|pids| !pids.is_empty()) {
        Ports::Ready
    } else {
        Ports::Waiting
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_kill_switch_only_lets_the_tunnel_and_the_cores_out() {
        let rules = nft_rules(990, false);
        assert_eq!(rules.matches("policy drop").count(), 3);
        assert!(rules.contains("meta skuid 990 accept"));
        assert!(rules.contains(r#"oifname "Phi2ray" accept"#));
        // Replaced in one go: an empty table first, so `delete` can't fail, then the new one.
        assert!(rules.starts_with("table inet phi2ray\ndelete table inet phi2ray\ntable inet phi2ray {"));
        assert!(!rules.contains("192.168.0.0/16"));
        // Connections opened before the kill switch must not keep going out.
        let output = &rules[rules.find("chain output").unwrap()..rules.find("chain input").unwrap()];
        assert!(!output.contains("ct state"));
    }

    #[test]
    fn the_local_network_is_optional_and_goes_both_ways() {
        let rules = nft_rules(990, true);
        assert!(rules.contains("ip daddr { 10.0.0.0/8"));
        assert!(rules.contains("ip saddr { 10.0.0.0/8"));
        assert!(rules.contains("ip6 daddr { fc00::/7 } accept"));
        if let Ok(path) = std::env::var("PHI2RAY_NFT_OUT") {
            // CI asks `nft --check` to read this.
            std::fs::write(path, rules).unwrap();
        }
    }

    fn config() -> Value {
        json!({
            "log": { "level": "warn" },
            "dns": { "servers": [{ "type": "local", "tag": "local" }], "rules": [], "final": "local" },
            "inbounds": [{ "type": "tun", "interface_name": TUN_NAME, "exclude_uid": [990] }],
            "outbounds": [
                { "type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 9 },
                { "type": "direct", "tag": "direct" }
            ],
            "route": { "rules": [{ "ip_cidr": ["1.2.3.4/32"], "outbound": "direct" }], "final": "proxy" }
        })
    }

    #[test]
    fn a_config_can_only_do_what_the_app_builds() {
        check_tun_config(&config(), 990).unwrap();
        let refused = |edit: fn(&mut Value)| {
            let mut c = config();
            edit(&mut c);
            assert!(check_tun_config(&c, 990).is_err());
        };
        // Files and control ports.
        refused(|c| c["log"]["output"] = json!("/etc/cron.d/x"));
        refused(|c| c["experimental"] = json!({ "clash_api": { "external_controller": "0.0.0.0:9090" } }));
        refused(|c| c["route"]["rule_set"] = json!([{ "type": "local", "path": "/x" }]));
        refused(|c| c["dns"]["servers"][0]["tls"] = json!({ "certificate_path": "/x" }));
        // Other ways in or out.
        refused(|c| c["inbounds"][0]["type"] = json!("mixed"));
        refused(|c| c["inbounds"][0]["exclude_uid"] = json!([1000]));
        refused(|c| c["inbounds"].as_array_mut().unwrap().push(json!({ "type": "mixed" })));
        refused(|c| c["outbounds"][0]["server"] = json!("203.0.113.1"));
        refused(|c| c["outbounds"][1]["bind_interface"] = json!("eth0"));
    }

    #[test]
    fn listeners_come_from_the_kernels_table() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 1111 1 0\n\
           1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1 0\n\
           2: 0100007F:1F91 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 3333 1 0\n\
           3: 6401A8C0:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4444 1 0\n";
        assert_eq!(parse_listeners(table), [(0x1F90, 1111), (0x50, 2222)]);
    }

    #[test]
    fn only_the_expected_process_may_hold_the_ports() {
        assert_eq!(ports_state(7, &[1, 2], &[vec![7], vec![7]]), Ports::Ready);
        assert_eq!(ports_state(7, &[1, 2], &[vec![7], vec![]]), Ports::Waiting);
        assert_eq!(ports_state(7, &[1, 2], &[vec![7], vec![8]]), Ports::Taken(2));
        // Someone we can't even see.
        assert_eq!(ports_state(7, &[1], &[vec![0]]), Ports::Taken(1));
    }
}
