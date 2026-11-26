//! Builds the Xray JSON config for one profile.

use serde_json::{json, Value};

use crate::parser::{or, split_list, Profile, Protocol, Stream};
use crate::split::SplitMode;
use crate::store::{Mode, Settings};

pub struct Inbounds {
    pub socks_port: u16,
    pub http_port: u16,
    pub socks_user: String,
    pub socks_pass: String,
    /// Localhost port for xray's traffic counters (`/debug/vars`).
    pub metrics_port: u16,
    /// Password-protected HTTP inbound used only by Phi2ray's own checks. It always goes
    /// to the server, whatever the split tunnel says.
    pub probe_port: u16,
    pub probe_user: String,
    pub probe_pass: String,
}

/// Which optional data files are next to xray.
pub struct Assets {
    pub geoip: bool,
    pub geosite: bool,
}

/// Private and loopback ranges, sent direct when "bypass LAN" is on.
const PRIVATE_IPS: [&str; 8] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

pub fn build(p: &Profile, inb: &Inbounds, s: &Settings, assets: &Assets) -> Value {
    let sniffing = json!({ "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true });

    // The metrics inbound must reach xray's stats endpoint, never the internet.
    let mut rules = vec![
        json!({ "type": "field", "inboundTag": ["metrics-in"], "outboundTag": "metrics" }),
        json!({ "type": "field", "inboundTag": ["probe-in"], "outboundTag": "proxy" }),
    ];
    if s.absolute_mode { rules.push(json!({"type":"field","ip":["::/0"],"outboundTag":"block"})); }

    // In VPN mode sing-box does the split (it also sees apps); here only for the proxy modes.
    let split = if s.mode == Mode::Tun { None } else { s.split.rules().filter(|r| r.has_sites()) };
    let mut send_rest_direct = false;
    if let Some(split) = &split {
        let (to, rest_direct) = match s.split.mode {
            SplitMode::Exclude => ("direct", false),
            SplitMode::Include => ("proxy", true),
        };
        let domains: Vec<String> = split.domains.iter().map(|d| format!("domain:{d}")).collect();
        if !domains.is_empty() {
            rules.push(json!({ "type": "field", "domain": domains, "outboundTag": to }));
        }
        if !split.cidrs.is_empty() {
            rules.push(json!({ "type": "field", "ip": split.cidrs, "outboundTag": to }));
        }
        send_rest_direct = rest_direct;
    }
    if s.block_quic && !send_rest_direct {
        // Browsers fall back to TCP right away, which is faster and steadier through the proxy.
        rules.push(json!({ "type": "field", "network": "udp", "port": "443", "outboundTag": "block" }));
    }
    if s.block_ads && assets.geosite {
        rules.push(json!({ "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" }));
    }
    if s.bypass_lan {
        rules.push(json!({ "type": "field", "ip": PRIVATE_IPS, "outboundTag": "direct" }));
    }
    if s.iran_direct {
        let mut domains = vec!["domain:ir"];
        if assets.geosite {
            domains.push("geosite:category-ir");
        }
        rules.push(json!({ "type": "field", "domain": domains, "outboundTag": "direct" }));
        if assets.geoip {
            rules.push(json!({ "type": "field", "ip": ["geoip:ir"], "outboundTag": "direct" }));
        }
    }

    if send_rest_direct {
        // Include mode: anything not listed above skips the server.
        rules.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": "direct" }));
    }

    let mut log = json!({ "loglevel": s.log_level });
    if s.log_level == "warning" {
        // The per-connection access log is only useful when debugging.
        log["access"] = json!("none");
    }

    let mut config = json!({
        "log": log,
        // Byte counters for the proxy outbound, read by the app for speed and totals.
        "stats": {},
        "policy": { "system": { "statsOutboundUplink": true, "statsOutboundDownlink": true } },
        "metrics": { "tag": "metrics" },
        "inbounds": [
            // Route the authenticated HTTP request to Xray's in-process metrics server.
            {
                "tag": "metrics-in",
                "listen": "127.0.0.1",
                "port": inb.metrics_port,
                "protocol": "http",
                "settings": { "accounts": [{ "user": inb.probe_user, "pass": inb.probe_pass }] }
            },
            {
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": inb.socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "password",
                    "accounts": [{ "user": inb.socks_user, "pass": inb.socks_pass }],
                    "udp": true
                },
                "sniffing": sniffing
            },
            {
                "tag": "probe-in",
                "listen": "127.0.0.1",
                "port": inb.probe_port,
                "protocol": "http",
                "settings": { "accounts": [{ "user": inb.probe_user, "pass": inb.probe_pass }] }
            }
        ],
        "outbounds": [
            outbound(p, s.mode == Mode::Tun && !s.ipv6),
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" }
        ],
        // AsIs: never resolve domains locally just to match rules, so DNS does not leak.
        "routing": { "domainStrategy": "AsIs", "rules": rules }
    });
    // The HTTP inbound is for the proxy modes only (the system proxy and apps set up by hand).
    // System mode remains compatible with apps that can't send proxy credentials.
    if s.mode != Mode::Tun {
        let auth = if s.mode == Mode::Manual {
            json!({ "accounts": [{ "user": inb.socks_user, "pass": inb.socks_pass }] })
        } else {
            json!({})
        };
        config["inbounds"].as_array_mut().unwrap().push(json!({
            "tag": "http",
            "listen": "127.0.0.1",
            "port": inb.http_port,
            "protocol": "http",
            "settings": auth,
            "sniffing": sniffing
        }));
    }
    config
}

/// Minimal config for the delay test: one local HTTP inbound, everything goes to the server.
pub fn build_test(p: &Profile, http_port: u16) -> Value {
    json!({
        "log": { "loglevel": "none" },
        "inbounds": [{ "tag": "http", "listen": "127.0.0.1", "port": http_port, "protocol": "http", "settings": {} }],
        "outbounds": [outbound(p, false)]
    })
}

pub fn for_export(p: &Profile) -> Value {
    json!({ "remarks": p.name, "outbounds": [outbound(p, false)] })
}

fn outbound(p: &Profile, ipv4_only: bool) -> Value {
    let (protocol, settings) = match p.protocol {
        Protocol::Vless => (
            "vless",
            json!({ "vnext": [{ "address": p.address, "port": p.port, "users": [{
                "id": p.secret, "encryption": or(&p.method, "none"), "flow": p.flow
            }] }] }),
        ),
        Protocol::Vmess => (
            "vmess",
            json!({ "vnext": [{ "address": p.address, "port": p.port, "users": [{
                "id": p.secret, "alterId": p.alter_id, "security": or(&p.method, "auto")
            }] }] }),
        ),
        Protocol::Trojan => (
            "trojan",
            json!({ "servers": [{ "address": p.address, "port": p.port, "password": p.secret }] }),
        ),
        Protocol::Shadowsocks => (
            "shadowsocks",
            json!({ "servers": [{
                "address": p.address, "port": p.port, "method": p.method, "password": p.secret
            }] }),
        ),
        Protocol::Http => ("http", json!({})),
        Protocol::Socks => ("socks", json!({})),
        Protocol::Wireguard => return crate::parser::wireguard::outbound(p, ipv4_only),
    };
    let settings = if let Some(settings) = &p.outbound_settings {
        let mut settings = settings.clone();
        settings["address"] = json!(p.address);
        settings["port"] = json!(p.port);
        settings
    } else { settings };
    let transport = if p.outbound_settings.is_some() {
        let s = &p.stream;
        let mut options = s.options.clone().unwrap_or_else(|| json!({"network": s.network, "security": s.security}));
        if !s.sni.is_empty() {
            let key = if s.security == "reality" { "realitySettings" } else { "tlsSettings" };
            if s.security != "none" { options[key]["serverName"] = json!(s.sni); }
        }
        if !s.host.is_empty() && matches!(s.network.as_str(), "ws" | "httpupgrade" | "xhttp") {
            let key = format!("{}Settings", s.network);
            options[&key]["host"] = json!(s.host);
        }
        options
    } else { stream(&p.stream) };
    let mut out = json!({ "tag": "proxy", "protocol": protocol, "settings": settings, "streamSettings": transport });
    if let Some(mux) = &p.mux { out["mux"] = mux.clone(); }
    out
}

fn stream(s: &Stream) -> Value {
    let mut out = json!({ "network": s.network, "security": s.security });
    let path = or(&s.path, "/");

    match s.network.as_str() {
        "ws" => out["wsSettings"] = json!({ "path": path, "host": s.host }),
        "httpupgrade" => out["httpupgradeSettings"] = json!({ "path": path, "host": s.host }),
        "grpc" => {
            out["grpcSettings"] = json!({ "serviceName": s.service_name, "multiMode": s.mode == "multi" })
        }
        "xhttp" => {
            let mut x = json!({ "path": path, "host": s.host });
            if !s.mode.is_empty() {
                x["mode"] = json!(s.mode);
            }
            out["xhttpSettings"] = x;
        }
        "kcp" => out["kcpSettings"] = json!({ "header": { "type": or(&s.header_type, "none") } }),
        "tcp" if s.header_type == "http" => {
            out["tcpSettings"] = json!({ "header": { "type": "http", "request": {
                "path": [path], "headers": { "Host": split_list(&s.host) }
            } } })
        }
        _ => {}
    }

    match s.security.as_str() {
        "tls" => {
            let mut tls = json!({ "serverName": or(&s.sni, &s.host), "fingerprint": s.fingerprint });
            if !s.alpn.is_empty() {
                tls["alpn"] = json!(s.alpn);
            }
            if s.allow_insecure {
                tls["allowInsecure"] = json!(true);
            }
            out["tlsSettings"] = tls;
        }
        "reality" => {
            out["realitySettings"] = json!({
                "serverName": s.sni,
                "fingerprint": or(&s.fingerprint, "chrome"),
                "publicKey": s.public_key,
                "shortId": s.short_id,
                "spiderX": s.spider_x
            })
        }
        _ => {}
    }
    if let Some(options) = &s.options {
        let mut merged = options.clone();
        for (key, value) in out.as_object().unwrap() {
            if let (Some(existing), Some(generated)) = (merged.get_mut(key).and_then(Value::as_object_mut), value.as_object()) {
                for (k, v) in generated {
                    // Empty summary fields must not erase an advanced custom option.
                    if !existing.contains_key(k) || (v != "" && v != &json!([])) { existing.insert(k.clone(), v.clone()); }
                }
            } else { merged[key] = value.clone(); }
        }
        merged
    } else { out }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::parser::parse_link;

    pub(crate) fn inbounds() -> Inbounds {
        Inbounds {
            socks_port: 10801,
            http_port: 10802,
            socks_user: "u".into(),
            socks_pass: "p".into(),
            metrics_port: 10803,
            probe_port: 10804,
            probe_user: "pu".into(),
            probe_pass: "pp".into(),
        }
    }

    /// Every optional routing feature on, at the most verbose log level.
    fn everything_on() -> Settings {
        Settings { iran_direct: true, block_ads: true, log_level: "info".into(), ..Settings::default() }
    }

    #[test]
    fn configuration_exports_reimport_with_advanced_options() {
        let source = crate::parser::custom::tests::sample(true);
        let mut profile = crate::parser::parse_many(&source.to_string()).profiles.remove(0);
        profile.name = "سرور آزمایشی".into();
        profile.library.starred = true;
        let link = parse_link("trojan://fake-password@example.invalid:443?type=ws&path=%2Ftest#Sample").unwrap();
        let parsed = crate::parser::parse_many(&json!([for_export(&profile), for_export(&link)]).to_string());
        assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
        assert_eq!(parsed.profiles.len(), 2);
        let first = &parsed.profiles[0];
        assert_eq!(first.name, profile.name);
        assert_eq!(first.secret, profile.secret);
        assert!(!first.library.starred);
        assert_eq!(outbound(first, false), outbound(&profile, false));
        assert_eq!(parsed.profiles[1].stream.path, "/test");
        assert_eq!(parsed.profiles[1].secret, "fake-password");
    }

    #[test]
    fn builds_reality_vless() {
        let p = parse_link("vless://id@a.com:443?security=reality&sni=g.com&pbk=K&sid=1&type=grpc&serviceName=svc").unwrap();
        let c = build(&p, &inbounds(), &Settings::default(), &Assets { geoip: true, geosite: true });
        let out = &c["outbounds"][0];
        assert_eq!(out["settings"]["vnext"][0]["users"][0]["encryption"], "none");
        assert_eq!(out["streamSettings"]["realitySettings"]["publicKey"], "K");
        assert_eq!(out["streamSettings"]["grpcSettings"]["serviceName"], "svc");
        assert!(c["inbounds"].as_array().unwrap().iter().all(|i| i["listen"] == "127.0.0.1"));
        // Defaults: metrics, probe, QUIC block and LAN bypass only, and no access log.
        assert_eq!(c["routing"]["rules"].as_array().unwrap().len(), 4);
        assert_eq!(c["routing"]["rules"][0]["outboundTag"], "metrics");
        assert_eq!(c["routing"]["rules"][1]["outboundTag"], "proxy");
        assert_eq!(c["inbounds"][0]["port"], 10803);
        assert_eq!(c["log"]["access"], "none");
    }

    #[test]
    fn http_inbound_requires_auth_in_manual_mode() {
        let p = parse_link("trojan://pw@a.com:443").unwrap();
        let assets = || Assets { geoip: false, geosite: false };
        let http = |mode| {
            let c = build(&p, &inbounds(), &Settings { mode, ..Settings::default() }, &assets());
            c["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == "http").cloned()
        };
        assert!(http(Mode::Tun).is_none());
        assert!(http(Mode::System).unwrap()["settings"]["accounts"].is_null());
        assert_eq!(http(Mode::Manual).unwrap()["settings"]["accounts"][0]["pass"], inbounds().socks_pass);
    }

    #[test]
    fn optional_rules_need_their_data_files() {
        let p = parse_link("trojan://pw@a.com:443").unwrap();
        let rules = |assets| build(&p, &inbounds(), &everything_on(), &assets)["routing"]["rules"].as_array().unwrap().len();
        assert_eq!(rules(Assets { geoip: true, geosite: true }), 7);
        assert_eq!(rules(Assets { geoip: false, geosite: false }), 5);
    }

    fn sample_split(mode: crate::split::SplitMode) -> crate::split::SplitTunnel {
        crate::split::SplitTunnel {
            enabled: true,
            mode,
            apps: vec!["Telegram.exe".into(), r"C:\Program Files (x86)\Steam\steam.exe".into()],
            sites: vec!["digikala.com".into(), "1.2.3.0/24".into()],
        }
    }

    #[test]
    fn split_in_proxy_modes() {
        let p = parse_link("trojan://pw@a.com:443").unwrap();
        let assets = Assets { geoip: false, geosite: false };
        let include = Settings { mode: Mode::System, split: sample_split(crate::split::SplitMode::Include), ..Settings::default() };
        let rules = build(&p, &inbounds(), &include, &assets)["routing"]["rules"].as_array().unwrap().clone();
        assert_eq!(rules[2]["domain"][0], "domain:digikala.com");
        assert_eq!(rules[2]["outboundTag"], "proxy");
        assert_eq!(rules.last().unwrap()["outboundTag"], "direct");
        // Phi2ray's own checks still reach the server, before any split rule.
        assert_eq!(rules[1]["inboundTag"][0], "probe-in");
        // In VPN mode sing-box does the split, so xray gets no split rules.
        let vpn = Settings { mode: Mode::Tun, ..include };
        let rules = build(&p, &inbounds(), &vpn, &assets)["routing"]["rules"].as_array().unwrap().clone();
        assert!(rules.iter().all(|r| r["domain"].is_null()));
    }

    /// Writes sample configs to $PHI2RAY_DUMP_DIR so they can be checked with `xray run -test`.
    #[test]
    #[ignore]
    fn dump_sample_configs() {
        let dir = std::path::PathBuf::from(std::env::var("PHI2RAY_DUMP_DIR").expect("set PHI2RAY_DUMP_DIR"));
        std::fs::create_dir_all(&dir).unwrap();
        let ss = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "aes-256-gcm:pw");
        let samples = [
            ("vless-reality", "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=reality&sni=www.google.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=ab12&flow=xtls-rprx-vision#r".to_string()),
            ("vless-ws-tls", "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&sni=a.com&host=a.com&path=%2Fws&alpn=h2,http%2F1.1#w".to_string()),
            ("vless-grpc", "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=grpc&security=tls&serviceName=svc&mode=multi#g".to_string()),
            ("vless-xhttp", "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=xhttp&security=tls&path=%2Fx&mode=auto#x".to_string()),
            ("vless-kcp", "vless://11111111-2222-3333-4444-555555555555@example.invalid:443?type=mkcp&seed=test&headerType=srtp".to_string()),
            ("vless-xhttp-pcs-extra", format!("vless://11111111-2222-3333-4444-555555555555@example.invalid:443?type=xhttp&security=tls&fp=chrome&pcs={}&extra=%7B%22scMinPostsIntervalMs%22%3A%2230%22%2C%22noSSEHeader%22%3Atrue%7D", "ab".repeat(32))),
            ("vless-httpupgrade", "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=httpupgrade&security=tls&path=%2Fh&host=a.com#h".to_string()),
            ("trojan-tcp-http", "trojan://pass@example.com:443?type=tcp&headerType=http&host=a.com&path=%2F#t".to_string()),
            ("shadowsocks", format!("ss://{ss}@example.com:8388#s")),
        ];
        let write = |path: std::path::PathBuf, v: &Value| std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap();
        let assets = Assets { geoip: true, geosite: true };
        for (name, link) in &samples {
            let p = parse_link(link).unwrap().validated().unwrap();
            write(dir.join(format!("{name}.json")), &build(&p, &inbounds(), &Settings::default(), &assets));
        }
        for tls in [false, true] {
            let raw = crate::parser::custom::tests::sample(tls);
            let p = crate::parser::parse_many(&raw.to_string()).profiles.remove(0).validated().unwrap();
            let name = if tls { "custom-xhttp-pinned-tls" } else { "custom-xhttp-encryption" };
            write(dir.join(format!("{name}.json")), &build(&p, &inbounds(), &Settings::default(), &assets));
            write(dir.join(format!("{name}-delay.json")), &build_test(&p, 10803));
        }
        for (protocol, raw) in crate::parser::custom::tests::common_samples() {
            let p = crate::parser::parse_many(&raw.to_string()).profiles.remove(0).validated().unwrap();
            write(dir.join(format!("custom-{protocol}.json")), &build_test(&p, 10803));
        }
        let p = parse_link(&samples[0].1).unwrap();
        write(dir.join("all-options.json"), &build(&p, &inbounds(), &everything_on(), &assets));
        write(dir.join("delay-test.json"), &build_test(&p, 10803));
        let manual = Settings { mode: Mode::Manual, ..Settings::default() };
        write(dir.join("manual-proxy.json"), &build(&p, &inbounds(), &manual, &assets));
        let strict = crate::absolute::effective(&Settings{absolute_mode:true,..Settings::default()});
        let cfg = build(&p,&inbounds(),&strict,&assets);
        write(dir.join("absolute-ready.json"),&cfg);
        write(dir.join("absolute-preparing.json"),&crate::connection::gated_config(&cfg));
        let wireguard = json!({
            "protocol": "wireguard",
            "settings": {
                "secretKey": "11".repeat(32),
                "address": ["10.7.0.2/32", "fd00::2/128"],
                "remoteDNS": ["10.7.0.1", "fd00::1"],
                "reserved": [1, 2, 3],
                "peers": [{
                    "endpoint": "198.51.100.27:51820",
                    "publicKey": "22".repeat(32),
                    "preSharedKey": "33".repeat(32),
                    "allowedIPs": ["0.0.0.0/0", "::/0"],
                    "keepAlive": 25
                }]
            }
        });
        let wg = crate::parser::parse_many(&wireguard.to_string()).profiles.remove(0);
        write(dir.join("wireguard-delay.json"), &build_test(&wg, 10803));
        write(dir.join("wireguard-vpn.json"), &build(&wg, &inbounds(), &Settings { ipv6: true, ..Settings::default() }, &assets));
        let wg_strict = build(&wg, &inbounds(), &strict, &assets);
        write(dir.join("wireguard-absolute.json"), &crate::connection::gated_config(&wg_strict));
        for (name, mode) in [("split-exclude-proxy", crate::split::SplitMode::Exclude), ("split-include-proxy", crate::split::SplitMode::Include)] {
            let settings = Settings { mode: Mode::System, split: sample_split(mode), ..Settings::default() };
            write(dir.join(format!("{name}.json")), &build(&p, &inbounds(), &settings, &assets));
        }

        // sing-box configs; check them with `sing-box check -c <file>`.
        let tun_dir = dir.join("sing-box");
        std::fs::create_dir_all(&tun_dir).unwrap();
        let variants = [
            ("absolute", strict, "203.0.113.7"),
            ("default", Settings::default(), "203.0.113.7"),
            (
                "all-options",
                Settings {
                    iran_direct: true,
                    bypass_lan: false,
                    ipv6: true,
                    tun_stack: "gvisor".into(),
                    tun_mtu: 1500,
                    strict_route: false,
                    remote_dns: "https://dns.google/dns-query".into(),
                    log_level: "debug".into(),
                    ..Settings::default()
                },
                "2001:db8::7",
            ),
            ("dot", Settings { remote_dns: "tls://9.9.9.9".into(), tun_stack: "system".into(), ..Settings::default() }, "203.0.113.7"),
            ("plain-dns", Settings { remote_dns: "8.8.8.8".into(), ..Settings::default() }, "203.0.113.7"),
            ("split-exclude", Settings { split: sample_split(crate::split::SplitMode::Exclude), ..Settings::default() }, "203.0.113.7"),
            ("split-include", Settings { split: sample_split(crate::split::SplitMode::Include), ..Settings::default() }, "203.0.113.7"),
        ];
        for (name, settings, ip) in variants {
            let tun = crate::tun::build(&crate::tun::TunInput {
                socks_port: 10801,
                socks_user: "u",
                socks_pass: "p",
                server_ip: ip.parse().unwrap(),
                xray_exe: std::path::Path::new(r"C:\Program Files\Phi2ray\core-0.1.0\xray.exe"),
                core_uid: (!cfg!(windows)).then_some(990),
                local_dns: (!cfg!(windows)).then(|| "192.168.1.1".parse().unwrap()),
                settings: &settings,
            })
            .unwrap();
            write(tun_dir.join(format!("{name}.json")), &tun);
        }
    }
}
