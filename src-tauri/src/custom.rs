//! Import connection settings, never a provider's listeners, logging or routing.
use super::*;
use serde_json::json;

pub(super) fn collect(value: Value, out: &mut Parsed, depth: usize) {
    if depth > 8 {
        fail(out, "JSON: too many nested lists".into());
        return;
    }
    match value {
        Value::Array(values) => {
            for value in values {
                if out.profiles.len() >= MAX_PROFILES {
                    fail(out, "JSON: server limit reached".into());
                } else {
                    collect(value, out, depth + 1);
                }
            }
        }
        Value::String(link) if link.len() > MAX_LINK_LEN => fail(out, "JSON: share link too long".into()),
        Value::String(link) => match parse_link(link.trim()) {
            Ok(p) if out.profiles.len() < MAX_PROFILES => push(out, p),
            _ => fail(out, "JSON: unsupported or invalid share link".into()),
        },
        value => match profile(&value) {
            Ok(p) => push(out, p),
            Err(e) => fail(out, format!("JSON: {e}")),
        },
    }
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

pub(super) fn profile(root: &Value) -> Result<Profile, String> {
    if root["v"].is_u64() && root["d"].is_string() && root.as_object().is_some_and(|o| o.len() == 2) {
        return Err("This looks like a SocksHTTP container. Use a SOCKS5 link or standard Xray JSON.".into());
    }
    let outbound = if let Some(outbounds) = root.get("outbounds") {
        let candidates: Vec<_> = outbounds.as_array().ok_or("outbounds must be a list")?.iter()
            .filter(|o| !matches!(o["protocol"].as_str(), Some("freedom" | "blackhole" | "dns"))).collect();
        candidates.iter().find(|o| o["tag"] == "proxy").copied()
            .or_else(|| if candidates.len() == 1 { Some(candidates[0]) } else { None })
            .ok_or("expected one proxy outbound, or an outbound tagged proxy")?
    } else { root };
    let protocol = match outbound["protocol"].as_str() {
        Some("vless") => Protocol::Vless,
        Some("vmess") => Protocol::Vmess,
        Some("trojan") => Protocol::Trojan,
        Some("shadowsocks") => Protocol::Shadowsocks,
        Some("http") => Protocol::Http,
        Some("socks") => Protocol::Socks,
        Some("wireguard") => Protocol::Wireguard,
        _ => return Err("unsupported outbound protocol".into()),
    };
    if outbound.as_object().is_some_and(|o| o.iter().any(|(k, v)| k.eq_ignore_ascii_case("proxySettings") && !v.is_null())) {
        return Err("chained proxySettings are not supported".into());
    }
    let name = or(&text(root, "remarks"), &or(&text(root, "ps"), &text(outbound, "tag")));
    if protocol == Protocol::Wireguard { return wireguard::parse_json(outbound, &name); }
    let mut settings = outbound.get("settings").cloned().ok_or("missing outbound settings")?;
    if !settings.is_object() { return Err("outbound settings must be an object".into()); }
    // Normalize legacy endpoint lists to the current core's single-endpoint form.
    for key in ["vnext", "servers"] {
        if let Some(servers) = settings.get(key) {
            let servers = servers.as_array().ok_or("server list must be an array")?;
            if servers.len() != 1 { return Err("an outbound must have exactly one server".into()); }
            let server = servers[0].as_object().ok_or("server must be an object")?;
            let mut flat = settings.as_object().unwrap().clone();
            flat.remove(key);
            flat.extend(server.clone());
            if let Some(users) = flat.remove("users") {
                let users = users.as_array().ok_or("users must be a list")?;
                if users.len() != 1 { return Err("an outbound must have exactly one user".into()); }
                flat.extend(users[0].as_object().ok_or("user must be an object")?.clone());
            }
            settings = Value::Object(flat);
        }
    }
    if settings.as_object().unwrap().iter().any(|(k, v)| k.eq_ignore_ascii_case("reverse") && !v.is_null()) {
        return Err("reverse proxy settings are not supported".into());
    }
    check_local_access(&settings)?;
    let address = strip_brackets(&text(&settings, "address"));
    if address.is_empty() || address.chars().any(char::is_whitespace) { return Err("missing or invalid server address".into()); }
    let port = settings["port"].as_u64().or_else(|| settings["port"].as_str()?.parse().ok())
        .filter(|&p| p > 0 && p <= u16::MAX as u64).ok_or("invalid server port")? as u16;
    settings["port"] = json!(port);
    let secret = text(&settings, if matches!(protocol, Protocol::Vless | Protocol::Vmess) { "id" } else { "password" });
    if secret.is_empty() && !matches!(protocol, Protocol::Http | Protocol::Socks) { return Err("missing id/password".into()); }
    let method = text(&settings, match protocol { Protocol::Vless => "encryption", Protocol::Vmess => "security", _ => "method" });
    if protocol == Protocol::Vless && method.is_empty() { settings["encryption"] = json!("none"); }
    let mut options = outbound.get("streamSettings").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!({}));
    if options.get("address").is_some() || options.get("port").is_some() {
        return Err("set the main server address/port in outbound settings, not streamSettings".into());
    }
    normalize_stream(&mut options, 0)?;
    let network = text(&options, "network");
    let security = text(&options, "security");
    let transport = &options[match network.as_str() {
        "xhttp" => "xhttpSettings", "ws" => "wsSettings", "grpc" => "grpcSettings",
        "httpupgrade" => "httpupgradeSettings", "kcp" => "kcpSettings", _ => "tcpSettings",
    }];
    let secure = &options[if security == "reality" { "realitySettings" } else { "tlsSettings" }];
    let host = or(&text(transport, "host"), transport["headers"]["Host"].as_str().unwrap_or_default());
    let stream = Stream {
        network, security, sni: text(secure, "serverName"), fingerprint: text(secure, "fingerprint"),
        host, path: text(transport, "path"), service_name: text(transport, "serviceName"), mode: text(transport, "mode"),
        options: Some(options), ..Default::default()
    };
    let mux = outbound.get("mux").filter(|v| !v.is_null()).cloned();
    if mux.as_ref().is_some_and(|v| !v.is_object()) { return Err("mux must be an object".into()); }
    if let Some(mux) = &mux { check_local_access(mux)?; }
    Ok(Profile {
        id: new_id(), name: or(&name, &format!("{address}:{port}")), protocol, address, port, secret, method,
        flow: text(&settings, "flow"), alter_id: settings["alterId"].as_u64().unwrap_or(0) as u16,
        group_id: String::new(), stream, outbound_settings: Some(settings), mux,
        library: LibraryPreferences::default(),
    })
}

/// Reapply the import rules to stored profiles before passing their options to a core.
pub(super) fn validate_saved(saved: &Profile) -> Result<Profile, String> {
    let mut candidate = saved.clone();
    if candidate.protocol == Protocol::Wireguard {
        wireguard::parse_json(&json!({"settings": &candidate.outbound_settings}), &candidate.name)?;
    } else {
        if candidate.outbound_settings.as_ref().is_some_and(|settings| !settings.is_object()) {
            return Err("outbound settings must be an object".into());
        }
        if let Some(options) = &mut candidate.stream.options {
            normalize_stream(options, 0)?;
        }
    }
    let mut valid = profile(&crate::config::for_export(&candidate))?;
    valid.id.clone_from(&saved.id);
    valid.name.clone_from(&saved.name);
    valid.group_id.clone_from(&saved.group_id);
    valid.library = saved.library.clone();
    Ok(valid)
}

fn normalize_stream(v: &mut Value, depth: usize) -> Result<(), String> {
    if depth > 8 { return Err("too many nested download transports".into()); }
    let object = v.as_object_mut().ok_or("streamSettings must be an object")?;
    // Unknown stream features can introduce a second endpoint or access local files.
    const KEYS: &[&str] = &["address", "port", "network", "method", "security", "tlsSettings", "realitySettings",
        "rawSettings", "tcpSettings", "splithttpSettings", "xhttpSettings", "kcpSettings", "grpcSettings",
        "wsSettings", "httpupgradeSettings", "sockopt"];
    if object.keys().any(|k| !KEYS.contains(&k.as_str())) { return Err("unsupported streamSettings option".into()); }
    object.retain(|_, v| !v.is_null());
    for (key, value) in object.iter() {
        if matches!(key.as_str(), "network" | "method" | "security" | "address") {
            if !value.is_string() { return Err("stream network/security/address must be strings".into()); }
        } else if key != "port" && !value.is_object() {
            return Err("transport, security and socket settings must be objects".into());
        }
    }
    let network = normalize_network(object.get("method").or_else(|| object.get("network")).and_then(Value::as_str).unwrap_or_default());
    if !matches!(network.as_str(), "tcp" | "ws" | "grpc" | "httpupgrade" | "xhttp" | "kcp") {
        return Err("transport is not supported by this app/core (use TCP, WS, gRPC, HTTPUpgrade, XHTTP or KCP)".into());
    }
    object.remove("method");
    object.insert("network".into(), json!(network));
    for (old, new) in [("rawSettings", "tcpSettings"), ("splithttpSettings", "xhttpSettings")] {
        if let Some(value) = object.remove(old) { object.entry(new).or_insert(value); }
    }
    let security = object.get("security").and_then(Value::as_str).unwrap_or("none").to_ascii_lowercase();
    if !matches!(security.as_str(), "none" | "tls" | "reality") { return Err("unsupported stream security".into()); }
    object.insert("security".into(), json!(security));
    if let Some(port) = object.get_mut("port") {
        let number = port.as_u64().or_else(|| port.as_str()?.parse().ok())
            .filter(|&p| p > 0 && p <= u16::MAX as u64).ok_or("invalid download port")?;
        *port = json!(number);
    }
    if object.get("address").and_then(Value::as_str).is_some_and(|a| a.is_empty() || a.chars().any(char::is_whitespace)) {
        return Err("invalid download address".into());
    }
    check_local_access(v)?;
    for key in ["tlsSettings", "realitySettings"] {
        if v[key].is_object() {
            let secure = v[key].as_object_mut().unwrap();
            if key == "tlsSettings" && secure.get("allowInsecure").and_then(Value::as_bool) == Some(true) {
                if secure.get("pinnedPeerCertSha256").and_then(Value::as_str).is_none_or(str::is_empty) {
                    return Err("this Xray core requires certificate verification; use a trusted certificate or pinnedPeerCertSha256".into());
                }
                secure.remove("allowInsecure");
            }
        }
    }
    if v["xhttpSettings"].is_object() {
        let x = &mut v["xhttpSettings"];
        if let Some(extra) = x.get("extra") { if !extra.is_object() { return Err("XHTTP extra must be a JSON object".into()); } }
        for extra in [false, true] {
            let container = if extra { x.get_mut("extra") } else { Some(&mut *x) };
            if let Some(download) = container.and_then(|e| e.get_mut("downloadSettings")) {
                normalize_stream(download, depth + 1)?;
                // The core assumes XHTTP plus a destination here; other shapes can panic at dial time.
                if download["network"] != "xhttp" || text(download, "address").is_empty() || download.get("port").is_none() {
                    return Err("XHTTP downloadSettings requires network xhttp, address and port".into());
                }
            }
        }
    }
    Ok(())
}

/// Resolve separate XHTTP download endpoints before VPN/firewall activation as well.
pub(super) fn pin_downloads(p: &mut Profile, mut resolve: impl FnMut(&str, u16) -> Result<std::net::IpAddr, String>) -> Result<(), String> {
    fn walk(v: &mut Value, address: &str, port: u16, resolve: &mut impl FnMut(&str, u16) -> Result<std::net::IpAddr, String>) -> Result<(), String> {
        if v["network"] != "xhttp" { return Ok(()); }
        let Some(x) = v.get_mut("xhttpSettings") else { return Ok(()); };
        for extra in [false, true] {
            let container = if extra { x.get_mut("extra") } else { Some(&mut *x) };
            let Some(download) = container.and_then(|c| c.get_mut("downloadSettings")) else { continue; };
            let domain = or(&text(download, "address"), address);
            let download_port = download["port"].as_u64().map(|p| p as u16).unwrap_or(port);
            if domain.parse::<std::net::IpAddr>().is_err() {
                let ip = resolve(&domain, download_port)?;
                let network = text(download, "network");
                let key = format!("{network}Settings");
                let host = text(&download[&key], "host");
                if download["security"] == "tls" && text(&download["tlsSettings"], "serverName").is_empty() {
                    download["tlsSettings"]["serverName"] = json!(domain);
                }
                if matches!(network.as_str(), "xhttp" | "ws" | "httpupgrade") && host.is_empty() {
                    let secure_key = if download["security"] == "reality" { "realitySettings" } else { "tlsSettings" };
                    let sni = if matches!(download["security"].as_str(), Some("tls" | "reality")) {
                        text(&download[secure_key], "serverName")
                    } else { String::new() };
                    download[&key]["host"] = json!(or(&sni, &domain));
                }
                download["address"] = json!(ip.to_string());
            } else { download["address"] = json!(domain); }
            download["port"] = json!(download_port);
            walk(download, &domain, download_port, resolve)?;
        }
        Ok(())
    }
    if let Some(options) = &mut p.stream.options { walk(options, &p.address, p.port, &mut resolve)?; }
    Ok(())
}

/// Each separate XHTTP download transport negotiates security independently.
pub(super) fn unencrypted_download(stream: &Value) -> bool {
    let settings = &stream["xhttpSettings"];
    [settings.get("downloadSettings"), settings["extra"].get("downloadSettings")]
        .into_iter().flatten().any(|download| {
            !matches!(download["security"].as_str(), Some("tls" | "reality"))
                || download["tlsSettings"]["allowInsecure"] == true
                || unencrypted_download(download)
        })
}

fn check_local_access(v: &Value) -> Result<(), String> {
    match v {
        Value::Object(o) => for (k, value) in o {
            let key = k.to_ascii_lowercase();
            if key == "headers" { continue; }
            if [("downloadsettings", "downloadSettings"), ("extra", "extra"), ("allowinsecure", "allowInsecure")]
                .iter().any(|(lower, canonical)| key == *lower && k != canonical)
            {
                return Err("use standard XHTTP and TLS field names".into());
            }
            // Go's JSON decoder also accepts differently cased field names.
            if matches!(key.as_str(), "certificatefile" | "keyfile" | "masterkeylog" | "dialerproxy" | "customsockopt" | "interface" | "mark" | "tproxy")
                && !value.is_null() && value != "" && value != 0 && value != false
                && !value.as_array().is_some_and(Vec::is_empty)
                && !(key == "tproxy" && value.as_str().is_some_and(|s| s.eq_ignore_ascii_case("off"))) {
                return Err("external files, chained proxies and system socket overrides are not supported in imported configs".into());
            }
            check_local_access(value)?;
        },
        Value::Array(a) => for value in a { check_local_access(value)?; },
        _ => {},
    }
    Ok(())
}

pub(super) fn link_options(s: &mut Stream, q: &HashMap<String, String>) -> Result<(), String> {
    let get = |keys: &[&str]| keys.iter().find_map(|&k| q.get(k).filter(|v| !v.is_empty())).cloned().unwrap_or_default();
    let mut options = json!({ "network": s.network, "security": s.security });
    let extra = get(&["extra", "xhttpExtra"]);
    if !extra.is_empty() {
        let value = serde_json::from_str::<Value>(&extra).ok()
            .or_else(|| b64_decode(&extra).ok().and_then(|b| serde_json::from_slice(&b).ok()))
            .or_else(|| serde_json::from_str(&extra.replace('+', " ")).ok())
            .filter(Value::is_object).ok_or("XHTTP extra must be a JSON object")?;
        if s.network != "xhttp" { return Err("extra is only supported for XHTTP".into()); }
        options["xhttpSettings"] = json!({"extra": value});
    }
    let pin = get(&["pcs", "pinnedPeerCertSha256"]);
    let names = get(&["vcn", "verifyPeerCertByName"]);
    let ech = get(&["ech", "echConfigList"]);
    if !pin.is_empty() || !names.is_empty() || !ech.is_empty() {
        let mut tls = json!({});
        for (key, value) in [("pinnedPeerCertSha256", pin), ("verifyPeerCertByName", names), ("echConfigList", ech)] {
            if !value.is_empty() { tls[key] = json!(value); }
        }
        options["tlsSettings"] = tls;
    }
    if !get(&["pqv"]).is_empty() { options["realitySettings"] = json!({"mldsa65Verify": get(&["pqv"])}); }
    if s.network == "kcp" && !get(&["seed"]).is_empty() { options["kcpSettings"] = json!({"seed": get(&["seed"])}); }
    if s.network == "grpc" && !s.host.is_empty() { options["grpcSettings"] = json!({"authority": s.host}); }
    normalize_stream(&mut options, 0)?;
    if s.security == "tls" && s.allow_insecure {
        if options["tlsSettings"]["pinnedPeerCertSha256"].as_str().is_some_and(|p| !p.is_empty()) {
            s.allow_insecure = false;
        } else {
            return Err("this Xray core requires a trusted certificate or pinnedPeerCertSha256; allowInsecure is unsupported".into());
        }
    }
    s.options = if options.as_object().unwrap().len() > 2 { Some(options) } else { None };
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{config, connection};

    // Same structures as typical v2rayN exports, with synthetic addresses and credentials.
    pub(crate) fn sample(tls: bool) -> Value {
        let mut outbound = json!({
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": "upload.example.invalid", "port": 443,
                "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption":
                    "mlkem768x25519plus.native.0rtt.SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"}]}]},
            "streamSettings": {"network": "xhttp", "xhttpSettings": {
                "mode": "stream-up", "path": "/assets", "host": "cdn.example.invalid",
                "extra": {"scMaxEachPostBytes": "1000000", "scMinPostsIntervalMs": "30", "xPaddingBytes": "100-1000"}
            }}
        });
        if tls {
            outbound["settings"]["vnext"][0]["users"][0]["encryption"] = json!("none");
            outbound["streamSettings"]["security"] = json!("tls");
            outbound["streamSettings"]["tlsSettings"] = json!({"serverName": "cdn.example.invalid", "fingerprint": "chrome",
                "pinnedPeerCertSha256": "610792abc1380f3fe53381ed3ba0c1a6a71a893755106d729b9d80e5930ae8be", "show": false});
            outbound["streamSettings"]["xhttpSettings"] = json!({"mode": "auto", "host": "cdn.example.invalid", "extra": {
                "headers": {"Pragma": "no-cache"}, "scMaxEachPostBytes": 1000000, "scMaxConcurrentPosts": 100,
                "scMinPostsIntervalMs": 30, "xPaddingBytes": "100-1000", "noGRPCHeader": false, "noSSEHeader": false,
                "xPaddingObfsMode": false}});
        }
        json!({"remarks": "🇨🇦 نمونه فارسی", "log": {"access": "untrusted.log"},
            "inbounds": [{"listen": "0.0.0.0", "port": 10808, "protocol": "socks"}],
            "dns": {"servers": ["8.8.8.8"]}, "routing": {"rules": []},
            "outbounds": [outbound, {"protocol": "freedom", "tag": "DIRECT"}, {"protocol": "blackhole", "tag": "BLOCK"}]})
    }

    fn imported(value: &Value) -> Profile {
        let parsed = parse_many(&value.to_string());
        assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
        assert_eq!(parsed.profiles.len(), 1);
        parsed.profiles.into_iter().next().unwrap()
    }

    #[test]
    fn exports_keep_xhttp_encryption_and_certificate_pins() {
        for tls in [false, true] {
            let source = sample(tls);
            let p = imported(&source);
            assert_eq!(p.name, "🇨🇦 نمونه فارسی");
            assert_eq!(p.insecure(), None);
            let config = config::build(&p, &config::tests::inbounds(), &crate::store::Settings::default(),
                &config::Assets { geoip: false, geosite: false });
            let out = &config["outbounds"][0];
            assert_eq!(out["streamSettings"]["xhttpSettings"], source["outbounds"][0]["streamSettings"]["xhttpSettings"]);
            assert_eq!(out["settings"]["encryption"], source["outbounds"][0]["settings"]["vnext"][0]["users"][0]["encryption"]);
            if tls { assert_eq!(out["streamSettings"]["tlsSettings"], source["outbounds"][0]["streamSettings"]["tlsSettings"]); }
            assert!(config["inbounds"].as_array().unwrap().iter().all(|i| i["listen"] == "127.0.0.1"));
            assert!(config.get("dns").is_none());
            assert!(!config.to_string().contains("untrusted.log"));
            assert_eq!(config::build_test(&p, 10803)["outbounds"][0], *out);
            let view = serde_json::to_string(&p.view()).unwrap();
            assert!(!view.contains(&p.secret));
            assert!(!view.contains("pinnedPeerCert"));
            // Private advanced fields survive encrypted-store serialization.
            let saved: Profile = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
            assert_eq!(config::build_test(&saved, 10803), config::build_test(&p, 10803));
        }
        let mut pinned = sample(true);
        pinned["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] = json!(true);
        let p = imported(&pinned);
        let c = config::build_test(&p, 10803);
        let tls = &c["outbounds"][0]["streamSettings"]["tlsSettings"];
        assert!(tls.get("allowInsecure").is_none());
        assert_eq!(tls["pinnedPeerCertSha256"], pinned["outbounds"][0]["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"]);
    }

    #[test]
    fn lists_base64_mixed_text_and_single_outbounds() {
        let full = sample(true);
        let standalone = &full["outbounds"][0];
        for value in [json!([full, standalone, "trojan://pass@example.invalid:443"]),
            json!([sample(false), sample(true), sample(false)])] {
            let pretty = serde_json::to_string_pretty(&value).unwrap();
            for text in [pretty.clone(), base64::engine::general_purpose::STANDARD.encode(&pretty)] {
                let parsed = parse_many(&text);
                assert_eq!(parsed.profiles.len(), 3, "{:?}", parsed.errors);
                assert_eq!(parsed.skipped, 0);
            }
        }
        let text = format!("trojan://pass@example.invalid:443\n{}\n{}\nbad://secret\n", serde_json::to_string_pretty(standalone).unwrap(), sample(false));
        let parsed = parse_many(&text);
        assert_eq!((parsed.profiles.len(), parsed.skipped), (3, 1));
        assert!(!parsed.errors.join(" ").contains("secret"));
    }

    pub(crate) fn common_samples() -> Vec<(&'static str, Value)> {
        [
            ("vmess", json!({"vnext": [{"address": "example.invalid", "port": 443, "users": [{"id": "11111111-2222-3333-4444-555555555555", "security": "auto"}]}]})),
            ("trojan", json!({"servers": [{"address": "example.invalid", "port": "443", "password": "pass"}]})),
            ("shadowsocks", json!({"address": "example.invalid", "port": 443, "password": "pass", "method": "aes-256-gcm"})),
            ("http", json!({"servers": [{"address": "example.invalid", "port": 443, "users": [{"user": "name", "pass": "pass"}]}]})),
            ("socks", json!({"address": "example.invalid", "port": 443, "user": "name", "pass": "pass"})),
        ].into_iter().map(|(protocol, settings)| {
            (protocol, json!({"protocol": protocol, "settings": settings, "mux": {"enabled": false, "concurrency": -1},
                "streamSettings": {"network": "grpc", "security": "tls", "tlsSettings": {"serverName": "example.invalid"},
                "grpcSettings": {"serviceName": "service", "multiMode": true, "authority": "cdn.example.invalid"}}}))
        }).collect()
    }

    #[test]
    fn common_outbound_forms_and_advanced_transports() {
        for (protocol, source) in common_samples() {
            let p = imported(&source);
            let c = config::build_test(&p, 10803);
            assert_eq!(c["outbounds"][0]["streamSettings"], source["streamSettings"]);
            assert_eq!(c["outbounds"][0]["protocol"], protocol);
            assert_eq!(c["outbounds"][0]["settings"]["address"], "example.invalid");
            assert_eq!(c["outbounds"][0]["mux"], source["mux"]);
        }
    }

    #[test]
    fn unsafe_or_ambiguous_custom_features_are_explicit_errors() {
        for bad in [
            json!({"tlsSettings": {"certificates": [{"certificateFile": "secret.pem"}]}}),
            json!({"tlsSettings": {"masterKeyLog": "secret.log"}}),
            json!({"tlsSettings": {"MASTERKEYLOG": "secret.log"}}),
            json!({"tlsSettings": {"certificates": [{"CertificateFile": "secret.pem"}]}}),
            json!({"sockopt": {"dialerProxy": "other"}}),
            json!({"sockopt": {"customSockopt": [{"value": "x"}]}}),
            json!({"network": "quic"}),
            json!({"network": "xdrive"}),
            json!({"security": "tls", "tlsSettings": {"allowInsecure": true}}),
            json!({"address": "override.invalid"}),
            json!({"tlsSettings": "broken"}),
            json!({"xhttpSettings": []}),
            json!({"network": 3}),
        ] {
            let mut source = sample(true);
            source["outbounds"][0]["streamSettings"] = bad;
            let parsed = parse_many(&source.to_string());
            assert!(parsed.profiles.is_empty());
            assert_eq!(parsed.skipped, 1);
            assert!(!parsed.errors.join(" ").contains("secret"));
        }
        let mut source = sample(true);
        source["outbounds"][0]["settings"]["vnext"][0]["users"] = json!([{"id": "one"}, {"id": "two"}]);
        assert!(parse_many(&source.to_string()).profiles.is_empty());
        assert!(parse_many("{\"outbounds\": BROKEN SECRET}").errors.iter().all(|e| !e.contains("SECRET")));
        let parsed = parse_many(&json!(vec![sample(true); MAX_PROFILES + 2]).to_string());
        assert_eq!((parsed.profiles.len(), parsed.skipped), (MAX_PROFILES, 2));
    }

    #[test]
    fn saved_profiles_reapply_the_import_checks() {
        let mut p = imported(&sample(true));
        p.library.starred = true;
        let validated = p.validated().unwrap();
        assert_eq!(validated.id, p.id);
        assert!(validated.library.starred);
        p.stream.options = Some(json!({"network": "xhttp", "tlsSettings": {"masterKeyLog": "path"}}));
        assert!(p.validated().is_err());
        p.stream.options = Some(json!({"network": "xhttp", "xhttpSettings": "invalid"}));
        assert!(p.validated().is_err());
    }

    #[test]
    fn uri_extra_plus_and_pins_are_not_lost() {
        let extra = r#"{"headers":{"X-Test":"a+b"},"scMinPostsIntervalMs":"30"}"#;
        let escaped: String = url::form_urlencoded::byte_serialize(extra.as_bytes()).collect();
        let p = parse_link(&format!("vless://id@example.invalid:443?type=splithttp&security=tls&path=/a+b&encryption=mlkem+x&pcs={}&extra={escaped}", "ab".repeat(32))).unwrap();
        assert_eq!(p.method, "mlkem+x");
        let out = &config::build_test(&p, 10803)["outbounds"][0]["streamSettings"];
        assert_eq!(out["xhttpSettings"]["path"], "/a+b");
        assert_eq!(out["xhttpSettings"]["extra"]["headers"]["X-Test"], "a+b");
        assert_eq!(out["tlsSettings"]["pinnedPeerCertSha256"], "ab".repeat(32));
        assert!(parse_link("vless://id@example.invalid:443?type=xhttp&extra=not-json").is_err());
        let kcp = parse_link("vless://id@example.invalid:443?type=mkcp&seed=test&headerType=srtp").unwrap();
        assert_eq!(config::build_test(&kcp, 10803)["outbounds"][0]["streamSettings"]["kcpSettings"],
            json!({"seed": "test", "header": {"type": "srtp"}}));
    }

    #[test]
    fn pinning_keeps_custom_and_download_handshakes() {
        let mut source = sample(true);
        source["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"] = json!({
            "address": "download.example.invalid", "port": 8443, "network": "splithttp", "security": "tls",
            "xhttpSettings": {"path": "/down", "mode": "stream-one"}});
        let mut p = imported(&source);
        let mut looked_up = vec![];
        p.pin_downloads(|host, port| { looked_up.push((host.to_string(), port)); Ok("203.0.113.9".parse().unwrap()) }).unwrap();
        assert_eq!(looked_up, vec![("download.example.invalid".into(), 8443)]);
        let p = connection::pin_address(&p, "203.0.113.8".parse().unwrap());
        let c = config::build_test(&p, 10803);
        let out = &c["outbounds"][0];
        assert_eq!(out["settings"]["address"], "203.0.113.8");
        assert_eq!(out["streamSettings"]["tlsSettings"]["serverName"], "cdn.example.invalid");
        let download = &out["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"];
        assert_eq!(download["address"], "203.0.113.9");
        assert_eq!(download["tlsSettings"]["serverName"], "download.example.invalid");
        assert_eq!(download["xhttpSettings"]["host"], "download.example.invalid");
        assert_eq!(download["xhttpSettings"]["path"], "/down");

        let mut no_sni = sample(true);
        no_sni["outbounds"][0]["streamSettings"]["tlsSettings"].as_object_mut().unwrap().remove("serverName");
        let pinned = connection::pin_address(&imported(&no_sni), "203.0.113.8".parse().unwrap());
        assert_eq!(pinned.stream.sni, "upload.example.invalid");
        assert_eq!(pinned.stream.host, "cdn.example.invalid");

        source["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["tlsSettings"] =
            json!({"serverName": "download-cdn.example.invalid"});
        let mut p = imported(&source);
        p.pin_downloads(|_, _| Ok("203.0.113.9".parse().unwrap())).unwrap();
        assert_eq!(p.stream.options.unwrap()["xhttpSettings"]["extra"]["downloadSettings"]["xhttpSettings"]["host"],
            "download-cdn.example.invalid");
    }
}
