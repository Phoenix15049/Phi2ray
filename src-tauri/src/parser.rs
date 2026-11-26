//! Parses share links, Xray JSON and plain/base64 subscriptions into private profiles.

use std::collections::HashMap;

use base64::Engine;
use percent_encoding::percent_decode_str;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[path = "custom.rs"]
pub(crate) mod custom;
#[path = "wireguard.rs"]
pub(crate) mod wireguard;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Http,
    Socks,
    Wireguard,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Stream {
    /// tcp, ws, grpc, httpupgrade, xhttp
    pub network: String,
    /// none, tls, reality
    pub security: String,
    pub sni: String,
    pub fingerprint: String,
    pub alpn: Vec<String>,
    pub allow_insecure: bool,
    pub public_key: String,
    pub short_id: String,
    pub spider_x: String,
    pub host: String,
    pub path: String,
    pub header_type: String,
    pub service_name: String,
    pub mode: String,
    /// Advanced Xray transport options, kept private like the server credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    /// Protocol credential. Never included in ProfileView.
    pub secret: String,
    /// vless encryption, vmess security or shadowsocks cipher.
    pub method: String,
    pub flow: String,
    pub alter_id: u16,
    /// The group (manual list or subscription) this server belongs to.
    #[serde(default)]
    pub group_id: String,
    pub stream: Stream,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_settings: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<Value>,
    #[serde(default)]
    pub library: LibraryPreferences,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LibraryPreferences {
    pub starred: bool,
    pub custom_name: bool,
    /// This profile was added by the user, even if it lives in a subscription group.
    pub local: bool,
}

/// Most servers taken from one paste or subscription; real lists have tens to hundreds.
pub const MAX_PROFILES: usize = 2000;
/// Longest link accepted. Real ones are well under 2 KB; vmess JSON with long paths a bit more.
const MAX_LINK_LEN: usize = 16 * 1024;
const MAX_NAME_LEN: usize = 100;
/// Lines looked at in one paste or subscription, valid or not, so junk can't keep the parser busy.
const MAX_LINES: usize = 20_000;
/// Error messages kept; the rest are only counted.
const MAX_ERRORS: usize = 20;

/// The result of parsing many links at once.
pub struct Parsed {
    pub profiles: Vec<Profile>,
    /// Up to `MAX_ERRORS` messages. They name the line and protocol only, never the link
    /// itself, which holds the server's password.
    pub errors: Vec<String>,
    /// Every line that couldn't be used.
    pub skipped: usize,
}

/// What the window gets for a server: everything it shows, but no id/password.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    pub group_id: String,
    pub starred: bool,
    pub stream: StreamView,
    /// "unencrypted" or "unverified" (TLS that accepts any certificate); None when fine.
    pub insecure: Option<&'static str>,
}

#[derive(Serialize)]
pub struct StreamView {
    pub network: String,
    pub security: String,
}

impl Profile {
    pub fn validated(&self) -> Result<Self, String> {
        custom::validate_saved(self).map_err(|error| format!("This saved profile cannot be used: {error}."))
    }

    pub fn pin_downloads(&mut self, resolve: impl FnMut(&str, u16) -> Result<std::net::IpAddr, String>) -> Result<(), String> {
        custom::pin_downloads(self, resolve)
    }

    pub fn view(&self) -> ProfileView {
        ProfileView {
            id: self.id.clone(),
            name: self.name.clone(),
            protocol: self.protocol.clone(),
            address: self.address.clone(),
            port: self.port,
            group_id: self.group_id.clone(),
            starred: self.library.starred,
            stream: StreamView { network: self.stream.network.clone(), security: self.stream.security.clone() },
            insecure: self.insecure(),
        }
    }

    /// "unencrypted": no TLS/REALITY on a protocol that doesn't encrypt by itself.
    /// "unverified": TLS that accepts any certificate (`allowInsecure`), so anyone on the path
    /// could pose as the server.
    pub fn insecure(&self) -> Option<&'static str> {
        let s = &self.stream;
        let plain = matches!(s.security.as_str(), "" | "none")
            && match self.protocol {
                Protocol::Vless => matches!(self.method.as_str(), "" | "none"),
                Protocol::Trojan | Protocol::Http | Protocol::Socks => true,
                Protocol::Vmess => matches!(self.method.as_str(), "none" | "zero"),
                Protocol::Shadowsocks => matches!(self.method.as_str(), "none" | "plain"),
                Protocol::Wireguard => false,
            };
        let download_unencrypted = matches!(self.protocol, Protocol::Vless | Protocol::Vmess | Protocol::Trojan | Protocol::Shadowsocks | Protocol::Http | Protocol::Socks)
            && self.stream.options.as_ref().is_some_and(custom::unencrypted_download);
        if plain || download_unencrypted {
            Some("unencrypted")
        } else if s.security == "tls" && s.allow_insecure {
            Some("unverified")
        } else {
            None
        }
    }
}

/// Parses pasted links, JSON exports/lists, or a base64 subscription body. At most
/// `MAX_PROFILES` servers are taken; the rest count as skipped.
pub fn parse_many(text: &str) -> Parsed {
    let text = text.trim();
    if text.len() > 8 * 1024 * 1024 {
        return Parsed { profiles: vec![], errors: vec!["Input exceeds 8 MB".into()], skipped: 1 };
    }
    let body = if text.starts_with(['{', '[']) || text.contains("://") || wireguard::contains_interface(text) {
        text.to_string()
    } else {
        match b64_decode(text) {
            Ok(bytes) => {
                if let Some(error) = protected_npvs_error(&bytes) {
                    return Parsed { profiles: vec![], errors: vec![error], skipped: 1 };
                }
                String::from_utf8(bytes).unwrap_or_else(|_| text.to_string())
            }
            Err(_) => text.to_string(),
        }
    };

    let mut out = Parsed { profiles: Vec::new(), errors: Vec::new(), skipped: 0 };
    let mut remaining = body.trim_start_matches('\u{feff}');
    if is_openvpn(remaining) {
        fail(&mut out, "OpenVPN profiles (.ovpn) need an OpenVPN client.".into());
        return out;
    }
    let mut index = 0;
    let mut entries = 0;
    while !remaining.is_empty() {
        let trimmed = remaining.trim_start();
        index += remaining[..remaining.len() - trimmed.len()].bytes().filter(|&b| b == b'\n').count();
        remaining = trimmed;
        if remaining.is_empty() { break; }
        if out.profiles.len() >= MAX_PROFILES || entries >= MAX_LINES {
            let rest = remaining.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#')).count();
            out.skipped += rest;
            if out.errors.len() < MAX_ERRORS {
                out.errors.push(format!("{rest} more lines skipped (the limit is {MAX_PROFILES} servers)"));
            }
            break;
        }
        if wireguard::is_interface(remaining.lines().next().unwrap_or_default()) {
            let (config, rest) = wireguard::split_config(remaining);
            match wireguard::parse_config(config) {
                Ok(p) => push(&mut out, p),
                Err(error) => fail(&mut out, format!("Line {} (WireGuard): {error}", index + 1)),
            }
            let lines = config.lines().count();
            entries += lines;
            index += lines;
            remaining = rest;
            continue;
        }
        if remaining.starts_with(['{', '[']) {
            let mut values = serde_json::Deserializer::from_str(remaining).into_iter::<Value>();
            match values.next() {
                Some(Ok(value)) => {
                    let used = values.byte_offset();
                    custom::collect(value, &mut out, 0);
                    index += remaining[..used].bytes().filter(|&b| b == b'\n').count();
                    remaining = &remaining[used..];
                    entries += 1;
                    continue;
                }
                _ => { fail(&mut out, format!("Line {} (JSON): invalid JSON", index + 1)); break; }
            }
        }
        let (line, rest) = remaining.split_once('\n').unwrap_or((remaining, ""));
        let line = line.trim();
        remaining = rest;
        index += 1;
        if line.starts_with('#') { continue; }
        entries += 1;
        let what = format!("Line {} ({})", index, scheme_of(line));
        if line.len() > MAX_LINK_LEN {
            fail(&mut out, format!("{what}: link too long"));
            continue;
        }
        match parse_link(line) {
            Ok(p) => push(&mut out, p),
            Err(e) => fail(&mut out, format!("{what}: {}", e.chars().take(80).collect::<String>())),
        }
    }
    out
}

fn is_openvpn(text: &str) -> bool {
    let mut mode = false;
    let mut endpoint = false;
    for line in text.lines().take(MAX_LINES) {
        let mut words = line.split_ascii_whitespace();
        match words.next() {
            Some("client") => mode = true,
            Some("dev") if words.next().is_some_and(|dev| matches!(dev, "tun" | "tap")) => mode = true,
            Some("remote") if words.next().is_some() => endpoint = true,
            _ => {}
        }
        if mode && endpoint { return true; }
    }
    false
}

pub(crate) fn protected_npvs_error(bytes: &[u8]) -> Option<String> {
    let version = *bytes.strip_prefix(b"NPVS")?.first()?;
    if version >= 32 { return None; }

    // Only the compact v5 header identifies the protection method.
    let reason = if version == 5 && bytes.len() >= 62 && bytes[9] == 1 {
        let header_len = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
        if (53..=bytes.len() - 9).contains(&header_len) {
            match bytes[59] {
                0 => "The Npv Tunnel file is encrypted for specific recipients.",
                1 => "The Npv Tunnel file is protected by its creator's passphrase.",
                2 => "The file is encrypted for Npv Tunnel.",
                _ => "This is a protected Npv Tunnel file.",
            }
        } else {
            "This is a protected Npv Tunnel file."
        }
    } else {
        "This is a protected Npv Tunnel file."
    };
    Some(format!("{reason} Ask the provider for a standard subscription link or Xray JSON."))
}

fn fail(out: &mut Parsed, message: String) {
    out.skipped += 1;
    if out.errors.len() < MAX_ERRORS { out.errors.push(message); }
}

fn push(out: &mut Parsed, mut p: Profile) {
    p.name = p.name.chars().take(MAX_NAME_LEN).collect();
    out.profiles.push(p);
}

/// The link's protocol for error messages, or "?" when it doesn't look like one.
fn scheme_of(line: &str) -> String {
    match line.split_once("://") {
        Some((scheme, _)) if !scheme.is_empty() && scheme.len() <= 12 && scheme.chars().all(|c| c.is_ascii_alphanumeric()) => {
            scheme.to_ascii_lowercase()
        }
        _ => "?".into(),
    }
}

pub fn parse_link(link: &str) -> Result<Profile, String> {
    let (scheme, _) = link.split_once("://").ok_or("not a link")?;
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_url_style(link, Protocol::Vless),
        "trojan" => parse_url_style(link, Protocol::Trojan),
        "vmess" => parse_vmess(link),
        "ss" => parse_ss(link),
        "socks" | "socks5" => parse_socks5(link),
        "npv" | "npvs" | "napsternetv" => Err("Use the provider's standard share link, Xray JSON or WireGuard file".into()),
        "darktunnel" => Err("DarkTunnel exports need a standard share link or Xray JSON.".into()),
        other => Err(format!("unsupported protocol: {}", other.chars().take(12).collect::<String>())),
    }
}

fn parse_socks5(link: &str) -> Result<Profile, String> {
    let url = Url::parse(link).map_err(|_| "invalid SOCKS5 link")?;
    if !matches!(url.path(), "" | "/") || url.query().is_some() {
        return Err("SOCKS5 links take only a host, port, optional credentials and name".into());
    }
    let host = url.host_str().ok_or("missing SOCKS5 host")?;
    let address = url::Host::parse(host).map_err(|_| "invalid SOCKS5 host")?.to_string();
    let (user, pass) = (url.username(), url.password().unwrap_or_default());
    let credential = |value: &str| percent_decode_str(value).decode_utf8().map(|s| s.into_owned())
        .map_err(|_| "invalid SOCKS5 credentials");
    let (user, pass) = (credential(user)?, credential(pass)?);
    if user.is_empty() != pass.is_empty() || user.len() > 255 || pass.len() > 255 {
        return Err("SOCKS5 requires both username and password (up to 255 bytes each)".into());
    }
    custom::profile(&serde_json::json!({
        "remarks": url.fragment().map(decode),
        "protocol": "socks",
        "settings": {"address": address, "port": url.port().unwrap_or(1080), "user": user, "pass": pass}
    }))
}

/// vless://uuid@host:port?type=..&security=..#name and trojan://password@host:port?...#name
fn parse_url_style(link: &str, protocol: Protocol) -> Result<Profile, String> {
    let url = Url::parse(link).map_err(|e| e.to_string())?;
    let secret = decode(url.username());
    if secret.is_empty() {
        return Err("missing id/password".into());
    }
    let address = strip_brackets(url.host_str().ok_or("missing host")?);
    let port = url.port().ok_or("missing port")?;

    // Share links use URI escaping: a literal '+' in paths, keys or passwords is not a space.
    let q: HashMap<String, String> = url.query().unwrap_or_default().split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (decode(k), decode(v))).collect();
    let get = |k: &str| q.get(k).map(|v| v.trim().to_string()).unwrap_or_default();

    let default_security = if protocol == Protocol::Trojan { "tls" } else { "none" };
    let mut stream = Stream {
        network: normalize_network(&get("type")),
        security: or(&get("security"), default_security),
        sni: or(&get("sni"), &get("peer")),
        fingerprint: get("fp"),
        alpn: split_list(&get("alpn")),
        allow_insecure: matches!(get("allowInsecure").as_str(), "1" | "true"),
        public_key: get("pbk"),
        short_id: get("sid"),
        spider_x: get("spx"),
        host: get("host"),
        path: get("path"),
        header_type: get("headerType"),
        service_name: get("serviceName"),
        mode: get("mode"),
        ..Default::default()
    };
    custom::link_options(&mut stream, &q)?;

    let name = url.fragment().map(decode).unwrap_or_default();
    Ok(Profile {
        id: new_id(),
        name: or(&name, &format!("{address}:{port}")),
        protocol,
        address,
        port,
        secret,
        method: get("encryption"),
        flow: get("flow"),
        alter_id: 0,
        group_id: String::new(),
        stream,
        outbound_settings: None,
        mux: None,
        library: LibraryPreferences::default(),
    })
}

/// vmess://base64(json)
fn parse_vmess(link: &str) -> Result<Profile, String> {
    let body = &link["vmess://".len()..];
    let body = body.split('#').next().unwrap_or_default();
    let json = b64_decode(body)?;
    let v: Value = serde_json::from_slice(&json).map_err(|e| format!("bad vmess json: {e}"))?;
    let s = |k: &str| match v.get(k) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    };

    let address = s("add");
    let secret = s("id");
    if address.is_empty() || secret.is_empty() {
        return Err("missing address or id".into());
    }
    let port: u16 = s("port").parse().map_err(|_| "bad port")?;
    let network = normalize_network(&s("net"));
    let is_grpc = network == "grpc";
    let header_type = s("type");

    let mut stream = Stream {
        security: or(&s("tls"), "none"),
        sni: s("sni"),
        fingerprint: s("fp"),
        alpn: split_list(&s("alpn")),
        host: s("host"),
        path: if is_grpc { String::new() } else { s("path") },
        service_name: if is_grpc { s("path") } else { String::new() },
        mode: if is_grpc { header_type.clone() } else { String::new() },
        header_type: if header_type == "none" { String::new() } else { header_type },
        network,
        ..Default::default()
    };
    let q = v.as_object().map(|o| o.iter().map(|(k, v)|
        (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect()).unwrap_or_default();
    custom::link_options(&mut stream, &q)?;

    Ok(Profile {
        id: new_id(),
        name: or(&s("ps"), &format!("{address}:{port}")),
        protocol: Protocol::Vmess,
        address,
        port,
        secret,
        method: or(&s("scy"), "auto"),
        flow: String::new(),
        alter_id: s("aid").parse().unwrap_or(0),
        group_id: String::new(),
        stream,
        outbound_settings: None,
        mux: None,
        library: LibraryPreferences::default(),
    })
}

/// ss://base64(method:password)@host:port#name (SIP002),
/// ss://method:password@host:port#name, or legacy ss://base64(method:password@host:port)#name
fn parse_ss(link: &str) -> Result<Profile, String> {
    let rest = &link["ss://".len()..];
    let (main, name) = match rest.split_once('#') {
        Some((m, n)) => (m, decode(n)),
        None => (rest, String::new()),
    };
    if main.contains("plugin=") {
        return Err("shadowsocks plugins are not supported".into());
    }
    let main = main.split('?').next().unwrap_or_default().trim_end_matches('/');

    let (userinfo, hostport) = match main.rsplit_once('@') {
        Some((u, h)) => {
            let decoded = decode(u);
            let userinfo = if decoded.contains(':') {
                decoded
            } else {
                String::from_utf8(b64_decode(u)?).map_err(|e| e.to_string())?
            };
            (userinfo, h.to_string())
        }
        None => {
            let plain = String::from_utf8(b64_decode(main)?).map_err(|e| e.to_string())?;
            let (u, h) = plain.rsplit_once('@').ok_or("bad shadowsocks link")?;
            (u.to_string(), h.to_string())
        }
    };

    let (method, password) = userinfo.split_once(':').ok_or("missing cipher or password")?;
    let (host, port) = hostport.rsplit_once(':').ok_or("missing port")?;
    let address = strip_brackets(host);
    let port: u16 = port.parse().map_err(|_| "bad port")?;

    Ok(Profile {
        id: new_id(),
        name: or(&name, &format!("{address}:{port}")),
        protocol: Protocol::Shadowsocks,
        address,
        port,
        secret: password.to_string(),
        method: method.to_string(),
        flow: String::new(),
        alter_id: 0,
        group_id: String::new(),
        outbound_settings: None,
        mux: None,
        library: LibraryPreferences::default(),
        stream: Stream {
            network: "tcp".into(),
            security: "none".into(),
            ..Default::default()
        },
    })
}

/// Lenient base64: accepts standard or URL-safe alphabets, with or without padding.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(cleaned)
        .map_err(|e| format!("bad base64: {e}"))
}

fn normalize_network(n: &str) -> String {
    match n.to_ascii_lowercase().as_str() {
        "" | "raw" => "tcp".into(),
        "splithttp" => "xhttp".into(),
        "websocket" => "ws".into(),
        "mkcp" => "kcp".into(),
        other => other.into(),
    }
}

fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().trim().to_string()
}

fn strip_brackets(host: &str) -> String {
    host.trim_start_matches('[').trim_end_matches(']').to_string()
}

pub fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect()
}

/// Returns `value`, or `fallback` when `value` is empty.
pub fn or(value: &str, fallback: &str) -> String {
    if value.is_empty() { fallback } else { value }.to_string()
}

fn new_id() -> String {
    hex::encode(rand::thread_rng().gen::<[u8; 8]>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_npvs_is_identified_before_text_parsing() {
        let mut file = vec![0; 256];
        file[..5].copy_from_slice(b"NPVS\x05");
        file[5..9].copy_from_slice(&53_u32.to_be_bytes());
        file[9] = 1;

        for (method, expected) in [
            (0, "specific recipients"),
            (1, "creator's passphrase"),
            (2, "encrypted for Npv Tunnel"),
            (3, "protected Npv Tunnel file"),
        ] {
            file[59] = method;
            assert!(protected_npvs_error(&file).unwrap().contains(expected));
            let base64 = base64::engine::general_purpose::STANDARD.encode(&file);
            let parsed = parse_many(&base64);
            assert!(parsed.profiles.is_empty());
            assert_eq!(parsed.skipped, 1);
            assert!(parsed.errors[0].contains(expected));
        }

        assert!(protected_npvs_error(b"NPVS ordinary text").is_none());
        assert!(protected_npvs_error(&file[..10]).unwrap().contains("protected Npv Tunnel file"));
        file[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        file[59] = 1;
        assert!(protected_npvs_error(&file).unwrap().contains("protected Npv Tunnel file"));
    }

    #[test]
    fn recognises_native_formats_and_imports_standard_socks_links() {
        let parsed = parse_many("client\ndev tun\nremote vpn.example.test 1194\n<auth-user-pass>\nsecret\n</auth-user-pass>");
        assert!(parsed.profiles.is_empty());
        assert!(parsed.errors[0].contains("OpenVPN"));
        assert!(!parsed.errors[0].contains("secret"));
        assert!(parse_many(r#"{"v":5,"d":"opaque"}"#).errors[0].contains("SocksHTTP"));
        assert!(parse_many("darktunnel://opaque").errors[0].contains("DarkTunnel"));

        let profile = parse_link("socks5://alice:p%40ss@[2001:db8::2]:8080#Example").unwrap();
        assert_eq!((profile.name.as_str(), profile.address.as_str(), profile.port), ("Example", "2001:db8::2", 8080));
        assert_eq!(profile.insecure(), Some("unencrypted"));
        let exported = crate::config::for_export(&profile);
        assert_eq!(exported["outbounds"][0]["settings"]["user"], "alice");
        assert_eq!(exported["outbounds"][0]["settings"]["pass"], "p@ss");
        assert_eq!(parse_many(&exported.to_string()).profiles.len(), 1);
        assert_eq!(parse_link("socks5://example.test").unwrap().port, 1080);
        assert!(parse_link("socks5://alice@example.test").is_err());
        assert!(parse_link("socks5://example.test?transport=unsupported").is_err());
    }

    #[test]
    fn limits() {
        let many: String = (0..MAX_PROFILES + 5).map(|i| format!("trojan://pw@h{i}.com:443\n")).collect();
        let parsed = parse_many(&many);
        assert_eq!(parsed.profiles.len(), MAX_PROFILES);
        assert_eq!((parsed.errors.len(), parsed.skipped), (1, 5));
        let long = format!("trojan://pw@a.com:443?path={}", "a".repeat(MAX_LINK_LEN));
        assert!(parse_many(&long).profiles.is_empty());
        let named = format!("trojan://pw@a.com:443#{}", "n".repeat(500));
        assert_eq!(parse_many(&named).profiles[0].name.chars().count(), MAX_NAME_LEN);

        // Junk can't pile up error messages; everything is still counted.
        let junk = "vless://broken\n".repeat(50_000);
        let parsed = parse_many(&junk);
        assert_eq!(parsed.errors.len(), MAX_ERRORS);
        assert_eq!(parsed.skipped, 50_000);
    }

    #[test]
    fn errors_never_show_the_link() {
        let parsed = parse_many("trojan://SECRETPASS@a.com\nvless://SECRETUUID@\nnope://SECRET");
        assert_eq!(parsed.skipped, 3);
        assert!(parsed.errors.iter().all(|e| !e.contains("SECRET")), "{:?}", parsed.errors);
        assert!(parsed.errors[0].starts_with("Line 1 (trojan)"));
    }

    #[test]
    fn insecure_servers() {
        let p = |l: &str| parse_link(l).unwrap().insecure();
        assert_eq!(p("vless://id@a.com:443?security=none"), Some("unencrypted"));
        // Old saved profiles still show the warning; this core rejects new unverified TLS links.
        let mut old = parse_link("trojan://pw@a.com:443").unwrap();
        old.stream.allow_insecure = true;
        assert_eq!(old.insecure(), Some("unverified"));
        assert!(parse_link("trojan://pw@a.com:443?allowInsecure=1").is_err());
        assert_eq!(p("vless://id@a.com:443?security=reality&pbk=K"), None);
        assert_eq!(p("trojan://pw@a.com:443"), None);
        let ss = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "aes-256-gcm:pw");
        assert_eq!(p(&format!("ss://{ss}@a.com:8388")), None);
        // The window's copy has no credentials.
        let view = serde_json::to_string(&parse_link("trojan://secretpw@a.com:443").unwrap().view()).unwrap();
        assert!(!view.contains("secretpw"));
    }

    #[test]
    fn vless_reality() {
        let p = parse_link(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=reality&sni=www.google.com&fp=chrome&pbk=PUBKEY&sid=ab&flow=xtls-rprx-vision#My%20Server",
        )
        .unwrap();
        assert_eq!(p.protocol, Protocol::Vless);
        assert_eq!(p.name, "My Server");
        assert_eq!(p.port, 443);
        assert_eq!(p.stream.security, "reality");
        assert_eq!(p.stream.public_key, "PUBKEY");
        assert_eq!(p.flow, "xtls-rprx-vision");
    }

    #[test]
    fn vless_ipv6_ws() {
        let p = parse_link("vless://id@[2001:db8::1]:8080?type=ws&path=%2Fws&host=a.com").unwrap();
        assert_eq!(p.address, "2001:db8::1");
        assert_eq!(p.stream.network, "ws");
        assert_eq!(p.stream.path, "/ws");
    }

    #[test]
    fn trojan_defaults_to_tls() {
        let p = parse_link("trojan://pass@t.com:443#t").unwrap();
        assert_eq!(p.stream.security, "tls");
        assert_eq!(p.secret, "pass");
    }

    #[test]
    fn vmess_json() {
        let json = r#"{"v":"2","ps":"vm","add":"v.com","port":"443","id":"uuid","aid":"0","net":"ws","path":"/p","host":"h.com","tls":"tls"}"#;
        let link = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json));
        let p = parse_link(&link).unwrap();
        assert_eq!(p.name, "vm");
        assert_eq!(p.stream.network, "ws");
        assert_eq!(p.stream.security, "tls");
        assert_eq!(p.method, "auto");
    }

    #[test]
    fn shadowsocks_forms() {
        let ui = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:secret");
        let p = parse_link(&format!("ss://{ui}@s.com:8388#ss")).unwrap();
        assert_eq!((p.method.as_str(), p.secret.as_str(), p.port), ("aes-256-gcm", "secret", 8388));

        let p = parse_link("ss://2022-blake3-aes-128-gcm:a%2Bb@s.com:443").unwrap();
        assert_eq!(p.secret, "a+b");

        let legacy = base64::engine::general_purpose::STANDARD.encode("chacha20-ietf-poly1305:pw@1.2.3.4:443");
        let p = parse_link(&format!("ss://{legacy}#old")).unwrap();
        assert_eq!(p.address, "1.2.3.4");
    }

    #[test]
    fn subscription_body() {
        let body = base64::engine::general_purpose::STANDARD
            .encode("trojan://a@b.com:443#1\nvless://id@c.com:443#2\nbogus://x\n");
        let Parsed { profiles: ok, errors: errs, .. } = parse_many(&body);
        assert_eq!(ok.len(), 2);
        assert_eq!(errs.len(), 1);
    }
}
