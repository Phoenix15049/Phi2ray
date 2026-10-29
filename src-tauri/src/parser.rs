//! Parses share links (vless://, vmess://, trojan://, ss://) and
//! base64 subscription bodies into `Profile`s.

use std::collections::HashMap;

use base64::Engine;
use percent_encoding::percent_decode_str;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    /// vless/vmess uuid, or trojan/shadowsocks password.
    pub secret: String,
    /// vless encryption, vmess security or shadowsocks cipher.
    pub method: String,
    pub flow: String,
    pub alter_id: u16,
    /// The group (manual list or subscription) this server belongs to.
    #[serde(default)]
    pub group_id: String,
    pub stream: Stream,
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
    pub fn view(&self) -> ProfileView {
        ProfileView {
            id: self.id.clone(),
            name: self.name.clone(),
            protocol: self.protocol.clone(),
            address: self.address.clone(),
            port: self.port,
            group_id: self.group_id.clone(),
            stream: StreamView { network: self.stream.network.clone(), security: self.stream.security.clone() },
            insecure: self.insecure(),
        }
    }

    /// "unencrypted": no TLS/REALITY on a protocol that doesn't encrypt by itself.
    /// "unverified": TLS that accepts any certificate (`allowInsecure`), so anyone on the path
    /// could pose as the server.
    pub fn insecure(&self) -> Option<&'static str> {
        let s = &self.stream;
        let plain = s.security == "none"
            && match self.protocol {
                Protocol::Vless | Protocol::Trojan => true,
                Protocol::Vmess => matches!(self.method.as_str(), "none" | "zero"),
                Protocol::Shadowsocks => matches!(self.method.as_str(), "none" | "plain"),
            };
        if plain {
            Some("unencrypted")
        } else if s.security == "tls" && s.allow_insecure {
            Some("unverified")
        } else {
            None
        }
    }
}

/// Parses pasted text: one link per line, or a base64 subscription body. At most
/// `MAX_PROFILES` servers are taken; the rest count as skipped.
pub fn parse_many(text: &str) -> Parsed {
    let text = text.trim();
    let body = if text.contains("://") {
        text.to_string()
    } else {
        b64_decode(text)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| text.to_string())
    };

    let mut out = Parsed { profiles: Vec::new(), errors: Vec::new(), skipped: 0 };
    let fail = |out: &mut Parsed, message: String| {
        out.skipped += 1;
        if out.errors.len() < MAX_ERRORS {
            out.errors.push(message);
        }
    };
    let lines: Vec<(usize, &str)> =
        body.lines().map(str::trim).enumerate().filter(|(_, l)| !l.is_empty() && !l.starts_with('#')).collect();
    for (i, &(index, line)) in lines.iter().enumerate() {
        if out.profiles.len() >= MAX_PROFILES || i >= MAX_LINES {
            let rest = lines.len() - i;
            out.skipped += rest;
            if out.errors.len() < MAX_ERRORS {
                out.errors.push(format!("{rest} more lines skipped (the limit is {MAX_PROFILES} servers)"));
            }
            break;
        }
        let what = format!("Line {} ({})", index + 1, scheme_of(line));
        if line.len() > MAX_LINK_LEN {
            fail(&mut out, format!("{what}: link too long"));
            continue;
        }
        match parse_link(line) {
            Ok(mut p) => {
                if p.name.chars().count() > MAX_NAME_LEN {
                    p.name = p.name.chars().take(MAX_NAME_LEN).collect();
                }
                out.profiles.push(p)
            }
            Err(e) => fail(&mut out, format!("{what}: {}", e.chars().take(80).collect::<String>())),
        }
    }
    out
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
        other => Err(format!("unsupported protocol: {}", other.chars().take(12).collect::<String>())),
    }
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

    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let get = |k: &str| q.get(k).map(|v| v.trim().to_string()).unwrap_or_default();

    let default_security = if protocol == Protocol::Trojan { "tls" } else { "none" };
    let stream = Stream {
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
    };

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

    let stream = Stream {
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
        assert_eq!(p("trojan://pw@a.com:443?security=tls&allowInsecure=1"), Some("unverified"));
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
