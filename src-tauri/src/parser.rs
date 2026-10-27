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

/// Parses pasted text: one link per line, or a base64 subscription body.
pub fn parse_many(text: &str) -> (Vec<Profile>, Vec<String>) {
    let text = text.trim();
    let body = if text.contains("://") {
        text.to_string()
    } else {
        b64_decode(text)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| text.to_string())
    };

    let mut profiles = Vec::new();
    let mut errors = Vec::new();
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_link(line) {
            Ok(p) => profiles.push(p),
            Err(e) => errors.push(format!("{}…: {e}", line.chars().take(32).collect::<String>())),
        }
    }
    (profiles, errors)
}

pub fn parse_link(link: &str) -> Result<Profile, String> {
    let (scheme, _) = link.split_once("://").ok_or("not a link")?;
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_url_style(link, Protocol::Vless),
        "trojan" => parse_url_style(link, Protocol::Trojan),
        "vmess" => parse_vmess(link),
        "ss" => parse_ss(link),
        other => Err(format!("unsupported protocol: {other}")),
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
        let (ok, errs) = parse_many(&body);
        assert_eq!(ok.len(), 2);
        assert_eq!(errs.len(), 1);
    }
}
