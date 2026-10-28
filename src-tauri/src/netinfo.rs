//! Connection info, looked up only when the user asks: the IP and location websites see
//! according to several independent databases, Cloudflare's view of the route, and where
//! the connection enters (the server address xray dials). When the entry and exit differ,
//! traffic passes through at least one intermediate hop (a relay or a CDN).
//!
//! Every request goes through the server, so none of these services sees the real IP.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::connection::{now_ms, InfoTarget};
use crate::probe::Via;

const TIMEOUT: Duration = Duration::from_secs(10);
/// These answers are a few hundred bytes; anything far bigger is not what we asked for.
const MAX_BODY: usize = 64 * 1024;
const TRACE_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";

#[derive(Clone, Copy)]
enum Source {
    IpApi,
    DbIp,
    FreeIpApi,
}

impl Source {
    const ALL: [Source; 3] = [Source::IpApi, Source::DbIp, Source::FreeIpApi];

    fn name(self) -> &'static str {
        match self {
            Source::IpApi => "ipapi.co",
            Source::DbIp => "DB-IP",
            Source::FreeIpApi => "FreeIPAPI",
        }
    }

    /// The caller's own IP when `ip` is None.
    fn url(self, ip: Option<IpAddr>) -> String {
        match (self, ip) {
            (Source::IpApi, None) => "https://ipapi.co/json/".into(),
            (Source::IpApi, Some(ip)) => format!("https://ipapi.co/{ip}/json/"),
            (Source::DbIp, None) => "https://api.db-ip.com/v2/free/self".into(),
            (Source::DbIp, Some(ip)) => format!("https://api.db-ip.com/v2/free/{ip}"),
            (Source::FreeIpApi, None) => "https://freeipapi.com/api/json".into(),
            (Source::FreeIpApi, Some(ip)) => format!("https://freeipapi.com/api/json/{ip}"),
        }
    }
}

/// One database's answer.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Geo {
    pub source: &'static str,
    pub ip: Option<String>,
    /// ISO country code, e.g. "DE".
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    /// e.g. "AS58212".
    pub asn: Option<String>,
    pub org: Option<String>,
    /// Whether the database flags the IP as a proxy or VPN, when it says.
    pub proxy: Option<bool>,
    pub error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Trace {
    pub ip: String,
    pub country: Option<String>,
    /// Cloudflare data center that answered, e.g. "FRA".
    pub colo: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// The server as written in the config (domain or IP).
    pub address: String,
    pub ip: String,
    /// False for private and other non-public addresses, which have no location.
    pub public: bool,
    pub geo: Vec<Geo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub exit: Vec<Geo>,
    pub trace: Option<Trace>,
    pub entry: Option<Entry>,
    pub checked_at: u64,
}

pub async fn lookup(target: InfoTarget) -> Result<Report, String> {
    let Via::Proxy { port, user, pass } = &target.via else {
        return Err("Connection info needs the probe proxy.".into());
    };
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
        .map_err(|e| e.to_string())?
        .basic_auth(user, pass);
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(concat!("Phi2ray/", env!("CARGO_PKG_VERSION")))
        .proxy(proxy)
        .build()
        .map_err(|e| e.to_string())?;

    let entry_ip = target.server_ip.filter(|ip| is_public(*ip));
    let spawn_geo = |source: Source, ip: Option<IpAddr>| {
        let client = client.clone();
        tauri::async_runtime::spawn(async move { geo(&client, source, ip).await })
    };
    // Everything runs at once; the slowest answer sets the wait.
    let exit_tasks: Vec<_> = Source::ALL.iter().map(|&s| spawn_geo(s, None)).collect();
    let entry_tasks: Vec<_> = match entry_ip {
        Some(ip) => [Source::IpApi, Source::FreeIpApi].iter().map(|&s| spawn_geo(s, Some(ip))).collect(),
        None => Vec::new(),
    };
    let trace_task = {
        let client = client.clone();
        tauri::async_runtime::spawn(async move { trace(&client).await })
    };

    let mut exit = Vec::new();
    for task in exit_tasks {
        exit.push(task.await.map_err(|e| e.to_string())?);
    }
    let mut entry_geo = Vec::new();
    for task in entry_tasks {
        entry_geo.push(task.await.map_err(|e| e.to_string())?);
    }
    let trace = trace_task.await.map_err(|e| e.to_string())?;

    if trace.is_none() && exit.iter().all(|g| g.ip.is_none()) {
        return Err("No answer through the server. Check the connection and try again.".into());
    }
    let entry = target.server_ip.map(|ip| Entry {
        address: target.server_address,
        ip: ip.to_string(),
        public: is_public(ip),
        geo: entry_geo,
    });
    Ok(Report { exit, trace, entry, checked_at: now_ms() })
}

async fn geo(client: &reqwest::Client, source: Source, ip: Option<IpAddr>) -> Geo {
    let failed = |error: String| Geo { source: source.name(), error: Some(error), ..Geo::default() };
    let body = match get(client, &source.url(ip)).await {
        Ok(body) => body,
        Err(e) => return failed(e),
    };
    match serde_json::from_str::<Value>(&body) {
        Ok(v) => parse_geo(source, &v).unwrap_or_else(|| failed(api_error(&v))),
        Err(_) => failed("Unexpected answer".into()),
    }
}

async fn trace(client: &reqwest::Client) -> Option<Trace> {
    parse_trace(&get(client, TRACE_URL).await.ok()?)
}

async fn get(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let mut response = client.get(url).send().await.map_err(|e| {
        if e.is_timeout() {
            "Timed out".to_string()
        } else {
            "No answer".to_string()
        }
    })?;
    if response.status().as_u16() == 429 {
        return Err("Rate limited, try later".into());
    }
    // Some of these answer errors as JSON with a 4xx status, so the body is read either way.
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "No answer".to_string())? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_BODY {
            return Err("Answer too large".into());
        }
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn text(v: &Value, key: &str) -> Option<String> {
    let s = match &v[key] {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    // A long or empty value isn't a name we want to show.
    (!s.is_empty() && s.len() <= 120 && s != "-").then_some(s)
}

fn country_code(v: &Value, key: &str) -> Option<String> {
    text(v, key).filter(|c| c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic())).map(|c| c.to_uppercase())
}

fn asn(raw: Option<String>) -> Option<String> {
    let raw = raw?;
    let digits = raw.trim_start_matches(|c: char| c.eq_ignore_ascii_case(&'a') || c.eq_ignore_ascii_case(&'s'));
    (digits.parse::<u32>().ok()? > 0).then(|| format!("AS{digits}"))
}

/// None when the answer has no IP (an error message, for instance).
fn parse_geo(source: Source, v: &Value) -> Option<Geo> {
    let geo = match source {
        Source::IpApi => {
            if v["error"].as_bool() == Some(true) {
                return None;
            }
            Geo {
                ip: text(v, "ip"),
                country: country_code(v, "country_code"),
                region: text(v, "region"),
                city: text(v, "city"),
                asn: asn(text(v, "asn")),
                org: text(v, "org"),
                ..Geo::default()
            }
        }
        Source::DbIp => Geo {
            ip: text(v, "ipAddress"),
            country: country_code(v, "countryCode"),
            region: text(v, "stateProv"),
            city: text(v, "city"),
            ..Geo::default()
        },
        Source::FreeIpApi => Geo {
            ip: text(v, "ipAddress"),
            country: country_code(v, "countryCode"),
            region: text(v, "regionName"),
            city: text(v, "cityName"),
            asn: asn(text(v, "asn")),
            org: text(v, "asnOrganization"),
            proxy: v["isProxy"].as_bool(),
            ..Geo::default()
        },
    };
    let ip = geo.ip.as_deref()?.parse::<IpAddr>().ok()?;
    Some(Geo { source: source.name(), ip: Some(ip.to_string()), ..geo })
}

fn api_error(v: &Value) -> String {
    ["reason", "error", "message"]
        .iter()
        .find_map(|k| text(v, k))
        .map(|e| e.chars().take(80).collect())
        .unwrap_or_else(|| "Unexpected answer".into())
}

fn parse_trace(body: &str) -> Option<Trace> {
    let field = |key: &str| body.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string());
    let ip = field("ip=")?.parse::<IpAddr>().ok()?.to_string();
    Some(Trace {
        ip,
        country: field("loc=").filter(|c| c.len() == 2),
        colo: field("colo=").filter(|c| !c.is_empty() && c.len() <= 8),
    })
}

/// Addresses that can have a location: not private, loopback, link-local, CGNAT or similar.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || (a == 100 && (64..128).contains(&b))
                || a >= 224)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback() || v6.is_unspecified() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_each_source() {
        let g = parse_geo(
            Source::IpApi,
            &json!({ "ip": "2.59.135.114", "city": "Neu-Isenburg", "region": "Hesse", "country_code": "DE", "asn": "AS58212", "org": "dataforest GmbH" }),
        )
        .unwrap();
        assert_eq!((g.country.as_deref(), g.asn.as_deref(), g.source), (Some("DE"), Some("AS58212"), "ipapi.co"));

        let g = parse_geo(Source::DbIp, &json!({ "ipAddress": "2.59.135.114", "countryCode": "DE", "city": "Frankfurt am Main" })).unwrap();
        assert_eq!(g.city.as_deref(), Some("Frankfurt am Main"));

        let g = parse_geo(
            Source::FreeIpApi,
            &json!({ "ipAddress": "2.59.135.114", "countryCode": "DE", "cityName": "Frankfurt am Main", "asn": "58212", "isProxy": false }),
        )
        .unwrap();
        assert_eq!((g.asn.as_deref(), g.proxy), (Some("AS58212"), Some(false)));
    }

    #[test]
    fn errors_and_junk_are_not_answers() {
        let v = json!({ "error": true, "reason": "RateLimited" });
        assert!(parse_geo(Source::IpApi, &v).is_none());
        assert_eq!(api_error(&v), "RateLimited");
        assert!(parse_geo(Source::DbIp, &json!({ "ipAddress": "<script>" })).is_none());
        assert!(parse_geo(Source::DbIp, &json!({ "countryCode": "DE" })).is_none());
        assert_eq!(asn(Some("as0".into())), None);
    }

    #[test]
    fn trace() {
        let t = parse_trace("fl=1\nip=2.59.135.114\nloc=DE\ncolo=FRA\n").unwrap();
        assert_eq!((t.ip.as_str(), t.colo.as_deref()), ("2.59.135.114", Some("FRA")));
        assert!(parse_trace("ip=nope").is_none());
    }

    #[test]
    fn public_addresses() {
        assert!(is_public("2.59.135.114".parse().unwrap()));
        assert!(!is_public("192.168.1.1".parse().unwrap()));
        assert!(!is_public("100.64.0.1".parse().unwrap()));
        assert!(!is_public("fd00::1".parse().unwrap()));
        assert!(is_public("2606:4700::1".parse().unwrap()));
    }
}
