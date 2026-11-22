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


const TIMEOUT: Duration = Duration::from_secs(7);
/// These answers are a few hundred bytes; anything far bigger is not what we asked for.
const MAX_BODY: usize = 64 * 1024;
const TRACE_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";
/// DNS blocklists that answer through public resolvers. Spamhaus, for one, refuses them.
const BLOCKLISTS: [(&str, &str); 5] = [
    ("Barracuda", "b.barracudacentral.org"),
    ("blocklist.de", "bl.blocklist.de"),
    ("DroneBL", "dnsbl.dronebl.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("s5h", "all.s5h.net"),
];

#[derive(Clone, Copy)]
enum Source {
    IpApi,
    IpQuery,
    FreeIpApi,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::IpApi => "ipapi.co",
            Source::IpQuery => "IPQuery",
            Source::FreeIpApi => "FreeIPAPI",
        }
    }

    /// The caller's own IP when `ip` is None.
    fn url(self, ip: Option<IpAddr>) -> String {
        match (self, ip) {
            (Source::IpApi, None) => "https://ipapi.co/json/".into(),
            (Source::IpApi, Some(ip)) => format!("https://ipapi.co/{ip}/json/"),
            (Source::IpQuery, None) => "https://api.ipquery.io/?format=json".into(),
            (Source::IpQuery, Some(ip)) => format!("https://api.ipquery.io/{ip}?format=json"),
            (Source::FreeIpApi, None) => "https://free.freeipapi.com/api/v1/json".into(),
            (Source::FreeIpApi, Some(ip)) => format!("https://free.freeipapi.com/api/v1/json/{ip}"),
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
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub error: Option<String>,
}

/// How the exit IP looks to the rest of the internet.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Quality {
    /// 0 to 100, higher is better: 100 minus the named provider's risk rating.
    pub score: Option<u8>,
    pub score_source: Option<&'static str>,
    pub risk: Option<u8>,
    pub confidence: Option<u8>,
    pub vpn: Option<bool>,
    pub proxy: Option<bool>,
    pub tor: Option<bool>,
    pub hosting: Option<bool>,
    pub compromised: Option<bool>,
    pub scraper: Option<bool>,
    pub attack_count: Option<u64>,
    /// "Residential", "Business", "Wireless" or "Hosting".
    pub network: Option<String>,
    pub operator: Option<String>,
    pub blocklists: Vec<Blocklist>,
    pub error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Blocklist {
    pub name: &'static str,
    /// None when the list gave no usable answer.
    pub listed: Option<bool>,
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
    pub exit_ip: IpAddr,
    pub exit: Vec<Geo>,
    pub trace: Option<Trace>,
    pub entry: Option<Entry>,
    pub quality: Option<Quality>,
    pub checked_at: u64,
}

pub async fn lookup(target: InfoTarget) -> Result<Report, String> {
    let proxy = target.via.for_reqwest()?;
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("Phi2ray/", env!("CARGO_PKG_VERSION")))
        .proxy(proxy)
        .build()
        .map_err(|e| e.to_string())?;

    let spawn_geo = |source, ip| {
        let client = client.clone();
        tauri::async_runtime::spawn(async move { geo(&client, source, ip).await })
    };
    let ipapi = spawn_geo(Source::IpApi, None);
    let free = spawn_geo(Source::FreeIpApi, None);
    let ipquery = {
        let client = client.clone();
        tauri::async_runtime::spawn(async move { get_json(&client, &Source::IpQuery.url(None)).await })
    };
    let trace = {
        let client = client.clone();
        tauri::async_runtime::spawn(async move { trace(&client).await })
    };
    let entry_ip = target.server_ip.map(|ip| ip.to_canonical());
    let entry_tasks = entry_ip.filter(|&ip| is_public(ip)).map(|ip| [
        spawn_geo(Source::IpApi, Some(ip)), spawn_geo(Source::IpQuery, Some(ip)),
    ]);

    let ipquery = ipquery.await.map_err(|e| e.to_string())?;
    let exit = vec![
        ipapi.await.map_err(|e| e.to_string())?,
        geo_result(Source::IpQuery, None, ipquery.as_ref().map_err(Clone::clone)),
        free.await.map_err(|e| e.to_string())?,
    ];
    let trace = trace.await.map_err(|e| e.to_string())?;
    let exit_ip = select_exit_ip(&exit, trace.as_ref()).ok_or("No public exit IP was reported through the server.")?;
    let quality = quality(&client, exit_ip, ipquery).await;
    let mut entry_geo = Vec::new();
    for task in entry_tasks.into_iter().flatten() {
        entry_geo.push(task.await.map_err(|e| e.to_string())?);
    }
    let entry = entry_ip.map(|ip| Entry {
        address: target.server_address,
        ip: ip.to_string(),
        public: is_public(ip),
        geo: entry_geo,
    });
    Ok(Report { exit_ip, exit, trace, entry, quality: Some(quality), checked_at: now_ms() })
}

fn select_exit_ip(exit: &[Geo], trace: Option<&Trace>) -> Option<IpAddr> {
    let answers: Vec<IpAddr> = trace.map(|t| t.ip.as_str()).into_iter().chain(exit.iter().filter_map(|g| g.ip.as_deref()))
        .filter_map(public_ip).collect();
    // Prefer the trace in a tie, but use the same address for the report and rating.
    let mut best = None;
    let mut most = 0;
    for ip in &answers {
        let count = answers.iter().filter(|answer| *answer == ip).count();
        if count > most {
            best = Some(*ip);
            most = count;
        }
    }
    best
}

async fn quality(client: &reqwest::Client, ip: IpAddr, ipquery: Result<Value, String>) -> Quality {
    let lists: Vec<_> = BLOCKLISTS
        .iter()
        .filter_map(|&(name, zone)| {
            let query = reversed(ip)?;
            let client = client.clone();
            Some(tauri::async_runtime::spawn(async move {
                Blocklist { name, listed: crate::dns::blocklisted(&client, &format!("{query}.{zone}")).await }
            }))
        })
        .collect();
    let proxycheck = match get_json(client, &format!("https://proxycheck.io/v3/{ip}?tag=0")).await {
        Ok(v) => parse_quality(&v, ip),
        Err(e) => Quality { error: Some(e), ..Quality::default() },
    };
    let mut quality = if proxycheck.risk.is_some() {
        proxycheck
    } else {
        let fallback = match ipquery {
            Ok(v) if text(&v, "ip").as_deref().and_then(public_ip) != Some(ip) => {
                get_json(client, &Source::IpQuery.url(Some(ip))).await
            }
            result => result,
        };
        with_fallback(proxycheck, fallback.as_ref().ok().and_then(|v| parse_ipquery_quality(v, ip)))
    };
    for task in lists {
        if let Ok(list) = task.await {
            quality.blocklists.push(list);
        }
    }
    quality
}

/// An IPv4 address the way DNS blocklists are asked: 1.2.3.4 becomes 4.3.2.1.
fn reversed(ip: IpAddr) -> Option<String> {
    let IpAddr::V4(v4) = ip else { return None };
    let [a, b, c, d] = v4.octets();
    Some(format!("{d}.{c}.{b}.{a}"))
}

fn parse_quality(v: &Value, ip: IpAddr) -> Quality {
    let entry = v.as_object().and_then(|fields| fields.iter().find_map(|(key, value)| {
        (public_ip(key) == Some(ip) && value.is_object()).then_some(value)
    }));
    let Some(entry) = entry else {
        return Quality { error: Some(api_error(v)), ..Quality::default() };
    };
    let risk = percent(&entry["risk"]);
    let found = &entry["detections"];
    let flag = |key: &str| found[key].as_bool();
    let attack_count = entry["attack_history"].as_object().and_then(|counts| {
        counts.values().try_fold(0u64, |total, count| total.checked_add(integer(count)?))
    }).filter(|count| *count <= 9_007_199_254_740_991);
    Quality {
        score: risk.map(|risk| 100 - risk),
        score_source: risk.map(|_| "proxycheck.io"),
        risk,
        confidence: percent(&found["confidence"]),
        vpn: flag("vpn"),
        proxy: flag("proxy"),
        tor: flag("tor"),
        hosting: flag("hosting"),
        compromised: flag("compromised"),
        scraper: flag("scraper"),
        attack_count,
        network: text(&entry["network"], "type"),
        operator: text(&entry["operator"], "name"),
        ..Quality::default()
    }
}

fn integer(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.trim().parse().ok())
}

fn percent(value: &Value) -> Option<u8> {
    integer(value).filter(|&number| number <= 100).map(|number| number as u8)
}

fn parse_ipquery_quality(v: &Value, ip: IpAddr) -> Option<Quality> {
    if text(v, "ip").as_deref().and_then(public_ip) != Some(ip) { return None; }
    let flags = &v["risk"];
    let risk = percent(&flags["risk_score"])?;
    Some(Quality {
        risk: Some(risk),
        score: Some(100 - risk),
        score_source: Some("IPQuery"),
        vpn: flags["is_vpn"].as_bool(),
        proxy: flags["is_proxy"].as_bool(),
        tor: flags["is_tor"].as_bool(),
        hosting: flags["is_datacenter"].as_bool(),
        ..Quality::default()
    })
}

fn with_fallback(mut quality: Quality, fallback: Option<Quality>) -> Quality {
    if let Some(fallback) = fallback {
        quality.risk = fallback.risk;
        quality.score = fallback.score;
        quality.score_source = fallback.score_source;
        quality.vpn = quality.vpn.or(fallback.vpn);
        quality.proxy = quality.proxy.or(fallback.proxy);
        quality.tor = quality.tor.or(fallback.tor);
        quality.hosting = quality.hosting.or(fallback.hosting);
        quality.error = None;
    } else if quality.error.is_none() {
        quality.error = Some("The providers did not report a risk score".into());
    }
    quality
}

async fn geo(client: &reqwest::Client, source: Source, ip: Option<IpAddr>) -> Geo {
    let result = get_json(client, &source.url(ip)).await;
    geo_result(source, ip, result.as_ref().map_err(Clone::clone))
}

fn geo_result(source: Source, ip: Option<IpAddr>, result: Result<&Value, String>) -> Geo {
    let failed = |error: String| Geo { source: source.name(), error: Some(error), ..Geo::default() };
    match result {
        Ok(v) => match parse_geo(source, v) {
            Some(geo) if ip.is_none() || geo.ip.as_deref().and_then(public_ip) == ip => geo,
            Some(_) => failed("The reported IP differs from the requested IP".into()),
            None => failed(api_error(v)),
        },
        Err(error) => failed(error),
    }
}

async fn trace(client: &reqwest::Client) -> Option<Trace> {
    parse_trace(&get(client, TRACE_URL).await.ok()?)
}

async fn get_json(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    serde_json::from_str(&get(client, url).await?).map_err(|_| "Unexpected answer".into())
}

async fn get(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let mut response = client.get(url).send().await.map_err(|e| {
        if e.is_timeout() {
            "Timed out".to_string()
        } else {
            "No answer".to_string()
        }
    })?;
    match response.status().as_u16() {
        200..=299 => {}
        429 => return Err("Rate limited, try later".into()),
        401 | 403 => return Err("Provider refused the request".into()),
        status => return Err(format!("Provider returned HTTP {status}")),
    }
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

/// A coordinate, sent as a number or a string depending on the service.
fn degrees(v: &Value, key: &str, limit: f64) -> Option<f64> {
    let value = v[key].as_f64().or_else(|| v[key].as_str()?.trim().parse().ok())?;
    (value.abs() <= limit).then_some(value)
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
                latitude: degrees(v, "latitude", 90.0),
                longitude: degrees(v, "longitude", 180.0),
                ..Geo::default()
            }
        }
        Source::IpQuery => {
            let loc = &v["location"];
            let isp = &v["isp"];
            Geo {
                ip: text(v, "ip"),
                country: country_code(loc, "country_code"),
                city: text(loc, "city"),
                region: text(loc, "state"),
                asn: asn(text(isp, "asn")),
                org: text(isp, "org").or_else(|| text(isp, "isp")),
                latitude: degrees(loc, "latitude", 90.0),
                longitude: degrees(loc, "longitude", 180.0),
                ..Geo::default()
            }
        }
        Source::FreeIpApi => Geo {
            ip: text(v, "ipAddress"),
            country: country_code(v, "countryCode"),
            region: text(v, "regionName"),
            city: text(v, "cityName"),
            asn: asn(text(v, "asn")),
            org: text(v, "asnOrganization"),
            proxy: v["isProxy"].as_bool(),
            latitude: degrees(v, "latitude", 90.0),
            longitude: degrees(v, "longitude", 180.0),
            ..Geo::default()
        },
    };
    let ip = public_ip(geo.ip.as_deref()?)?;
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
    let ip = public_ip(&field("ip=")?)?;
    Some(Trace {
        ip: ip.to_string(),
        country: field("loc=").filter(|c| c.len() == 2),
        colo: field("colo=").filter(|c| !c.is_empty() && c.len() <= 8),
    })
}

fn public_ip(raw: &str) -> Option<IpAddr> {
    let ip = raw.parse::<IpAddr>().ok()?.to_canonical();
    is_public(ip).then_some(ip)
}

/// Addresses that can have a location: not private, loopback, link-local, CGNAT or similar.
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || a == 0
                || (a == 100 && (64..128).contains(&b))
                || (a == 198 && (18..=19).contains(&b))
                || a >= 224)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let [first, second, ..] = v6.segments();
            (first & 0xe000) == 0x2000 && !(first == 0x2001 && second == 0xdb8)
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

        let g = parse_geo(Source::IpQuery, &json!({
            "ip": "2.59.135.114", "location": { "country_code": "DE", "city": "Frankfurt am Main" },
            "isp": { "asn": "AS58212", "org": "Example" }
        })).unwrap();
        assert_eq!(g.city.as_deref(), Some("Frankfurt am Main"));

        let g = parse_geo(
            Source::FreeIpApi,
            &json!({ "ipAddress": "2.59.135.114", "countryCode": "DE", "cityName": "Frankfurt am Main", "asn": "58212", "isProxy": false }),
        )
        .unwrap();
        assert_eq!((g.asn.as_deref(), g.proxy), (Some("AS58212"), Some(false)));
    }

    #[test]
    fn reads_the_quality_answer() {
        let v = json!({ "status": "ok", "2.59.135.114": {
            "risk": 50,
            "network": { "type": "Hosting" },
            "detections": { "vpn": true, "proxy": false, "tor": false, "hosting": true, "compromised": false, "confidence": 95 },
            "attack_history": { "login_attempt": 2, "registration_attempt": 3 },
            "operator": { "name": "IVPN" },
        }});
        let q = parse_quality(&v, "2.59.135.114".parse().unwrap());
        assert_eq!((q.score, q.vpn, q.proxy, q.hosting), (Some(50), Some(true), Some(false), Some(true)));
        assert_eq!((q.risk, q.confidence, q.attack_count, q.scraper), (Some(50), Some(95), Some(5), None));
        assert_eq!((q.network.as_deref(), q.operator.as_deref()), (Some("Hosting"), Some("IVPN")));

        let q = parse_quality(&json!({ "status": "denied", "message": "100 queries exhausted" }), "2.59.135.114".parse().unwrap());
        assert_eq!((q.score, q.error.as_deref()), (None, Some("100 queries exhausted")));
        let ip = "1.1.1.1".parse().unwrap();
        assert_eq!(parse_quality(&json!({ "1.1.1.1": { "risk": 900 } }), ip).score, None);
        let missing = parse_quality(&json!({ "1.1.1.1": { "detections": {"vpn": true}, "attack_history": {"login_attempt": "bad"} } }), ip);
        assert_eq!((missing.risk, missing.vpn, missing.tor, missing.attack_count), (None, Some(true), None, None));
        assert_eq!(reversed("1.2.3.4".parse().unwrap()).as_deref(), Some("4.3.2.1"));
        assert_eq!(reversed("2606:4700::1".parse().unwrap()), None);
    }

    #[test]
    fn falls_back_only_to_a_score_for_the_selected_exit() {
        let ip = "1.1.1.1".parse().unwrap();
        let primary = || parse_quality(&json!({"::ffff:1.1.1.1": {
            "risk": null, "detections": {"vpn": false, "hosting": true, "confidence": 100}
        }}), ip);
        let alternate = json!({"ip": "1.1.1.1", "risk": {
            "risk_score": 0, "is_vpn": true, "is_tor": false
        }});
        let q = with_fallback(primary(), parse_ipquery_quality(&alternate, ip));
        assert_eq!((q.risk, q.score, q.score_source), (Some(0), Some(100), Some("IPQuery")));
        assert_eq!((q.vpn, q.hosting, q.tor, q.confidence), (Some(false), Some(true), Some(false), Some(100)));
        assert!(q.error.is_none());
        assert!(parse_ipquery_quality(&alternate, "8.8.8.8".parse().unwrap()).is_none());
        assert!(parse_ipquery_quality(&json!({"ip": "1.1.1.1", "risk": {"risk_score": 150}}), ip).is_none());
        let q = with_fallback(primary(), None);
        assert!(q.score.is_none() && q.error.is_some());
    }

    #[test]
    fn coordinates_are_checked() {
        let v = json!({ "lat": "52.5", "lon": 13.4, "bad": 200 });
        assert_eq!((degrees(&v, "lat", 90.0), degrees(&v, "lon", 180.0)), (Some(52.5), Some(13.4)));
        assert_eq!(degrees(&v, "bad", 90.0), None);
    }

    #[test]
    fn errors_and_junk_are_not_answers() {
        let v = json!({ "error": true, "reason": "RateLimited" });
        assert!(parse_geo(Source::IpApi, &v).is_none());
        assert_eq!(api_error(&v), "RateLimited");
        assert!(parse_geo(Source::IpQuery, &json!({ "ip": "<script>" })).is_none());
        assert!(parse_geo(Source::FreeIpApi, &json!({ "countryCode": "DE" })).is_none());
        let wrong_ip = geo_result(Source::IpQuery, "8.8.8.8".parse().ok(), Ok(&json!({"ip": "1.1.1.1"})));
        assert!(wrong_ip.ip.is_none() && wrong_ip.error.is_some());
        assert_eq!(asn(Some("as0".into())), None);
    }

    #[test]
    fn trace() {
        let t = parse_trace("fl=1\nip=2.59.135.114\nloc=DE\ncolo=FRA\n").unwrap();
        assert_eq!((t.ip.as_str(), t.colo.as_deref()), ("2.59.135.114", Some("FRA")));
        assert!(parse_trace("ip=nope").is_none());
    }

    #[test]
    fn all_exit_metrics_use_the_same_public_ip() {
        let trace = parse_trace("ip=8.8.8.8").unwrap();
        let geo = |ip: &str| Geo { ip: Some(ip.into()), ..Geo::default() };
        assert_eq!(select_exit_ip(&[geo("1.1.1.1"), geo("1.1.1.1")], Some(&trace)), "1.1.1.1".parse().ok());
        assert_eq!(select_exit_ip(&[geo("1.1.1.1")], Some(&trace)), "8.8.8.8".parse().ok());
        assert_eq!(select_exit_ip(&[geo("127.0.0.1"), geo("ff02::1"), geo("2001:db8::1")], None), None);
    }

    #[test]
    fn public_addresses() {
        assert!(is_public("2.59.135.114".parse().unwrap()));
        assert!(!is_public("192.168.1.1".parse().unwrap()));
        assert!(!is_public("100.64.0.1".parse().unwrap()));
        assert!(!is_public("fd00::1".parse().unwrap()));
        assert!(is_public("2606:4700::1".parse().unwrap()));
        for address in ["127.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "203.0.113.1"] {
            assert!(!is_public(format!("::ffff:{address}").parse().unwrap()), "{address}");
        }
        assert!(is_public("::ffff:8.8.8.8".parse().unwrap()));
    }
}
