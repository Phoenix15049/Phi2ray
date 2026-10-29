//! Subscriptions: fetching a provider's server list and merging updates into a group.

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};

use crate::parser::{self, Profile};

const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_INTERVAL_HOURS: u32 = 12;
/// Real subscriptions are a few KB to a few hundred KB.
const MAX_BODY: usize = 8 * 1024 * 1024;
const TOO_LARGE: &str = "The subscription is too large (over 8 MB).";
const MAX_REDIRECTS: usize = 5;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Subscription {
    pub url: String,
    pub auto_update: bool,
    pub interval_hours: u32,
    /// Unix time in milliseconds of the last successful update.
    pub updated_at: Option<u64>,
    pub last_error: Option<String>,
    /// Usage reported by the provider (`subscription-userinfo` header), in bytes.
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    /// Unix time in seconds when the subscription expires.
    pub expire: Option<u64>,
}

impl Default for Subscription {
    fn default() -> Self {
        Self {
            url: String::new(),
            auto_update: true,
            interval_hours: DEFAULT_INTERVAL_HOURS,
            updated_at: None,
            last_error: None,
            upload: None,
            download: None,
            total: None,
            expire: None,
        }
    }
}

impl Subscription {
    pub fn is_due(&self, now_ms: u64) -> bool {
        let interval_ms = u64::from(self.interval_hours.max(1)) * 3_600_000;
        self.auto_update && self.updated_at.is_none_or(|t| now_ms.saturating_sub(t) >= interval_ms)
    }
}

/// What a provider returned.
pub struct Fetched {
    pub profiles: Vec<Profile>,
    pub skipped: usize,
    /// Suggested group name (`profile-title` header).
    pub title: Option<String>,
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<u64>,
    pub interval_hours: Option<u32>,
}

/// Downloads a subscription. `proxy` routes the request through the running
/// connection, since subscription hosts are often blocked on the open network.
pub async fn fetch(url: &str, proxy: Option<&crate::probe::LocalProxy>) -> Result<Fetched, String> {
    let parsed = url::Url::parse(url.trim()).map_err(|_| "That doesn't look like a valid link.".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("Subscription links must start with https:// or http://".into());
    }

    let mut client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!("Phi2ray/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            // An https link must stay https: a redirect to http would let anyone on the
            // path read the subscription token and swap the servers.
            let downgrade = attempt.previous().iter().any(|u| u.scheme() == "https") && attempt.url().scheme() != "https";
            if downgrade {
                attempt.error("the provider redirected to an unencrypted (http) address")
            } else if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }));
    if let Some(proxy) = proxy {
        client = client.proxy(proxy.for_reqwest()?);
    } else {
        client = client.no_proxy();
    }
    let client = client.build().map_err(|e| e.to_string())?;

    let response = client.get(parsed).send().await.map_err(describe)?;
    if !response.status().is_success() {
        return Err(format!("The provider answered with HTTP {}.", response.status().as_u16()));
    }
    let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let usage = header("subscription-userinfo").map(|v| parse_userinfo(&v)).unwrap_or_default();
    let title = header("profile-title").and_then(|v| decode_title(&v));
    let interval_hours = header("profile-update-interval").and_then(|v| v.trim().parse().ok());
    // Read in pieces and stop at the limit, so a broken or hostile provider can't fill memory.
    if response.content_length().is_some_and(|len| len > MAX_BODY as u64) {
        return Err(TOO_LARGE.into());
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(describe)? {
        if bytes.len() + chunk.len() > MAX_BODY {
            return Err(TOO_LARGE.into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8_lossy(&bytes);

    let parser::Parsed { profiles, skipped, .. } = parser::parse_many(&body);
    if profiles.is_empty() {
        return Err(if body.trim().is_empty() {
            "The subscription is empty.".into()
        } else {
            "No supported servers found. Only vless, vmess, trojan and shadowsocks links are supported.".into()
        });
    }
    Ok(Fetched {
        profiles,
        skipped,
        title,
        upload: usage.get("upload").copied(),
        download: usage.get("download").copied(),
        total: usage.get("total").copied().filter(|&t| t > 0),
        expire: usage.get("expire").copied().filter(|&t| t > 0),
        interval_hours,
    })
}

/// A message for the user. Never includes the URL: it holds the subscription's token, and
/// these messages are shown, saved and logged (and logs get pasted into support chats).
fn describe(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "The provider didn't answer in time.".into()
    } else if e.is_connect() {
        "Couldn't reach the provider. If it's blocked, connect first and update again.".into()
    } else if e.is_redirect() {
        "The provider redirected to an unencrypted (http) address, or too many times.".into()
    } else {
        format!("Download failed: {}", e.without_url())
    }
}

/// `upload=1; download=2; total=3; expire=4`
fn parse_userinfo(value: &str) -> HashMap<String, u64> {
    value
        .split(';')
        .filter_map(|part| part.split_once('='))
        .filter_map(|(k, v)| Some((k.trim().to_ascii_lowercase(), v.trim().parse::<f64>().ok()? as u64)))
        .collect()
}

/// `profile-title` is plain text, percent-encoded, or `base64:<text>`.
fn decode_title(value: &str) -> Option<String> {
    let value = value.trim();
    let title = match value.strip_prefix("base64:") {
        Some(b64) => String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?).ok()?,
        None => percent_decode_str(value).decode_utf8_lossy().into_owned(),
    };
    let title = title.trim().to_string();
    (!title.is_empty()).then_some(title)
}

/// Replaces a group's servers with fresh ones, keeping the ids of servers that didn't
/// change, so the selection and test results survive an update.
pub fn merge(old: &[Profile], fresh: Vec<Profile>, group_id: &str) -> Vec<Profile> {
    let mut old_ids: HashMap<String, String> = old.iter().map(|p| (identity(p), p.id.clone())).collect();
    fresh
        .into_iter()
        .map(|mut p| {
            if let Some(id) = old_ids.remove(&identity(&p)) {
                p.id = id;
            }
            p.group_id = group_id.to_string();
            p
        })
        .collect()
}

/// What makes two servers "the same" across updates (the display name may change).
fn identity(p: &Profile) -> String {
    let s = &p.stream;
    format!(
        "{:?}|{}|{}|{}|{}|{}|{}|{}|{}",
        p.protocol, p.address, p.port, p.secret, s.network, s.security, s.path, s.host, s.sni
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_link;

    #[test]
    fn userinfo_and_title() {
        let u = parse_userinfo("upload=455727941; download=6174315083; total=1073741824000; expire=1729281113");
        assert_eq!(u["download"], 6174315083);
        assert_eq!(u["expire"], 1729281113);
        assert_eq!(decode_title("base64:8J+HqfCfh6ogTXkgVlBO").as_deref(), Some("🇩🇪 My VPN"));
        assert_eq!(decode_title("My%20VPN").as_deref(), Some("My VPN"));
        assert_eq!(decode_title("  "), None);
    }

    #[test]
    fn merge_keeps_ids_of_unchanged_servers() {
        let mut a = parse_link("trojan://pw@a.com:443#A").unwrap();
        a.id = "keep".into();
        let b = parse_link("trojan://pw@b.com:443#B").unwrap();
        let fresh = vec![parse_link("trojan://pw@a.com:443#A renamed").unwrap(), parse_link("trojan://pw@c.com:443#C").unwrap()];
        let merged = merge(&[a, b], fresh, "g1");
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "keep");
        assert_eq!(merged[0].name, "A renamed");
        assert_ne!(merged[1].id, "keep");
        assert!(merged.iter().all(|p| p.group_id == "g1"));
    }

    #[test]
    fn due() {
        let s = Subscription { updated_at: Some(0), interval_hours: 1, ..Default::default() };
        assert!(!s.is_due(1_000));
        assert!(s.is_due(3_600_000));
        assert!(!Subscription { auto_update: false, ..s }.is_due(u64::MAX));
    }
}
