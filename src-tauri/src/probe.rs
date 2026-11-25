//! Bounded HTTP(S) probes used by the connection supervisor: "does traffic get through?"
//! and "which IP and country does the internet see?".

use std::time::{Duration, Instant};

use serde::Serialize;

const TIMEOUT: Duration = Duration::from_secs(6);
const MAX_BODY: usize = 16 * 1024;
/// HTTPS endpoint that reports the caller's public IP and country.
const TRACE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";

/// xray's password-protected probe inbound: Phi2ray's own way through the server. It always
/// goes to the server, whatever the split tunnel says, and other programs can't use it.
#[derive(Clone)]
pub struct LocalProxy {
    pub port: u16,
    pub user: String,
    pub pass: String,
}

impl LocalProxy {
    pub fn for_reqwest(&self) -> Result<reqwest::Proxy, String> {
        let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{}", self.port)).map_err(|e| e.to_string())?;
        if self.user.is_empty() && self.pass.is_empty() { Ok(proxy) } else { Ok(proxy.basic_auth(&self.user, &self.pass)) }
    }
}

#[derive(Clone, Serialize)]
pub struct ExitInfo {
    pub ip: String,
    /// ISO country code, e.g. "DE".
    pub country: Option<String>,
}

/// Fetches `url` and returns the time to the response headers, if the status was 2xx.
/// Redirects don't count: a captive portal (hotel or café Wi-Fi login) answers with one.
pub fn check(url: &str, proxy: &LocalProxy) -> Option<u32> {
    tauri::async_runtime::block_on(measure(url, proxy))
}

fn client(proxy: Option<&LocalProxy>) -> Result<reqwest::Client, String> {
    let builder = reqwest::Client::builder().no_proxy().timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    let builder = match proxy {
        Some(proxy) => builder.proxy(proxy.for_reqwest()?),
        None => builder,
    };
    builder.build().map_err(|_| "Could not create the connection probe.".into())
}

pub async fn measure(url: &str, proxy: &LocalProxy) -> Option<u32> {
    let client = client(Some(proxy)).ok()?;
    let start = Instant::now();
    let response = client.get(url).send().await.ok()?;
    response.status().is_success().then_some(start.elapsed().as_millis() as u32)
}

pub(crate) async fn bounded_body(mut response: reqwest::Response, max: usize) -> Option<Vec<u8>> {
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > max as u64) {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if chunk.len() > max - body.len() { return None; }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

/// The manual connection deadline measures the server through the private probe inbound.
pub async fn wait_for_server(url: &str, proxy: &LocalProxy, limit: Duration) -> Result<(), String> {
    let client = client(Some(proxy))?;
    tokio::time::timeout(limit, async {
        loop {
            if client.get(url).send().await.is_ok_and(|r| r.status().is_success()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .map_err(|_| format!("The server did not pass the connection check within {} seconds.", limit.as_secs()))
}

pub fn exit_info(proxy: &LocalProxy) -> Option<ExitInfo> {
    tauri::async_runtime::block_on(async {
        let response = client(Some(proxy)).ok()?.get(TRACE_URL).send().await.ok()?;
        let body = bounded_body(response, MAX_BODY).await?;
        parse_trace(std::str::from_utf8(&body).ok()?)
    })
}

/// Total bytes (up, down) through the proxy outbound, from xray's localhost metrics endpoint.
pub fn xray_traffic(metrics_port: u16) -> Option<(u64, u64)> {
    tauri::async_runtime::block_on(async {
        let url = format!("http://127.0.0.1:{metrics_port}/debug/vars");
        let response = client(None).ok()?.get(url).timeout(Duration::from_millis(750)).send().await.ok()?;
        let body = bounded_body(response, 256 * 1024).await?;
        parse_traffic(std::str::from_utf8(&body).ok()?)
    })
}

fn parse_traffic(body: &str) -> Option<(u64, u64)> {
    let vars: serde_json::Value = serde_json::from_str(body).ok()?;
    let proxy = &vars["stats"]["outbound"]["proxy"];
    // Counters appear only after the first byte, so missing means zero.
    Some((proxy["uplink"].as_u64().unwrap_or(0), proxy["downlink"].as_u64().unwrap_or(0)))
}

fn parse_trace(body: &str) -> Option<ExitInfo> {
    let field = |key: &str| body.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string());
    let ip = field("ip=")?.parse::<std::net::IpAddr>().ok().filter(|ip| crate::netinfo::is_public(*ip))?;
    let country = field("loc=").filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()));
    Some(ExitInfo { ip: ip.to_string(), country })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace() {
        let info = parse_trace("fl=1\nh=1.1.1.1\nip=2.59.135.114\nts=1\nloc=DE\ncolo=FRA\n").unwrap();
        assert_eq!(info.ip, "2.59.135.114");
        assert_eq!(info.country.as_deref(), Some("DE"));
        assert!(parse_trace("nothing").is_none());
        assert!(parse_trace("ip=127.0.0.1").is_none());
        assert!(parse_trace("ip=invalid").is_none());
    }

    #[test]
    fn traffic() {
        let body = r#"{"cmdline":["xray"],"stats":{"outbound":{"proxy":{"downlink":2048,"uplink":512},"direct":{"downlink":9,"uplink":9}}}}"#;
        assert_eq!(parse_traffic(body), Some((512, 2048)));
        assert_eq!(parse_traffic(r#"{"stats":{}}"#), Some((0, 0)));
        assert_eq!(parse_traffic("not json"), None);
    }

}
