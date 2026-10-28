//! Blocking HTTP probes used by the connection supervisor: "does traffic get through?"
//! and "which IP and country does the internet see?".

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use base64::Engine;
use serde::Serialize;
use url::Url;

const TIMEOUT: Duration = Duration::from_secs(6);
const MAX_BODY: usize = 16 * 1024;
/// Plain-HTTP endpoint that reports the caller's public IP and country.
const TRACE_URL: &str = "http://1.1.1.1/cdn-cgi/trace";

/// How a probe reaches the internet.
#[derive(Clone)]
pub enum Via {
    /// Straight from this process. In VPN mode that means through the tunnel, which
    /// tests the whole path apps use (adapter, routing, DNS, xray, server).
    Direct,
    /// Through xray's password-protected probe inbound, which always goes to the server.
    Proxy { port: u16, user: String, pass: String },
}

#[derive(Clone, Serialize)]
pub struct ExitInfo {
    pub ip: String,
    /// ISO country code, e.g. "DE".
    pub country: Option<String>,
}

/// Fetches `url` and returns the time to the response headers, if the status was 2xx/3xx.
pub fn check(url: &str, via: &Via) -> Option<u32> {
    let (ms, status, _) = get(url, via, MAX_BODY)?;
    (200..400).contains(&status).then_some(ms)
}

pub fn exit_info(via: &Via) -> Option<ExitInfo> {
    let (_, status, body) = get(TRACE_URL, via, MAX_BODY)?;
    if status != 200 {
        return None;
    }
    parse_trace(&body)
}

/// Total bytes (up, down) through the proxy outbound, from xray's localhost metrics endpoint.
pub fn xray_traffic(metrics_port: u16) -> Option<(u64, u64)> {
    let url = format!("http://127.0.0.1:{metrics_port}/debug/vars");
    let (_, status, body) = get(&url, &Via::Direct, 256 * 1024)?;
    if status != 200 {
        return None;
    }
    parse_traffic(&body)
}

fn parse_traffic(body: &str) -> Option<(u64, u64)> {
    let vars: serde_json::Value = serde_json::from_str(body).ok()?;
    let proxy = &vars["stats"]["outbound"]["proxy"];
    // Counters appear only after the first byte, so missing means zero.
    Some((proxy["uplink"].as_u64().unwrap_or(0), proxy["downlink"].as_u64().unwrap_or(0)))
}

fn parse_trace(body: &str) -> Option<ExitInfo> {
    let field = |key: &str| body.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string());
    Some(ExitInfo { ip: field("ip=")?, country: field("loc=").filter(|c| c.len() == 2) })
}

/// Minimal HTTP/1.1 GET with `Connection: close`. Returns (ms to first byte, status, body).
fn get(url: &str, via: &Via, max_body: usize) -> Option<(u32, u16, String)> {
    let url = Url::parse(url).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    let host_header = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };

    let mut proxy_auth = String::new();
    let (mut stream, target) = match via {
        Via::Direct => {
            let addr = (host, port).to_socket_addrs().ok()?.next()?;
            let path = match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_string(),
            };
            (TcpStream::connect_timeout(&addr, TIMEOUT).ok()?, path)
        }
        Via::Proxy { port, user, pass } => {
            let credentials = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            proxy_auth = format!("Proxy-Authorization: Basic {credentials}\r\n");
            let addr = ([127, 0, 0, 1], *port).into();
            (TcpStream::connect_timeout(&addr, TIMEOUT).ok()?, url.to_string())
        }
    };
    stream.set_read_timeout(Some(TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(TIMEOUT)).ok()?;

    let start = Instant::now();
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host_header}\r\n{proxy_auth}User-Agent: Phi2ray\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut first_byte_ms = None;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                first_byte_ms.get_or_insert(start.elapsed().as_millis() as u32);
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > max_body {
                    break;
                }
            }
            Err(_) if !buf.is_empty() => break,
            Err(_) => return None,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status = text.strip_prefix("HTTP/1.")?.get(2..5)?.parse().ok()?;
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let body = if chunked { dechunk(body) } else { body.to_string() };
    Some((first_byte_ms?, status, body))
}

/// Decodes a `Transfer-Encoding: chunked` body (Go's HTTP server uses it for large responses).
fn dechunk(mut body: &str) -> String {
    let mut out = String::new();
    while let Some((size_line, rest)) = body.split_once("\r\n") {
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if size == 0 || rest.len() < size {
            break;
        }
        out.push_str(&rest[..size]);
        body = rest[size..].strip_prefix("\r\n").unwrap_or(&rest[size..]);
    }
    out
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
    }

    #[test]
    fn traffic() {
        let body = r#"{"cmdline":["xray"],"stats":{"outbound":{"proxy":{"downlink":2048,"uplink":512},"direct":{"downlink":9,"uplink":9}}}}"#;
        assert_eq!(parse_traffic(body), Some((512, 2048)));
        assert_eq!(parse_traffic(r#"{"stats":{}}"#), Some((0, 0)));
        assert_eq!(parse_traffic("not json"), None);
    }

    #[test]
    fn chunked_bodies() {
        assert_eq!(dechunk("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), "hello world");
        assert_eq!(dechunk("a;ext=1\r\n0123456789\r\n0\r\n\r\n"), "0123456789");
    }
}
