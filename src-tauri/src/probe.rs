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
        Ok(proxy.basic_auth(&self.user, &self.pass))
    }
}

/// How a probe reaches the internet.
#[derive(Clone)]
pub enum Via {
    /// Straight from this process. In VPN mode that means through the tunnel, which
    /// tests the whole path apps use (adapter, routing, DNS, xray, server).
    Direct,
    Proxy(LocalProxy),
}

#[derive(Clone, Serialize)]
pub struct ExitInfo {
    pub ip: String,
    /// ISO country code, e.g. "DE".
    pub country: Option<String>,
}

/// Fetches `url` and returns the time to the response headers, if the status was 2xx.
/// Redirects don't count: a captive portal (hotel or café Wi-Fi login) answers with one.
pub fn check(url: &str, via: &Via) -> Option<u32> {
    let (ms, status, _) = get(url, via, MAX_BODY)?;
    (200..300).contains(&status).then_some(ms)
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
        Via::Proxy(p) => {
            let credentials = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", p.user, p.pass));
            proxy_auth = format!("Proxy-Authorization: Basic {credentials}\r\n");
            let addr = ([127, 0, 0, 1], p.port).into();
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
    let (status, body) = parse_response(&buf)?;
    Some((first_byte_ms?, status, body))
}

/// Splits a raw HTTP/1.x response into status and body. Works on bytes until the very end,
/// so a hostile or broken response (bad sizes, invalid UTF-8) can't make it panic.
fn parse_response(raw: &[u8]) -> Option<(u16, String)> {
    let status = std::str::from_utf8(raw.strip_prefix(b"HTTP/1.")?.get(2..5)?).ok()?.parse().ok()?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match split {
        Some(i) => (&raw[..i], &raw[i + 4..]),
        None => (raw, &[][..]),
    };
    let chunked = String::from_utf8_lossy(head).lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let body = if chunked { dechunk(body) } else { body.to_vec() };
    Some((status, String::from_utf8_lossy(&body).into_owned()))
}

/// Decodes a `Transfer-Encoding: chunked` body (Go's HTTP server uses it for large responses).
fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(line_end) = body.windows(2).position(|w| w == b"\r\n") {
        let size_line = String::from_utf8_lossy(&body[..line_end]);
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        let rest = &body[line_end + 2..];
        if size == 0 || rest.len() < size {
            break;
        }
        out.extend_from_slice(&rest[..size]);
        body = rest[size..].strip_prefix(b"\r\n").unwrap_or(&rest[size..]);
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
        assert_eq!(dechunk(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), b"hello world");
        assert_eq!(dechunk(b"a;ext=1\r\n0123456789\r\n0\r\n\r\n"), b"0123456789");
    }

    #[test]
    fn hostile_responses_never_panic() {
        // A chunk size that ends inside a multi-byte character used to crash the app.
        let (status, body) = parse_response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\né\r\n0\r\n\r\n".as_bytes()).unwrap();
        assert_eq!((status, body.chars().count()), (200, 1));
        assert!(parse_response(b"HTTP/1.1 2\xff\xfe").is_none());
        assert!(parse_response(b"garbage").is_none());
        let huge = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nabc";
        assert_eq!(parse_response(huge).unwrap().1, "");
        // Random bytes, including invalid UTF-8 and stray CRLFs.
        let mut seed = 0x2545_f491_u32;
        for _ in 0..2000 {
            let len = (seed % 64) as usize;
            let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                raw.push([b'1', b'f', b'\r', b'\n', 0xc3, 0xa9, 0xff, b';'][(seed % 8) as usize]);
            }
            let _ = parse_response(&raw);
        }
    }
}
