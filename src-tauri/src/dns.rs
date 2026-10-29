//! Tests DNS-over-HTTPS servers with a real lookup, so the settings page can show
//! which one answers fastest. A TCP "ping" would be meaningless here: in VPN mode the
//! tunnel accepts every TCP handshake locally in about a millisecond.

use std::time::{Duration, Instant};

use base64::Engine;

const TIMEOUT: Duration = Duration::from_secs(6);
/// Looked up during the test.
const TEST_NAME: &str = "www.google.com";

/// Milliseconds for one lookup over an already-open connection (what browsing feels like),
/// or an error message for servers that can't be tested.
pub async fn ping(address: &str, proxy: Option<&crate::probe::LocalProxy>) -> Result<Option<u32>, String> {
    let url = url::Url::parse(address.trim()).map_err(|_| "Only DNS-over-HTTPS servers can be tested.".to_string())?;
    if url.scheme() != "https" {
        return Err("Only DNS-over-HTTPS servers can be tested.".into());
    }

    let mut client = reqwest::Client::builder().timeout(TIMEOUT);
    client = match proxy {
        Some(p) => client.proxy(p.for_reqwest()?),
        None => client.no_proxy(),
    };
    let client = client.build().map_err(|e| e.to_string())?;

    let query = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query_packet(TEST_NAME));
    let mut request_url = url.clone();
    request_url.query_pairs_mut().append_pair("dns", &query);

    // The first lookup also opens the TLS connection; the second shows the steady-state latency.
    let mut best = None;
    for _ in 0..2 {
        let start = Instant::now();
        let ok = match client.get(request_url.clone()).header("accept", "application/dns-message").send().await {
            Ok(resp) if resp.status().is_success() => resp.bytes().await.map(|b| is_answer(&b)).unwrap_or(false),
            _ => false,
        };
        if !ok {
            return Ok(None);
        }
        best = Some(start.elapsed().as_millis() as u32);
    }
    Ok(best)
}

/// Encrypted resolvers reached by IP, so finding them needs no DNS of its own.
const BOOTSTRAP_DOH: [&str; 2] = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"];
/// Kept short: if DoH is blocked, connecting falls back to the system's DNS without much delay.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_millis(1500);

/// The server's IPv4 addresses over DNS-over-HTTPS, before the tunnel exists: the network's
/// own DNS doesn't see the name and can't hand back a fake answer. Both resolvers are asked at
/// once and the first useful answer wins. Empty if neither answers in time.
pub async fn resolve_bootstrap(name: &str, proxy: Option<&crate::probe::LocalProxy>) -> Vec<std::net::IpAddr> {
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if !valid {
        return Vec::new();
    }
    let mut client = reqwest::Client::builder().timeout(BOOTSTRAP_TIMEOUT);
    client = match proxy.map(|p| p.for_reqwest()) {
        Some(Ok(p)) => client.proxy(p),
        _ => client.no_proxy(),
    };
    let Ok(client) = client.build() else { return Vec::new() };
    let query = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query_packet(name));
    let ask = |server: &'static str| {
        let (client, query) = (client.clone(), query.clone());
        async move {
            let url = format!("{server}?dns={query}");
            let resp = client.get(url).header("accept", "application/dns-message").send().await.ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let body = resp.bytes().await.ok()?;
            let ips = a_records(&body);
            (!ips.is_empty()).then_some(ips)
        }
    };
    let (a, b) = (Box::pin(ask(BOOTSTRAP_DOH[0])), Box::pin(ask(BOOTSTRAP_DOH[1])));
    let first = tokio::time::timeout(BOOTSTRAP_TIMEOUT, async {
        match futures_select(a, b).await {
            (Some(ips), _) => Some(ips),
            (None, other) => other.await,
        }
    })
    .await;
    first.ok().flatten().unwrap_or_default().into_iter().map(std::net::IpAddr::V4).collect()
}

/// Waits for whichever future finishes first; returns its result and the one still running.
async fn futures_select<F>(a: std::pin::Pin<Box<F>>, b: std::pin::Pin<Box<F>>) -> (F::Output, std::pin::Pin<Box<F>>)
where
    F: std::future::Future,
{
    let mut a = Some(a);
    let mut b = Some(b);
    std::future::poll_fn(move |cx| {
        if let std::task::Poll::Ready(out) = a.as_mut().unwrap().as_mut().poll(cx) {
            return std::task::Poll::Ready((out, b.take().unwrap()));
        }
        if let std::task::Poll::Ready(out) = b.as_mut().unwrap().as_mut().poll(cx) {
            return std::task::Poll::Ready((out, a.take().unwrap()));
        }
        std::task::Poll::Pending
    })
    .await
}

/// The IPv4 addresses (type A) in a DNS response; empty for errors or anything malformed.
fn a_records(packet: &[u8]) -> Vec<std::net::Ipv4Addr> {
    let mut ips = Vec::new();
    if !is_answer(packet) {
        return ips;
    }
    let count = |i: usize| u16::from_be_bytes([packet[i], packet[i + 1]]) as usize;
    let (questions, answers) = (count(4), count(6));
    // Skips a (possibly compressed) name; None if it runs off the end.
    let skip_name = |mut i: usize| -> Option<usize> {
        loop {
            let len = *packet.get(i)? as usize;
            if len == 0 {
                return Some(i + 1);
            }
            if len & 0xC0 == 0xC0 {
                return Some(i + 2);
            }
            i += 1 + len;
        }
    };
    let mut i = 12;
    for _ in 0..questions {
        let Some(next) = skip_name(i) else { return Vec::new() };
        i = next + 4;
    }
    for _ in 0..answers {
        let Some(next) = skip_name(i) else { break };
        let Some(head) = packet.get(next..next + 10) else { break };
        let (kind, len) = (u16::from_be_bytes([head[0], head[1]]), u16::from_be_bytes([head[8], head[9]]) as usize);
        let Some(data) = packet.get(next + 10..next + 10 + len) else { break };
        if kind == 1 && len == 4 {
            ips.push(std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        i = next + 10 + len;
    }
    ips
}

/// A standard DNS query for the A record of `name`.
fn query_packet(name: &str) -> Vec<u8> {
    // Header: id 0, recursion desired, one question.
    let mut packet = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]); // root, type A, class IN
    packet
}

/// A response with no error code.
fn is_answer(packet: &[u8]) -> bool {
    packet.len() >= 12 && packet[2] & 0x80 != 0 && packet[3] & 0x0F == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_shape() {
        let p = query_packet("a.bc");
        assert_eq!(&p[12..], &[1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
        assert!(is_answer(&[0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]));
        assert!(!is_answer(&[0, 0, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn reads_a_records() {
        // Question a.bc A IN; a CNAME (skipped) then an A record, both with compressed names.
        let mut p = vec![0, 0, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        p.extend_from_slice(&[1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
        p.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 12]);
        p.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7]);
        assert_eq!(a_records(&p), vec![std::net::Ipv4Addr::new(203, 0, 113, 7)]);
        // Truncated or garbage packets give nothing and never panic.
        for cut in 0..p.len() {
            let _ = a_records(&p[..cut]);
        }
        assert!(a_records(&[0, 0, 0x81, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 7]).is_empty());
    }
}
