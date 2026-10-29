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
}
