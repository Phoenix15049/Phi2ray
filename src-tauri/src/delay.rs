//! Real delay test: starts a throwaway xray for one profile and times an HTTP
//! request through it. Unlike a TCP ping, this proves the server actually works.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use url::Url;

use crate::config;
use crate::parser::Profile;
use crate::xray::PortState;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

/// A plain-HTTP URL to fetch through the proxy, e.g. a generate_204 endpoint.
pub struct TestTarget {
    request: Vec<u8>,
}

impl TestTarget {
    pub fn parse(address: &str) -> Result<Self, String> {
        let url = Url::parse(address.trim()).map_err(|_| format!("Invalid test URL: {address}"))?;
        if url.scheme() != "http" {
            return Err("The test URL must start with http://".into());
        }
        let host = url.host_str().ok_or("The test URL has no host.")?;
        let host_header = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        let request = format!("GET {url} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Phi2ray\r\nConnection: close\r\n\r\n");
        Ok(Self { request: request.into_bytes() })
    }
}

/// Returns the round-trip time in milliseconds, or None if the server doesn't work.
pub async fn test(exe: &Path, asset_dir: &Path, profile: &Profile, target: &TestTarget) -> Option<u32> {
    let port = std::net::TcpListener::bind("127.0.0.1:0").ok()?.local_addr().ok()?.port();
    let cfg = config::build_test(profile, port).to_string();

    // With the helper up, a tunnel or the kill switch may be too, and only the cores' account
    // reaches the server directly.
    #[cfg(not(windows))]
    if crate::helper::running() {
        return test_with_helper(cfg, port, target).await;
    }

    let mut cmd = Command::new(exe);
    cmd.args(["run", "-format", "json", "-c", "stdin:"])
        .env("XRAY_LOCATION_ASSET", asset_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(crate::xray::CREATE_NO_WINDOW);
    // Tied to this thread, which lives as long as the app's async runtime.
    #[cfg(not(windows))]
    unsafe {
        cmd.pre_exec(crate::platform::die_with_parent);
    }

    let mut child = cmd.spawn().ok()?;
    #[cfg(windows)]
    if child.raw_handle().is_none_or(|handle| crate::platform::bind_to_app(handle).is_err()) {
        let _ = child.kill().await;
        return None;
    }
    let mut stdin = child.stdin.take()?;
    let sent = stdin.write_all(cfg.as_bytes()).await.is_ok();
    drop(stdin);

    let result = if sent && wait_ready(&mut child, port).await { measure(port, target).await } else { None };
    let _ = child.kill().await;
    result
}

#[cfg(not(windows))]
async fn test_with_helper(config: String, port: u16, target: &TestTarget) -> Option<u32> {
    let test = tokio::task::spawn_blocking(move || crate::helper::start_test(config, port)).await.ok()??;
    let result = measure(port, target).await;
    let _ = tokio::task::spawn_blocking(move || crate::helper::stop_test(test)).await;
    result
}

async fn wait_ready(child: &mut Child, port: u16) -> bool {
    let Some(pid) = child.id() else { return false };
    for _ in 0..60 {
        if !matches!(child.try_wait(), Ok(None)) {
            return false; // xray rejected the config
        }
        match crate::xray::port_state(pid, &[port]) {
            PortState::Ready => return true,
            PortState::Taken(_) => return false,
            PortState::Waiting => {}
        }
        sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Times one request through the local HTTP proxy on `port`.
pub async fn measure(port: u16, target: &TestTarget) -> Option<u32> {
    timeout(REQUEST_TIMEOUT, async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        let start = Instant::now();
        stream.write_all(&target.request).await.ok()?;
        read_success(&mut stream).await.then(|| start.elapsed().as_millis() as u32)
    })
    .await
    .ok()
    .flatten()
}

async fn read_success(stream: &mut (impl AsyncRead + Unpin)) -> bool {
    // Read the entire status code and its separator, even when TCP splits them across reads.
    let mut head = [0u8; 13];
    stream.read_exact(&mut head).await.is_ok() && is_success(&head)
}

/// True for an HTTP 2xx status line. Redirects don't count (captive portals answer with one).
fn is_success(head: &[u8]) -> bool {
    head.starts_with(b"HTTP/1.")
        && matches!(head.get(7), Some(b'0' | b'1'))
        && head.get(8) == Some(&b' ')
        && head.get(9) == Some(&b'2')
        && head.get(10..12).is_some_and(|code| code.iter().all(u8::is_ascii_digit))
        && matches!(head.get(12), Some(b' ' | b'\r'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line() {
        assert!(is_success(b"HTTP/1.1 204 No Content\r\n"));
        assert!(!is_success(b"HTTP/1.0 302 Found"));
        assert!(!is_success(b"HTTP/1.1 502 Bad Gateway"));
        assert!(!is_success(b""));
        assert!(!is_success(b"HTTP/1.1 2"));
        assert!(!is_success(b"HTTP/1.1 2xx Invalid"));
        assert!(!is_success(b"HTTP/1.1 2040 Invalid"));
    }

    #[test]
    fn fragmented_and_truncated_status_codes() {
        tauri::async_runtime::block_on(async {
            let (mut writer, mut reader) = tokio::io::duplex(7);
            let task = tauri::async_runtime::spawn(async move {
                writer.write_all(b"HTTP/1.").await.unwrap();
                tokio::task::yield_now().await;
                writer.write_all(b"1 204 ").await.unwrap();
            });
            assert!(read_success(&mut reader).await);
            task.await.unwrap();

            let mut truncated = &b"HTTP/1.1 20"[..];
            assert!(!read_success(&mut truncated).await);
            let mut failed = &b"HTTP/1.1 502 Bad Gateway\r\n"[..];
            assert!(!read_success(&mut failed).await);
        });
    }

    #[test]
    fn test_target() {
        let t = TestTarget::parse("http://cp.cloudflare.com:8080/generate_204").unwrap();
        let req = String::from_utf8(t.request).unwrap();
        assert!(req.starts_with("GET http://cp.cloudflare.com:8080/generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com:8080\r\n"));
        assert!(TestTarget::parse("https://example.com").is_err());
    }
}
