//! Real delay test: starts a throwaway xray for one profile and times an HTTP
//! request through it. Unlike a TCP ping, this proves the server actually works.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::time::sleep;
use url::Url;
use rand::{distributions::Alphanumeric, Rng};

use crate::config;
use crate::parser::Profile;
use crate::xray::PortState;

pub struct TestTarget(Url);

impl TestTarget {
    pub fn parse(address: &str) -> Result<Self, String> {
        let url = Url::parse(address.trim()).map_err(|_| "Invalid test URL.")?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
            || !url.username().is_empty() || url.password().is_some() {
            return Err("Use an HTTPS or HTTP test URL without credentials.".into());
        }
        Ok(Self(url))
    }
}

/// Returns the round-trip time in milliseconds, or None if the server doesn't work.
pub async fn test(exe: &Path, asset_dir: &Path, profile: &Profile, target: &TestTarget) -> Option<u32> {
    let port = std::net::TcpListener::bind("127.0.0.1:0").ok()?.local_addr().ok()?.port();
    let credential = || rand::thread_rng().sample_iter(Alphanumeric).take(24).map(char::from).collect::<String>();
    let proxy = crate::probe::LocalProxy { port, user: credential(), pass: credential() };
    let mut cfg = config::build_test(profile, port);
    cfg["inbounds"][0]["settings"]["accounts"] = serde_json::json!([{ "user": proxy.user, "pass": proxy.pass }]);
    let cfg = cfg.to_string();

    // With the helper up, a tunnel or the kill switch may be too, and only the cores' account
    // reaches the server directly.
    #[cfg(not(windows))]
    if crate::helper::running() {
        return test_with_helper(cfg, &proxy, target).await;
    }

    crate::xray::verify(exe).ok()?;
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

    let result = if sent && wait_ready(&mut child, port).await { measure(&proxy, target).await } else { None };
    let _ = child.kill().await;
    result
}

#[cfg(not(windows))]
async fn test_with_helper(config: String, proxy: &crate::probe::LocalProxy, target: &TestTarget) -> Option<u32> {
    let port = proxy.port;
    let test = tokio::task::spawn_blocking(move || crate::helper::start_test(config, port)).await.ok()??;
    let result = measure(proxy, target).await;
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
            PortState::Taken(_) | PortState::Unverified => return false,
            PortState::Waiting => {}
        }
        sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Times one request through the local HTTP proxy on `port`.
async fn measure(proxy: &crate::probe::LocalProxy, target: &TestTarget) -> Option<u32> {
    crate::probe::measure(target.0.as_str(), proxy).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target() {
        assert!(TestTarget::parse("https://example.test/generate_204").is_ok());
        assert!(TestTarget::parse("http://example.test:8080/").is_ok());
        assert!(TestTarget::parse("http://user:password@example.test/").is_err());
        assert!(TestTarget::parse("file:///etc/passwd").is_err());
    }
}
