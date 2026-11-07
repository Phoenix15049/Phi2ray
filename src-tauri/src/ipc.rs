//! The console protocol: what the `phi2ray` command-line tool sends to the running app over a
//! local named pipe (a Unix socket on Linux), and what comes back. The tool includes this same file, so both sides
//! always agree on it.
//!
//! One request per connection. The tool writes a `Request` as one JSON line; the app answers
//! with JSON lines: any number of `Reply::Progress` (one per tested server, for example), then
//! exactly one `Reply::Done` or `Reply::Failed`.

use serde::{Deserialize, Serialize};

/// Bumped when a request or reply changes in a way the other side can't read.
pub const VERSION: u32 = 1;
/// Largest request accepted. A paste of thousands of links fits.
pub const MAX_REQUEST: usize = 4 * 1024 * 1024;

/// The pipe of one Windows account's Phi2ray, like `\\.\pipe\phi2ray-S-1-5-21-…`.
#[cfg(windows)]
pub fn pipe_name(sid: &str) -> String {
    format!(r"\\.\pipe\phi2ray-{sid}")
}

/// One account's socket on Linux. The runtime folder belongs to that account alone.
#[cfg(not(windows))]
pub fn socket_path() -> Option<std::path::PathBuf> {
    let dir = std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    Some(dir.join("phi2ray").join("console.sock"))
}

/// Where an AppImage notes its own path, for `phi2ray start`.
#[cfg(not(windows))]
pub fn app_record(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".local/share/phi2ray/appimage-path")
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub version: u32,
    pub command: Command,
}

/// Servers and groups are named the way the user types them: a number from the list, a name,
/// or an id.
#[derive(Serialize, Deserialize)]
#[serde(tag = "name", rename_all = "kebab-case")]
pub enum Command {
    Status,
    Servers { group: Option<String> },
    Groups,
    /// The selected server when none is given.
    Connect { server: Option<String> },
    Disconnect,
    /// All servers (of `group`, if given) when none are listed.
    Test { servers: Vec<String>, group: Option<String> },
    /// "vpn", "proxy" or "manual"; just reports the current mode when None.
    Mode { mode: Option<String> },
    KillSwitch { on: Option<bool> },
    /// Links are added to `group` (the default group if None); an http(s) URL is added as a
    /// subscription.
    Add { text: String, group: Option<String> },
    /// Every subscription when None.
    Update { group: Option<String> },
    /// Lines after `since` (all kept lines if None), at most the last `last` of them.
    Logs { since: Option<u64>, last: usize },
    Info,
    Show,
    Quit,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Reply {
    Progress { data: serde_json::Value },
    Done { data: serde_json::Value },
    Failed { error: String },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusView {
    pub app_version: String,
    /// "connected", "reconnecting" or "disconnected".
    pub state: String,
    pub server: Option<ServerView>,
    /// "vpn", "proxy" or "manual".
    pub mode: String,
    pub kill_switch: bool,
    /// The kill switch is blocking the internet with no connection.
    pub blocked: bool,
    pub healthy: Option<bool>,
    pub latency_ms: Option<u32>,
    pub exit_ip: Option<String>,
    pub exit_country: Option<String>,
    /// Unix time in milliseconds.
    pub connected_since: Option<u64>,
    pub reconnects: u32,
    pub up_speed: u64,
    pub down_speed: u64,
    pub up_total: u64,
    pub down_total: u64,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServerView {
    /// 1-based position in the full server list; stable until servers are added or removed.
    pub number: usize,
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub transport: String,
    pub group: String,
    pub selected: bool,
    /// "unencrypted" or "unverified" when the server's traffic isn't safely encrypted.
    pub insecure: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub number: usize,
    pub id: String,
    pub name: String,
    pub servers: usize,
    pub subscription: bool,
    pub auto_update: bool,
    /// Unix time in milliseconds.
    pub updated_at: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelayView {
    pub number: usize,
    pub name: String,
    pub ms: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddView {
    pub added: usize,
    pub errors: Vec<String>,
    /// Set when a subscription was added.
    pub group: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateView {
    pub group: String,
    pub servers: Option<usize>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsView {
    pub lines: Vec<String>,
    /// Pass as `since` to get only newer lines.
    pub next: u64,
}
