//! `phi2ray-helper`: the only part of Phi2ray on Linux that runs as root.
//!
//! The app runs as the user and starts this program through `pkexec` the first time it needs it,
//! with pipes on stdin and stdout (see `helper_protocol.rs`). There is no socket and no service,
//! so nothing but that app can talk to it, and it's gone when the app is.
//!
//! What it does, and nothing else:
//! - starts xray and sing-box from its own root-owned folder, as the `phi2ray-core` account. Xray
//!   gets no rights at all; sing-box only the network rights the VPN adapter needs. Neither
//!   stays root. The kill switch tells them from everything else by that account.
//! - sets and removes the kill switch (nftables).
//!
//! When the app goes away, stdin closes and the cores stop, but the kill switch stays: it's
//! fail-closed, like the Windows filters, and a restart clears it.

#[cfg(target_os = "linux")]
#[path = "../../src/helper_protocol.rs"]
#[allow(dead_code)]
mod protocol;

#[cfg(target_os = "linux")]
mod helper;

#[cfg(target_os = "linux")]
fn main() {
    helper::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("phi2ray-helper only exists on Linux.");
    std::process::exit(1);
}
