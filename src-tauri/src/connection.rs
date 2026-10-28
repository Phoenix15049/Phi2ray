//! Connecting, disconnecting, and the supervisor that keeps a connection alive.
//!
//! Leak protection rules:
//! - When something fails while connected, the tunnel (or system proxy) stays in place and
//!   only the broken part is restarted, so traffic stalls instead of leaking.
//! - With the kill switch on, the firewall stays up through every restart, and even after
//!   giving up, until the user disconnects.

use std::net::{IpAddr, SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::Serialize;
use serde_json::Value;
use tauri::{AppHandle, Manager};

use crate::parser::Profile;
use crate::probe::{self, ExitInfo, Via};
use crate::split::SplitMode;
use crate::store::{Mode, Settings};
use crate::xray::{SING_BOX_EXE, XRAY_EXE};
use crate::{config, firewall, proxy, tun, win, AppState};

/// Returned by `connect` when the chosen options need an elevated process.
pub const ADMIN_REQUIRED: &str = "ADMIN_REQUIRED";

const HEALTHY_INTERVAL: Duration = Duration::from_secs(15);
const UNHEALTHY_INTERVAL: Duration = Duration::from_secs(5);
/// Failed checks in a row before xray is restarted.
const MAX_FAILURES: u32 = 3;
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkState {
    Connected,
    Reconnecting,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub ok: bool,
    pub ms: Option<u32>,
    /// Unix time in milliseconds.
    pub checked_at: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub profile_id: String,
    pub mode: Mode,
    pub socks_port: u16,
    pub http_port: u16,
    pub socks_user: String,
    pub socks_pass: String,
    /// Unix time in milliseconds.
    pub started_at: u64,
    pub state: LinkState,
    pub health: Option<Health>,
    pub exit: Option<ExitInfo>,
    pub reconnects: u32,
    pub kill_switch: bool,
    pub traffic: Traffic,
}

/// Bytes through the server: current speed (per second) and totals for this session.
#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Traffic {
    pub up_speed: u64,
    pub down_speed: u64,
    pub up_total: u64,
    pub down_total: u64,
}

/// Turns xray's raw counters into speeds and totals. xray's counters restart at zero
/// when it is restarted, so earlier totals are kept as a base.
#[derive(Default)]
struct TrafficMeter {
    base: (u64, u64),
    last_raw: (u64, u64),
    last_at: Option<Instant>,
}

impl TrafficMeter {
    fn sample(&mut self, raw: (u64, u64), now: Instant) -> Traffic {
        if raw.0 < self.last_raw.0 || raw.1 < self.last_raw.1 {
            self.base.0 += self.last_raw.0;
            self.base.1 += self.last_raw.1;
            self.last_raw = (0, 0);
        }
        let secs = self.last_at.map_or(0.0, |t| now.duration_since(t).as_secs_f64());
        let speed = |now: u64, before: u64| if secs > 0.0 { ((now - before) as f64 / secs) as u64 } else { 0 };
        let traffic = Traffic {
            up_speed: speed(raw.0, self.last_raw.0),
            down_speed: speed(raw.1, self.last_raw.1),
            up_total: self.base.0 + raw.0,
            down_total: self.base.1 + raw.1,
        };
        self.last_raw = raw;
        self.last_at = Some(now);
        traffic
    }
}

/// The running connection: what the UI sees plus what's needed to restart its parts.
pub struct Link {
    pub session: Session,
    xray_cfg: Value,
    tun_cfg: Option<Value>,
    test_url: String,
    metrics_port: u16,
    /// Probes go straight through the tunnel (VPN mode), testing the whole path apps use.
    /// Not when split tunnelling only sends listed apps through it: Phi2ray itself isn't one.
    probe_direct: bool,
    /// xray's probe inbound, which always goes to the server.
    probe_proxy: Via,
    /// The server as configured, and the IP xray dials when it was looked up beforehand.
    server_address: String,
    server_port: u16,
    server_ip: Option<IpAddr>,
}

impl Link {
    fn probe_via(&self) -> Via {
        if self.probe_direct {
            Via::Direct
        } else {
            self.probe_proxy.clone()
        }
    }
}

/// What the connection info lookup needs: a way through the server, and the server's IP.
pub struct InfoTarget {
    pub via: Via,
    pub server_address: String,
    pub server_ip: Option<IpAddr>,
}

/// Always goes through xray's probe inbound, so the answer is what the server's side sees
/// in every mode, split tunnel included. Resolving the server here uses the same DNS that
/// xray itself used to reach it.
pub fn info_target(state: &AppState) -> Result<InfoTarget, String> {
    let (via, address, port, ip) = {
        let link = state.link.lock().unwrap();
        let link = link.as_ref().ok_or("Not connected.")?;
        (link.probe_proxy.clone(), link.server_address.clone(), link.server_port, link.server_ip)
    };
    let ip = ip.or_else(|| resolve_server(state, &address, port).ok());
    Ok(InfoTarget { via, server_address: address, server_ip: ip })
}

pub fn connect(app: &AppHandle, state: &AppState, id: &str) -> Result<Session, String> {
    let _guard = state.switching.lock().unwrap();
    let (profile, settings) = {
        let mut store = state.store.lock().unwrap();
        let profile = store.profiles.iter().find(|p| p.id == id).cloned().ok_or("Server not found.")?;
        store.settings.selected = Some(id.to_string());
        store.save(&state.paths.store)?;
        (profile, store.settings.clone())
    };

    let xray_exe = state.paths.xray();
    if !xray_exe.exists() {
        return Err(format!("Xray core not found. Put {XRAY_EXE} in {}", state.paths.core.display()));
    }
    crate::verify_cached(state, &xray_exe)?;
    if settings.mode == Mode::Tun && !state.paths.sing_box().exists() {
        return Err(format!(
            "VPN mode needs {SING_BOX_EXE} in {}. Or switch to System proxy mode.",
            state.paths.core.display()
        ));
    }
    if (settings.mode == Mode::Tun || settings.kill_switch) && !win::is_elevated() {
        return Err(ADMIN_REQUIRED.into());
    }
    if settings.mode == Mode::Tun {
        crate::verify_cached(state, &state.paths.sing_box())?;
    }

    // Look the server up while any previous connection is still up: in VPN mode and with the
    // kill switch, the open network isn't usable once the new connection starts.
    let pin = settings.mode == Mode::Tun || settings.kill_switch;
    let server_ip = if pin { Some(resolve_server(state, &profile.address, profile.port)?) } else { None };
    let original_address = profile.address.clone();
    let profile = match server_ip {
        Some(ip) => pin_address(&profile, ip),
        None => profile,
    };

    if settings.kill_switch {
        firewall::enable(&firewall_rules(state, &settings))?;
        log(state, "[app] Kill switch on");
    } else if firewall::is_active() {
        firewall::disable();
        log(state, "[app] Kill switch off");
    }
    state.blocked.store(false, Ordering::SeqCst);

    // Stop the previous connection (its supervisor exits when the generation changes).
    state.generation.fetch_add(1, Ordering::SeqCst);
    state.core.lock().unwrap().stop();
    let _ = proxy::restore(&state.paths.proxy_marker);
    *state.link.lock().unwrap() = None;

    match start(state, &profile, &settings, &original_address, server_ip) {
        Ok(link) => {
            let session = link.session.clone();
            *state.link.lock().unwrap() = Some(link);
            let generation = state.generation.load(Ordering::SeqCst);
            let app = app.clone();
            thread::spawn(move || supervise(app, generation));
            Ok(session)
        }
        Err(e) => {
            // A failed manual connect leaves the network as it was before Phi2ray touched it.
            state.core.lock().unwrap().stop();
            let _ = proxy::restore(&state.paths.proxy_marker);
            firewall::disable();
            log(state, format!("[app] Connect failed: {e}"));
            Err(e)
        }
    }
}

/// `profile` may already point at `server_ip`; `original_address` is what the user configured.
fn start(
    state: &AppState,
    profile: &Profile,
    settings: &Settings,
    original_address: &str,
    server_ip: Option<IpAddr>,
) -> Result<Link, String> {
    let (socks_port, http_port) = if settings.fixed_ports {
        ensure_free(settings.socks_port)?;
        ensure_free(settings.http_port)?;
        (settings.socks_port, settings.http_port)
    } else {
        random_ports()?
    };
    let session = Session {
        profile_id: profile.id.clone(),
        mode: settings.mode,
        socks_port,
        http_port,
        socks_user: random_string(12),
        socks_pass: random_string(24),
        started_at: now_ms(),
        state: LinkState::Connected,
        health: None,
        exit: None,
        reconnects: 0,
        kill_switch: settings.kill_switch,
        traffic: Traffic::default(),
    };
    let metrics_port = random_port()?;
    let (probe_port, probe_user, probe_pass) = (random_port()?, random_string(12), random_string(24));

    let inbounds = config::Inbounds {
        socks_port,
        http_port,
        socks_user: session.socks_user.clone(),
        socks_pass: session.socks_pass.clone(),
        metrics_port,
        probe_port,
        probe_user: probe_user.clone(),
        probe_pass: probe_pass.clone(),
    };
    let assets = config::Assets {
        geoip: state.paths.core.join("geoip.dat").exists(),
        geosite: state.paths.core.join("geosite.dat").exists(),
    };
    let xray_cfg = config::build(profile, &inbounds, settings, &assets);
    let tun_cfg = match (settings.mode, server_ip) {
        (Mode::Tun, Some(server_ip)) => Some(tun::build(&tun::TunInput {
            socks_port,
            socks_user: &session.socks_user,
            socks_pass: &session.socks_pass,
            server_ip,
            settings,
        })?),
        _ => None,
    };

    log(state, format!("[app] Connecting to {} ({:?} mode)", profile.name, settings.mode));
    let mut core = state.core.lock().unwrap();
    core.start_xray(&state.paths.xray(), &state.paths.core, &xray_cfg, socks_port)?;
    match (&tun_cfg, settings.mode) {
        (Some(cfg), _) => core.start_tun(&state.paths.sing_box(), &state.paths.data.join("sing-box"), cfg)?,
        (None, Mode::System) => proxy::enable(http_port, &state.paths.proxy_marker)?,
        _ => {}
    }
    let include_only = settings.split.rules().is_some() && settings.split.mode == SplitMode::Include;
    let probe_direct = settings.mode == Mode::Tun && !include_only;
    Ok(Link {
        session,
        xray_cfg,
        tun_cfg,
        test_url: settings.test_url.clone(),
        metrics_port,
        probe_direct,
        probe_proxy: Via::Proxy { port: probe_port, user: probe_user, pass: probe_pass },
        server_address: original_address.to_string(),
        server_port: profile.port,
        server_ip,
    })
}

/// Manual disconnect: everything back to how it was, kill switch included.
pub fn disconnect(state: &AppState) {
    let _guard = state.switching.lock().unwrap();
    teardown(state);
    firewall::disable();
    state.blocked.store(false, Ordering::SeqCst);
}

/// Stops the connection but leaves the kill switch alone.
fn teardown(state: &AppState) {
    state.generation.fetch_add(1, Ordering::SeqCst);
    state.core.lock().unwrap().stop();
    let _ = proxy::restore(&state.paths.proxy_marker);
    *state.link.lock().unwrap() = None;
}

/// Applies a kill switch change to the running connection right away.
pub fn apply_kill_switch(state: &AppState, settings: &Settings) -> Result<(), String> {
    let _guard = state.switching.lock().unwrap();
    let connected = state.link.lock().unwrap().is_some();
    if settings.kill_switch && connected && !firewall::is_active() {
        if !win::is_elevated() {
            return Err("The kill switch needs administrator rights. Restart Phi2ray as administrator.".into());
        }
        firewall::enable(&firewall_rules(state, settings))?;
        log(state, "[app] Kill switch on");
    } else if !settings.kill_switch && firewall::is_active() {
        firewall::disable();
        state.blocked.store(false, Ordering::SeqCst);
        log(state, "[app] Kill switch off");
    }
    if let Some(link) = state.link.lock().unwrap().as_mut() {
        link.session.kill_switch = firewall::is_active();
    }
    Ok(())
}

/// Runs a health check now and records the result.
pub fn check_now(state: &AppState) -> Result<Health, String> {
    let (via, url) = {
        let link = state.link.lock().unwrap();
        let link = link.as_ref().ok_or("Not connected.")?;
        (link.probe_via(), link.test_url.clone())
    };
    let ms = probe::check(&url, &via);
    let health = Health { ok: ms.is_some(), ms, checked_at: now_ms() };
    let exit = ms.and_then(|_| probe::exit_info(&via));
    if let Some(link) = state.link.lock().unwrap().as_mut() {
        link.session.health = Some(health.clone());
        if exit.is_some() {
            link.session.exit = exit;
        }
    }
    Ok(health)
}

/// Watches one connection (identified by `generation`) until it is replaced or stopped.
fn supervise(app: AppHandle, generation: u64) {
    let mut failures = 0u32;
    let mut backoff = Duration::from_secs(1);
    let mut next_check = Instant::now() + Duration::from_secs(2);
    let mut need_exit_info = true;
    let mut meter = TrafficMeter::default();
    let mut traffic_warned = false;

    loop {
        thread::sleep(Duration::from_secs(1));
        let state = app.state::<AppState>();
        let current = || state.generation.load(Ordering::SeqCst) == generation;
        if !current() {
            return;
        }

        // 1. Are both cores still running?
        let (xray_ok, tun_ok) = {
            let mut core = state.core.lock().unwrap();
            (core.xray_alive(), core.tun_alive() != Some(false))
        };
        if !xray_ok || !tun_ok {
            let Ok(_guard) = state.switching.try_lock() else { continue };
            if !current() {
                return;
            }
            let part = if xray_ok { "VPN adapter" } else { "Xray" };
            log(&state, format!("[app] {part} stopped unexpectedly"));
            if !auto_reconnect(&state) {
                give_up(&state);
                return;
            }
            set_state(&state, LinkState::Reconnecting);
            match restart(&state, !xray_ok, !tun_ok) {
                Ok(()) => {
                    log(&state, format!("[app] {part} restarted"));
                    backoff = Duration::from_secs(1);
                    next_check = Instant::now() + Duration::from_secs(2);
                    need_exit_info = true;
                }
                Err(e) => {
                    log(&state, format!("[app] Restart failed, retrying in {}s: {e}", backoff.as_secs()));
                    drop(_guard);
                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
            continue;
        }

        // 2. Traffic counters (a quick localhost request, so done every second).
        let Some(metrics_port) = state.link.lock().unwrap().as_ref().map(|l| l.metrics_port) else { return };
        match probe::xray_traffic(metrics_port) {
            Some(raw) => {
                let traffic = meter.sample(raw, Instant::now());
                if let Some(link) = state.link.lock().unwrap().as_mut() {
                    link.session.traffic = traffic;
                }
            }
            None if !traffic_warned => {
                traffic_warned = true;
                log(&state, format!("[app] Traffic counters unavailable on 127.0.0.1:{metrics_port}"));
            }
            None => {}
        }

        // 3. Does traffic actually get through? (Probing can take seconds, so no locks held.)
        if Instant::now() < next_check {
            continue;
        }
        let Some((via, url)) = state.link.lock().unwrap().as_ref().map(|l| (l.probe_via(), l.test_url.clone())) else {
            return;
        };
        let ms = probe::check(&url, &via);
        let exit = if ms.is_some() && need_exit_info { probe::exit_info(&via) } else { None };
        if !current() {
            return;
        }

        let healthy = ms.is_some();
        {
            let mut link = state.link.lock().unwrap();
            let Some(link) = link.as_mut() else { return };
            link.session.health = Some(Health { ok: healthy, ms, checked_at: now_ms() });
            if healthy {
                link.session.state = LinkState::Connected;
                if exit.is_some() {
                    link.session.exit = exit;
                    need_exit_info = false;
                }
            }
        }

        if healthy {
            failures = 0;
            next_check = Instant::now() + HEALTHY_INTERVAL;
            continue;
        }
        failures += 1;
        next_check = Instant::now() + UNHEALTHY_INTERVAL;
        if failures == 1 {
            log(&state, "[app] Health check failed");
        }
        if failures >= MAX_FAILURES && auto_reconnect(&state) {
            // The server or network hiccuped: a fresh xray drops stale connections.
            let Ok(_guard) = state.switching.try_lock() else { continue };
            if !current() {
                return;
            }
            set_state(&state, LinkState::Reconnecting);
            log(&state, format!("[app] No traffic for {failures} checks, restarting Xray"));
            match restart(&state, true, false) {
                Ok(()) => need_exit_info = true,
                Err(e) => log(&state, format!("[app] Restart failed: {e}")),
            }
            failures = 0;
        }
    }
}

/// Restarts the failed parts of the current connection in place (same ports and credentials).
fn restart(state: &AppState, xray: bool, tun: bool) -> Result<(), String> {
    let (xray_cfg, tun_cfg, socks_port) = {
        let link = state.link.lock().unwrap();
        let link = link.as_ref().ok_or("Not connected.")?;
        (link.xray_cfg.clone(), link.tun_cfg.clone(), link.session.socks_port)
    };
    let mut core = state.core.lock().unwrap();
    if xray {
        core.start_xray(&state.paths.xray(), &state.paths.core, &xray_cfg, socks_port)?;
    }
    if let (true, Some(cfg)) = (tun, &tun_cfg) {
        core.start_tun(&state.paths.sing_box(), &state.paths.data.join("sing-box"), cfg)?;
    }
    drop(core);
    if let Some(link) = state.link.lock().unwrap().as_mut() {
        link.session.reconnects += 1;
    }
    Ok(())
}

/// Auto-reconnect is off and a core died: stop, but keep blocking if the kill switch is on.
fn give_up(state: &AppState) {
    teardown(state);
    if firewall::is_active() {
        state.blocked.store(true, Ordering::SeqCst);
        log(state, "[app] Disconnected. The kill switch keeps blocking the internet until you reconnect or disconnect.");
    } else {
        log(state, "[app] Disconnected");
    }
}

fn auto_reconnect(state: &AppState) -> bool {
    state.store.lock().unwrap().settings.auto_reconnect
}

fn set_state(state: &AppState, link_state: LinkState) {
    if let Some(link) = state.link.lock().unwrap().as_mut() {
        link.session.state = link_state;
    }
}

fn firewall_rules(state: &AppState, settings: &Settings) -> firewall::Rules {
    let mut apps = vec![state.paths.xray()];
    if state.paths.sing_box().exists() {
        apps.push(state.paths.sing_box());
    }
    firewall::Rules { apps, allow_lan: settings.bypass_lan }
}

/// Resolves the server, falling back to the last known address when DNS isn't reachable
/// (for example while the kill switch is blocking the open network).
fn resolve_server(state: &AppState, address: &str, port: u16) -> Result<IpAddr, String> {
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(ip);
    }
    let lookup = (address, port).to_socket_addrs().map(|addrs| {
        let addrs: Vec<SocketAddr> = addrs.collect();
        addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).map(|a| a.ip())
    });
    let mut cache = state.resolved.lock().unwrap();
    match lookup {
        Ok(Some(ip)) => {
            cache.insert(address.to_string(), ip);
            Ok(ip)
        }
        _ => cache.get(address).copied().ok_or_else(|| format!("Cannot resolve server {address}")),
    }
}

/// Points the profile at `ip` while keeping its domain for TLS SNI and the HTTP Host header,
/// so the server sees exactly the same handshake as before.
pub fn pin_address(p: &Profile, ip: IpAddr) -> Profile {
    let mut p = p.clone();
    if p.address.parse::<IpAddr>().is_ok() {
        return p;
    }
    let domain = std::mem::replace(&mut p.address, ip.to_string());
    let s = &mut p.stream;
    if s.security == "tls" && s.sni.is_empty() {
        s.sni = domain.clone();
    }
    if matches!(s.network.as_str(), "ws" | "httpupgrade" | "xhttp") && s.host.is_empty() {
        s.host = domain;
    }
    p
}

pub fn log(state: &AppState, line: impl Into<String>) {
    state.logs.lock().unwrap().push_back(line.into());
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn ensure_free(port: u16) -> Result<(), String> {
    TcpListener::bind(("127.0.0.1", port))
        .map(drop)
        .map_err(|_| format!("Port {port} is already in use. Pick another port in Settings."))
}

fn random_port() -> Result<u16, String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())
}

/// Two distinct random localhost ports, so local apps can't rely on a fixed, well-known port.
fn random_ports() -> Result<(u16, u16), String> {
    let a = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let b = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = |l: &TcpListener| l.local_addr().map(|a| a.port()).map_err(|e| e.to_string());
    Ok((port(&a)?, port(&b)?))
}

fn random_string(len: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_link;

    #[test]
    fn traffic_survives_counter_resets() {
        let mut m = TrafficMeter::default();
        let t0 = Instant::now();
        m.sample((0, 0), t0);
        let t = m.sample((1000, 4000), t0 + Duration::from_secs(2));
        assert_eq!((t.up_speed, t.down_speed, t.down_total), (500, 2000, 4000));
        // xray restarted: its counters start over, totals keep growing.
        let t = m.sample((100, 200), t0 + Duration::from_secs(3));
        assert_eq!((t.up_total, t.down_total), (1100, 4200));
    }

    #[test]
    fn pinning_keeps_the_domain_for_tls_and_host() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let p = pin_address(&parse_link("vless://id@cdn.example.com:443?type=ws&security=tls").unwrap(), ip);
        assert_eq!(p.address, "203.0.113.7");
        assert_eq!(p.stream.sni, "cdn.example.com");
        assert_eq!(p.stream.host, "cdn.example.com");

        // Explicit SNI/host win; IP addresses are left alone.
        let p = pin_address(&parse_link("vless://id@a.com:443?type=ws&security=tls&sni=s.com&host=h.com").unwrap(), ip);
        assert_eq!((p.stream.sni.as_str(), p.stream.host.as_str()), ("s.com", "h.com"));
        let p = pin_address(&parse_link("trojan://pw@198.51.100.1:443").unwrap(), ip);
        assert_eq!(p.address, "198.51.100.1");
    }
}
