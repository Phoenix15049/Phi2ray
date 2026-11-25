//! Connecting, disconnecting, and the supervisor that keeps a connection alive.
//!
//! Leak protection rules:
//! - When something fails while connected, the tunnel (or system proxy) stays in place and
//!   dependent routes are withdrawn before the connection is rebuilt.
//! - With the kill switch on, the firewall stays up through every restart, and even after
//!   giving up, until the user disconnects.

use std::net::{IpAddr, TcpListener, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::Serialize;
use serde_json::Value;
use tauri::{AppHandle, Manager};

use crate::parser::{wireguard, Profile, Protocol};
use crate::probe::{self, ExitInfo, LocalProxy};
use crate::store::{Mode, Settings};
use crate::xray::{SING_BOX_EXE, XRAY_EXE};
use crate::{config, firewall, platform, proxy, tun, AppState};

/// Returned by `connect` when the chosen options need an elevated process.
pub const ADMIN_REQUIRED: &str = "ADMIN_REQUIRED";

const HEALTHY_INTERVAL: Duration = Duration::from_secs(15);
const UNHEALTHY_INTERVAL: Duration = Duration::from_secs(5);
/// Failed checks in a row before xray is restarted. When restarts don't help (the server
/// itself is down), each further one waits twice as long, up to `MAX_FAILURES << 3` checks:
/// every restart drops all open connections, so restarting every 15 seconds only hurts.
const MAX_FAILURES: u32 = 3;
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// A remembered server address is only used as a fallback for this long.
const RESOLVED_MAX_AGE_SECS: u64 = 30 * 86_400;
/// When encrypted DNS fails, an address confirmed this recently is used before asking the
/// network's DNS, which would see the server's name.
const RESOLVED_RECENT_SECS: u64 = 7 * 86_400;

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
    /// Never sent with the status the window polls; only on request (copying the SOCKS link).
    #[serde(skip_serializing)]
    pub socks_user: String,
    #[serde(skip_serializing)]
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
    profile: Profile,
    settings: Settings,
    test_url: String,
    metrics_port: u16,
    local_ports: Vec<u16>,
    /// xray's probe inbound, which always goes to the server.
    probe_proxy: LocalProxy,
    /// The server as configured, and the IP xray dials when it was looked up beforehand.
    server_address: String,
    server_port: u16,
    server_ip: Option<IpAddr>,
}

/// Phi2ray's own way through the server, for subscription downloads and DNS tests.
pub fn internal_proxy(state: &AppState) -> Option<LocalProxy> {
    let (proxy, ports) = {
        let link = state.link.lock().unwrap();
        let link = link.as_ref().filter(|l| l.session.state == LinkState::Connected)?;
        (link.probe_proxy.clone(), link.local_ports.clone())
    };
    state.core.lock().unwrap().xray_ready(&ports).then_some(proxy)
}

/// What the connection info lookup needs: a way through the server, and the server's IP.
pub struct InfoTarget {
    pub via: LocalProxy,
    pub server_address: String,
    pub server_ip: Option<IpAddr>,
}

/// Always goes through xray's probe inbound, so the answer is what the server's side sees
/// in every mode, split tunnel included. Resolving the server here uses the same DNS that
/// xray itself used to reach it.
pub fn info_target(state: &AppState) -> Result<InfoTarget, String> {
    let via = internal_proxy(state).ok_or("The connection is not ready.")?;
    let (address, port, ip) = {
        let link = state.link.lock().unwrap();
        let link = link.as_ref().filter(|l| l.session.state == LinkState::Connected).ok_or("Not connected.")?;
        if link.probe_proxy.port != via.port { return Err("The connection changed. Try again.".into()); }
        (link.server_address.clone(), link.server_port, link.server_ip)
    };
    let ip = ip.or_else(|| resolve_server(state, &address, port).ok());
    Ok(InfoTarget { via, server_address: address, server_ip: ip })
}

pub fn connect(app: &AppHandle, state: &AppState, id: &str) -> Result<Session, String> {
    let _guard = state.switching.lock().unwrap();
    let result = connect_locked(app,state,id);
    if let Err(e) = &result {
        if state.store.lock().unwrap().settings.absolute_mode {
            crate::absolute::phase(state,"error",Some(e.clone()));
            state.blocked.store(firewall::is_active(),Ordering::SeqCst);
        }
    }
    result
}

fn connect_locked(app: &AppHandle, state: &AppState, id: &str) -> Result<Session,String> {
    let (mut profile, settings) = {
        let mut store = state.store.lock().unwrap();
        let profile = store.profiles.iter().find(|p| p.id == id).cloned().ok_or("Server not found.")?;
        store.settings.selected = Some(id.to_string());
        store.save(&state.paths.store)?;
        (profile, crate::absolute::effective(&store.settings))
    };

    let xray_exe = state.paths.xray();
    if !settings.absolute_mode && (crate::absolute::marker(state).exists() || state.absolute.lock().unwrap().phase == "error") {
        return Err("Restore the previous Absolute settings before connecting. See Settings → Protection.".into());
    }
    if settings.absolute_mode { crate::absolute::validate_profile(&profile)?; }
    if !settings.absolute_mode && profile.insecure().is_some() {
        log(state, "[app] This profile has an unencrypted or unverified transport.");
    }
    if profile.protocol == Protocol::Wireguard && settings.mode == Mode::Tun &&
        !settings.ipv6 && !wireguard::permits_ipv4(&profile)
    {
        return Err("This WireGuard profile requires IPv6. Enable IPv6 in VPN settings.".into());
    }
    if !xray_exe.exists() {
        return Err(format!("Xray core not found. Put {XRAY_EXE} in {}", state.paths.core.display()));
    }
    if settings.mode == Mode::Tun && !state.paths.sing_box().exists() {
        return Err(format!(
            "VPN mode needs {SING_BOX_EXE} in {}. Or switch to System proxy mode.",
            state.paths.core.display()
        ));
    }
    if settings.mode == Mode::Tun || settings.kill_switch {
        platform::elevate()?;
    }
    if settings.absolute_mode {
        absolute_barrier(state, &settings, false)?;
        teardown(state);
        state.blocked.store(true, Ordering::SeqCst);
    }

    // Look the server up while any previous connection is still up: in VPN mode and with the
    // kill switch, the open network isn't usable once the new connection starts.
    let pin = settings.mode == Mode::Tun || settings.kill_switch || profile.protocol == Protocol::Wireguard;
    let server_ip = if pin { Some(resolve_server(state, &profile.address, profile.port)?) } else { None };
    if pin { profile.pin_downloads(|address, port| resolve_server(state, address, port))?; }
    let original_address = profile.address.clone();
    let profile = match server_ip {
        Some(ip) => pin_address(&profile, ip),
        None => profile,
    };

    // Whether the kill switch was already protecting the user (connected, or holding the
    // internet blocked). A failed switch to another server must not drop that protection.
    let was_protected = firewall::is_active();
    if settings.kill_switch {
        firewall::enable(&firewall_rules(state, &settings))?;
        log(state, "[app] Kill switch on");
    } else if firewall::is_active() {
        firewall::disable()?;
        log(state, "[app] Kill switch off");
    }
    state.blocked.store(false, Ordering::SeqCst);

    // Stop the previous connection (its supervisor exits when the generation changes).
    state.generation.fetch_add(1, Ordering::SeqCst);
    restore_proxy(state);
    state.core.lock().unwrap().stop();
    *state.link.lock().unwrap() = None;

    let mut result = start(state, &profile, &settings, &original_address, server_ip);
    if let Err(e) = &result {
        // Random ports: someone grabbed one in the moment before xray did. New ports, once.
        if e.starts_with(crate::xray::PORT_TAKEN) && !settings.fixed_ports {
            log(state, format!("[app] {e} Retrying with new ports."));
            state.core.lock().unwrap().stop();
            result = start(state, &profile, &settings, &original_address, server_ip);
        }
    }
    match result {
        Ok(link) => {
            let session = link.session.clone();
            *state.link.lock().unwrap() = Some(link);
            let generation = state.generation.load(Ordering::SeqCst);
            let app = app.clone();
            thread::spawn(move || supervise(app, generation));
            Ok(session)
        }
        Err(e) => {
            state.core.lock().unwrap().stop();
            restore_proxy(state);
            log(state, format!("[app] Connect failed: {e}"));
            if settings.absolute_mode || (settings.kill_switch && was_protected) {
                // The previous connection is already gone: keep blocking until the user
                // reconnects or chooses to unblock.
                state.blocked.store(true, Ordering::SeqCst);
                log(state, "[app] The kill switch keeps blocking the internet until you reconnect or disconnect.");
                if settings.absolute_mode { crate::absolute::phase(state, "error", Some(e.clone())); }
            } else {
                // A failed connect from idle leaves the network as it was before.
                if let Err(error) = firewall::disable() {
                    state.blocked.store(true, Ordering::SeqCst);
                    log(state, format!("[app] Could not release the kill switch: {error}"));
                }
            }
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
            xray_exe: &state.paths.xray(),
            core_uid: platform::core_uid(),
            local_dns: platform::system_dns(),
            settings,
        })?),
        _ => None,
    };

    log(state, format!("[app] Connecting to {} ({:?} mode)", profile.name, settings.mode));
    // VPN mode has no HTTP inbound: nothing needs it, and it would be a password-less way in.
    let mut local_ports = vec![socks_port, probe_port, metrics_port];
    if settings.mode != Mode::Tun {
        local_ports.push(http_port);
    }
    let proxy = LocalProxy { port: probe_port, user: probe_user, pass: probe_pass };
    start_parts(state, settings, &xray_cfg, tun_cfg.as_ref(), &local_ports, &proxy)?;
    Ok(Link {
        session,
        profile: profile.clone(),
        settings: settings.clone(),
        test_url: settings.test_url.clone(),
        metrics_port,
        local_ports,
        probe_proxy: proxy,
        server_address: original_address.to_string(),
        server_port: profile.port,
        server_ip,
    })
}

pub(crate) fn gated_config(config: &Value) -> Value {
    let mut cfg = config.clone();
    cfg["routing"]["rules"].as_array_mut().unwrap().insert(2, serde_json::json!({
        "type":"field", "inboundTag":["socks","http"], "outboundTag":"block"
    }));
    cfg
}

#[derive(Clone,Copy,Debug,PartialEq)]
enum AbsoluteStep { Barrier, Stop, ProbeOnly, Timezone, UserProxy, Tunnel, Activate }

fn absolute_steps(mut step: impl FnMut(AbsoluteStep) -> Result<(),String>) -> Result<(),String> {
    use AbsoluteStep::*;
    for action in [Barrier, Stop, ProbeOnly, Timezone, UserProxy, Tunnel, Activate] { step(action)?; }
    Ok(())
}

fn start_parts(state: &AppState, settings: &Settings, xray_cfg: &Value, tun_cfg: Option<&Value>, local_ports: &[u16], proxy: &LocalProxy) -> Result<(), String> {
    if settings.absolute_mode {
        return absolute_steps(|step| {
            match step {
                AbsoluteStep::Barrier => absolute_barrier(state, settings, false)?,
                AbsoluteStep::Stop => state.core.lock().unwrap().stop(),
                AbsoluteStep::ProbeOnly => {
                    crate::absolute::arm(state, settings)?;
                    crate::absolute::phase(state,"preparing",None);
                    state.core.lock().unwrap().start_xray(&state.paths.xray(),&state.paths.core,&gated_config(xray_cfg),local_ports)?;
                }
                AbsoluteStep::Timezone => {
                    check_startup(settings, proxy)?;
                    crate::absolute::prepare(state, proxy, settings)?;
                }
                AbsoluteStep::UserProxy => state.core.lock().unwrap().start_xray(&state.paths.xray(),&state.paths.core,xray_cfg,local_ports)?,
                AbsoluteStep::Tunnel => state.core.lock().unwrap().start_tun(&state.paths.sing_box(),&state.paths.work,tun_cfg.ok_or("Absolute needs a VPN adapter config")?)?,
                AbsoluteStep::Activate => {
                    crate::absolute::verify_location(state, settings)?;
                    absolute_barrier(state, settings, true)?;
                    crate::absolute::phase(state, "active", None);
                }
            }
            Ok(())
        });
    }
    let mut core = state.core.lock().unwrap();
    core.start_xray(&state.paths.xray(), &state.paths.core, xray_cfg, local_ports)?;
    check_startup(settings, proxy)?;
    match (tun_cfg, settings.mode) {
        (Some(cfg), _) => core.start_tun(&state.paths.sing_box(), &state.paths.work, cfg)?,
        (None, Mode::System) => {
            let port = xray_cfg["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == "http").and_then(|i| i["port"].as_u64()).ok_or("HTTP inbound missing")? as u16;
            proxy::enable(port, &state.paths.proxy_marker)?;
        }
        _ => {}
    }
    drop(core);
    Ok(())
}

fn check_startup(settings: &Settings, proxy: &LocalProxy) -> Result<(), String> {
    if let Some(seconds) = settings.connect_timeout {
        tauri::async_runtime::block_on(probe::wait_for_server(
            &settings.test_url, proxy, Duration::from_secs(seconds.into()),
        ))?;
    }
    Ok(())
}

/// Manual disconnect: everything back to how it was, kill switch included.
pub fn disconnect(state: &AppState) {
    let _guard = state.switching.lock().unwrap();
    let settings = state.store.lock().unwrap().settings.clone();
    if settings.absolute_mode {
        let barrier = absolute_barrier(state, &settings, false);
        teardown(state);
        match barrier {
            Ok(()) => crate::absolute::phase(state, "armed", None),
            Err(e) => {
                log(state, format!("[absolute] {e}"));
                crate::absolute::phase(state, "error", Some(e));
            }
        }
    } else {
        teardown(state);
        if crate::absolute::marker(state).exists() {
            if let Err(e) = absolute_barrier(state,&settings,false)
                .and_then(|_| crate::absolute::restore_owned(state)) {
                crate::absolute::phase(state,"error",Some(e.clone()));
                log(state,format!("[absolute] {e}"));
                state.blocked.store(firewall::is_active(),Ordering::SeqCst);
                return;
            }
        }
        match firewall::disable() {
            Ok(()) => crate::absolute::phase(state, "off", None),
            Err(e) => {
                log(state, format!("[app] Could not release the kill switch: {e}"));
                if state.absolute.lock().unwrap().phase != "off" {
                    crate::absolute::phase(state, "error", Some(e));
                }
            }
        }
    }
    state.blocked.store(firewall::is_active(), Ordering::SeqCst);
}

pub fn shutdown(state: &AppState) -> Result<(), String> {
    let _guard = state.switching.lock().unwrap();
    if state.link.lock().unwrap().is_none() && !firewall::is_active() && !crate::absolute::marker(state).exists() { return Ok(()); }
    let settings = state.store.lock().unwrap().settings.clone();
    if settings.absolute_mode { absolute_barrier(state, &settings, false)?; }
    teardown(state);
    if let Err(e) = crate::absolute::restore_owned(state) {
        crate::absolute::phase(state, "error", Some(e.clone()));
        state.blocked.store(firewall::is_active(),Ordering::SeqCst);
        return Err(e);
    }
    if let Err(e) = firewall::disable() {
        state.blocked.store(firewall::is_active(), Ordering::SeqCst);
        return Err(e);
    }
    crate::absolute::phase(state,"off",None);
    state.blocked.store(firewall::is_active(),Ordering::SeqCst);
    Ok(())
}

/// Stops the connection but leaves the kill switch alone.
pub(crate) fn teardown(state: &AppState) {
    state.generation.fetch_add(1, Ordering::SeqCst);
    restore_proxy(state);
    state.core.lock().unwrap().stop();
    *state.link.lock().unwrap() = None;
}

/// Applies a kill switch change right away. The settings caller holds `state.switching`.
pub fn apply_kill_switch(state: &AppState, settings: &Settings) -> Result<(), String> {
    let connected = state.link.lock().unwrap().is_some();
    if settings.kill_switch && connected && !firewall::verified() {
        platform::elevate().map_err(|e| {
            if e == ADMIN_REQUIRED {
                "The kill switch needs administrator rights. Restart Phi2ray as administrator.".to_string()
            } else {
                e
            }
        })?;
        firewall::enable(&firewall_rules(state, settings))?;
        log(state, "[app] Kill switch on");
        // Only the cores' account gets past the kill switch, so an xray running as the user moves
        // there, using fresh private endpoints.
        #[cfg(not(windows))]
        if state.core.lock().unwrap().xray_is_local() {
            restart(state)?;
        }
    } else if !settings.kill_switch && firewall::is_active() {
        firewall::disable()?;
        state.blocked.store(false, Ordering::SeqCst);
        log(state, "[app] Kill switch off");
    }
    if let Some(link) = state.link.lock().unwrap().as_mut() {
        link.session.kill_switch = firewall::verified();
    }
    Ok(())
}

/// Runs a health check now and records the result.
pub fn check_now(state: &AppState) -> Result<Health, String> {
    let via = internal_proxy(state).ok_or("The connection is not ready.")?;
    let (url, started_at) = {
        let link = state.link.lock().unwrap();
        let link = link.as_ref().filter(|l| l.session.state == LinkState::Connected).ok_or("Not connected.")?;
        if link.probe_proxy.port != via.port { return Err("The connection changed. Try again.".into()); }
        (link.test_url.clone(), link.session.started_at)
    };
    let ms = probe::check(&url, &via);
    let health = Health { ok: ms.is_some(), ms, checked_at: now_ms() };
    let exit = ms.and_then(|_| probe::exit_info(&via));
    if let Some(link) = state.link.lock().unwrap().as_mut()
        .filter(|link| link.session.started_at == started_at && link.probe_proxy.port == via.port) {
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
    let mut next_absolute_check = Instant::now() + Duration::from_secs(60);
    let mut next_firewall_check = Instant::now();
    // Restarts in a row that didn't bring traffic back.
    let mut fruitless_restarts = 0u32;

    loop {
        thread::sleep(Duration::from_secs(1));
        let state = app.state::<AppState>();
        let current = || state.generation.load(Ordering::SeqCst) == generation;
        if !current() {
            return;
        }

        if Instant::now() >= next_firewall_check {
            let Ok(_guard) = state.switching.try_lock() else { continue };
            if !current() { return; }
            next_firewall_check = Instant::now() + Duration::from_secs(5);
            let protected = state.link.lock().unwrap().as_ref().is_some_and(|l| l.session.kill_switch);
            if protected {
                if let Err(error) = firewall::verify() {
                    log(&state, format!("[app] Kill switch could not be verified: {error}"));
                    set_state(&state, LinkState::Reconnecting);
                    if let Err(error) = restart(&state) {
                        log(&state, format!("[app] Could not restore the protected connection: {error}"));
                    }
                    need_exit_info = true;
                    continue;
                }
            }
        }

        // 1. Are both cores still running and do local listeners still belong to Xray?
        let Some((ports, mode)) = state.link.lock().unwrap().as_ref()
            .map(|link| (link.local_ports.clone(), link.session.mode)) else { return; };
        let (xray_ok, tun_ok) = {
            let mut core = state.core.lock().unwrap();
            (core.xray_ready(&ports), mode != Mode::Tun || core.tun_alive() == Some(true))
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
            match restart(&state) {
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
        if state.store.lock().unwrap().settings.absolute_mode && Instant::now() >= next_absolute_check {
            let settings = state.store.lock().unwrap().settings.clone();
            let proxy = state.link.lock().unwrap().as_ref().filter(|l| l.session.state == LinkState::Connected).map(|l| l.probe_proxy.clone());
            if let Some(proxy) = proxy {
                let verification = crate::absolute::verify(&state, &proxy, &settings);
                let Ok(_guard) = state.switching.try_lock() else { continue };
                if !current() { return; }
                match verification {
                    Ok(ip) => state.absolute.lock().unwrap().exit_ip = Some(ip),
                    Err(e) => {
                        log(&state, format!("[absolute] {e}"));
                        set_state(&state, LinkState::Reconnecting);
                        if let Err(e) = restart(&state) { log(&state, format!("[absolute] Revalidation failed: {e}")); }
                    }
                }
            }
            next_absolute_check = Instant::now() + Duration::from_secs(60);
        }
        if Instant::now() < next_check {
            continue;
        }
        let Some((via, url)) = state.link.lock().unwrap().as_ref().map(|l| (l.probe_proxy.clone(), l.test_url.clone())) else {
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
            if fruitless_restarts > 0 {
                log(&state, "[app] Traffic is getting through again");
            }
            failures = 0;
            fruitless_restarts = 0;
            next_check = Instant::now() + HEALTHY_INTERVAL;
            continue;
        }
        failures += 1;
        next_check = Instant::now() + UNHEALTHY_INTERVAL;
        if failures == 1 {
            log(&state, "[app] Health check failed");
        }
        if failures >= MAX_FAILURES << fruitless_restarts.min(3) && auto_reconnect(&state) {
            // The server or network hiccuped: a fresh xray drops stale connections.
            let Ok(_guard) = state.switching.try_lock() else { continue };
            if !current() {
                return;
            }
            set_state(&state, LinkState::Reconnecting);
            if fruitless_restarts == 0 {
                log(&state, format!("[app] No traffic for {failures} checks, restarting Xray"));
            } else {
                log(&state, format!("[app] Still no traffic: the server may be down or blocked. Restarting Xray again ({})", fruitless_restarts + 1));
            }
            match restart(&state) {
                Ok(()) => need_exit_info = true,
                Err(e) => log(&state, format!("[app] Restart failed: {e}")),
            }
            failures = 0;
            fruitless_restarts += 1;
        }
    }
}

/// Withdraw dependent routes before replacing Xray and rotate private endpoints on recovery.
fn restart(state: &AppState) -> Result<(), String> {
    let (profile, mut settings, address, ip, reconnects) = {
        let link = state.link.lock().unwrap();
        let link = link.as_ref().ok_or("Not connected.")?;
        (link.profile.clone(), link.settings.clone(), link.server_address.clone(), link.server_ip, link.session.reconnects)
    };
    {
        let store = state.store.lock().unwrap();
        settings.kill_switch = settings.absolute_mode || store.settings.kill_switch;
        settings.connect_timeout = store.settings.connect_timeout;
    }
    let barrier = if settings.absolute_mode { absolute_barrier(state, &settings, false) } else { Ok(()) };
    restore_proxy(state);
    state.core.lock().unwrap().stop();
    let result = (|| {
        barrier?;
        if settings.mode == Mode::Tun || settings.kill_switch { platform::elevate()?; }
        if settings.kill_switch && !settings.absolute_mode { firewall::enable(&firewall_rules(state, &settings))?; }
        start(state, &profile, &settings, &address, ip)
    })();
    match result {
        Ok(mut link) => {
            link.session.reconnects = reconnects.saturating_add(1);
            *state.link.lock().unwrap() = Some(link);
            Ok(())
        }
        Err(e) => {
            state.core.lock().unwrap().stop();
            restore_proxy(state);
            if settings.absolute_mode {
                let _ = absolute_barrier(state, &settings, false);
                crate::absolute::phase(state, "error", Some(e.clone()));
            }
            Err(e)
        }
    }
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
    let s = &state.store.lock().unwrap().settings;
    s.absolute_mode || s.auto_reconnect
}

fn set_state(state: &AppState, link_state: LinkState) {
    if let Some(link) = state.link.lock().unwrap().as_mut() {
        link.session.state = link_state;
    }
}

fn firewall_rules(state: &AppState, settings: &Settings) -> firewall::Rules {
    let mut apps = vec![state.paths.xray()];
    if !settings.absolute_mode && state.paths.sing_box().exists() {
        apps.push(state.paths.sing_box());
    }
    firewall::Rules { apps, allow_lan: settings.bypass_lan, strict: settings.absolute_mode,
        tun_luid: None, bootstrap_app: settings.absolute_mode.then(|| std::env::current_exe().ok()).flatten() }
}

pub(crate) fn absolute_barrier(state: &AppState, settings: &Settings, ready: bool) -> Result<(), String> {
    if !cfg!(windows) { return Err("Absolute mode is currently supported on Windows only.".into()); }
    let mut requested = settings.clone();
    requested.absolute_mode = true;
    let settings = crate::absolute::effective(&requested);
    let mut rules = firewall_rules(state, &settings);
    if ready { rules.tun_luid = Some(firewall::tun_luid()?); }
    firewall::enable(&rules)
}

/// Resolves the server, falling back to the last known address when DNS isn't reachable
/// (for example while the kill switch is blocking the open network).
pub(crate) fn resolve_server(state: &AppState, address: &str, port: u16) -> Result<IpAddr, String> {
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(ip);
    }
    // A filtered domain can come back as a private or reserved address (Iranian DNS answers
    // 10.10.34.36, for example). That's never the real server, so it's neither used nor kept.
    let public = |ips: Vec<IpAddr>| -> Vec<IpAddr> { ips.into_iter().filter(|ip| crate::netinfo::is_public(*ip)).collect() };
    // Encrypted DNS first (through the current connection when there is one), so the network's
    // own DNS neither sees the server's name nor gets to answer it.
    let doh = tauri::async_runtime::block_on(crate::dns::resolve_bootstrap(address, internal_proxy(state).as_ref()));
    let strict = state.store.lock().unwrap().settings.absolute_mode;
    let mut answered = !doh.is_empty();
    let mut found = public(doh);
    let now = now_ms() / 1000;
    if found.is_empty() {
        // Then a recently resolved DNS address, still without telling the network
        // which server this is. Only after that, the network's own DNS.
        let recent = {
            let store = state.store.lock().unwrap();
            store
                .resolved
                .get(address)
                .copied()
                .filter(|ip| !strict && crate::netinfo::is_public(*ip) && store.resolved_at.get(address).is_some_and(|&t| now.saturating_sub(t) <= RESOLVED_RECENT_SECS))
        };
        if let Some(ip) = recent {
            log(state, "[app] Encrypted DNS didn't answer; using the server's recently resolved address (not yet authenticated)");
            return Ok(ip);
        }
        let system: Vec<IpAddr> = if strict { vec![] } else { (address, port).to_socket_addrs().map(|a| a.map(|a| a.ip()).collect()).unwrap_or_default() };
        answered |= !system.is_empty();
        found = public(system);
    }
    let mut store = state.store.lock().unwrap();
    match found.iter().find(|ip| ip.is_ipv4()).or(found.first()) {
        Some(&ip) => {
            let stale = store.resolved_at.get(address).is_none_or(|&t| now.saturating_sub(t) > 86_400);
            if store.resolved.get(address) != Some(&ip) || stale {
                store.resolved.insert(address.to_string(), ip);
                store.resolved_at.insert(address.to_string(), now);
                let _ = store.save(&state.paths.store);
            }
            Ok(ip)
        }
        // Last resort: the previous DNS answer, unless it's too old to trust (servers move).
        None => store
            .resolved
            .get(address)
            .copied()
            .filter(|ip| !strict && crate::netinfo::is_public(*ip) && store.resolved_at.get(address).is_some_and(|&t| now.saturating_sub(t) <= RESOLVED_MAX_AGE_SECS))
            .ok_or_else(|| {
                if answered {
                    format!("DNS gave a fake address for {address} (it's probably filtered). Try another DNS or connect once on a network where it works.")
                } else {
                    format!("Cannot resolve server {address}")
                }
            }),
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
        // Same choice as config::stream makes unpinned: the Host header first, then the address.
        s.sni = if p.outbound_settings.is_some() || s.host.is_empty() { domain.clone() } else { s.host.clone() };
    }
    if matches!(s.network.as_str(), "ws" | "httpupgrade" | "xhttp") && s.host.is_empty() {
        // XHTTP uses SNI as the HTTP host when no explicit host was supplied.
        s.host = if s.network == "xhttp" && matches!(s.security.as_str(), "tls" | "reality") && !s.sni.is_empty() {
            s.sni.clone()
        } else { domain };
    }
    p
}

/// Puts back the user's own proxy settings; a failure is logged, never silently dropped.
fn restore_proxy(state: &AppState) {
    if let Err(e) = proxy::restore(&state.paths.proxy_marker) {
        log(state, format!("[app] {e}"));
    }
}

pub fn log(state: &AppState, line: impl Into<String>) {
    crate::xray::push_log(&state.logs, line.into());
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

    #[test]
    fn absolute_never_opens_user_traffic_before_timezone_and_stops_on_failure() {
        use AbsoluteStep::*;
        for fail in [None,Some(Barrier),Some(Stop),Some(ProbeOnly),Some(Timezone),Some(UserProxy),Some(Tunnel),Some(Activate)] {
            let mut actions=vec![];
            let mut timezone_ready=false;
            let mut tunnel_ready=false;
            let result=absolute_steps(|step| {
                if matches!(step,UserProxy|Tunnel|Activate) { assert!(timezone_ready); }
                if step==Activate { assert!(tunnel_ready); }
                actions.push(step);
                if Some(step)==fail { return Err("simulated failure".into()); }
                if step==Timezone {timezone_ready=true;}
                if step==Tunnel {tunnel_ready=true;}
                Ok(())
            });
            assert_eq!(result.is_err(),fail.is_some());
            if let Some(fail)=fail {assert_eq!(actions.last(),Some(&fail));}
        }
    }

    #[test]
    fn absolute_probe_gate_precedes_every_user_route() {
        let profile=crate::parser::parse_link("trojan://password@example.invalid:443").unwrap();
        let settings=crate::absolute::effective(&Settings{absolute_mode:true,iran_direct:true,bypass_lan:true,..Settings::default()});
        let cfg=crate::config::build(&profile,&crate::config::tests::inbounds(),&settings,&crate::config::Assets{geoip:false,geosite:false});
        let gated=gated_config(&cfg);
        assert_eq!(gated["routing"]["rules"][0]["outboundTag"],"metrics");
        assert_eq!(gated["routing"]["rules"][1]["inboundTag"],serde_json::json!(["probe-in"]));
        assert_eq!(gated["routing"]["rules"][2]["outboundTag"],"block");
        assert_eq!(gated["routing"]["rules"][2]["inboundTag"],serde_json::json!(["socks","http"]));
        assert!(!cfg.to_string().contains("domain:ir"));
        assert!(cfg["inbounds"].as_array().unwrap().iter().all(|i| i["listen"]=="127.0.0.1"));
    }
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

        // A clean CDN address with a different Host: pinning must not change the SNI.
        let link = "vless://id@clean.com:443?type=ws&security=tls&host=worker.dev";
        let sni = |p: &Profile| {
            let inb = crate::config::tests::inbounds();
            crate::config::build(p, &inb, &Settings::default(), &crate::config::Assets { geoip: false, geosite: false })
                ["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"]
                .clone()
        };
        let plain = parse_link(link).unwrap();
        assert_eq!(sni(&plain), "worker.dev");
        assert_eq!(sni(&pin_address(&plain, ip)), sni(&plain));

        for security in ["tls", "reality"] {
            let p = parse_link(&format!("vless://id@origin.example:443?type=xhttp&security={security}&sni=cdn.example&pbk=key")).unwrap();
            let pinned = pin_address(&p, ip);
            assert_eq!(pinned.stream.host, "cdn.example");
            assert_eq!(pinned.stream.sni, "cdn.example");
        }
    }
}
