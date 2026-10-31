//! Console control: the `phi2ray` command-line tool talks to the running app over a named pipe
//! (see `ipc.rs` for the protocol), and the app runs its commands as if they came from the
//! window. Off by default; turned on in Settings.
//!
//! Turning it on (single-exe builds) also puts the tool in `Program Files\Phi2ray\bin` and that
//! folder on the user's PATH. Only administrators can write there, so nothing can swap the
//! `phi2ray` command for another program.
//!
//! Who can talk to the app (see `pipe::security`):
//! - Only this computer (remote clients are refused) and only the Windows account running
//!   Phi2ray, plus administrators and the system.
//! - Nobody else can create the pipe's other end: the tool checks the pipe belongs to an
//!   administrator before it sends anything, so a program posing as Phi2ray is noticed.
//! - Commands only do what the window can do. Nothing passes paths, configs or other raw input
//!   to the cores, and no reply carries a password or server credentials.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

use crate::connection::{self, LinkState, ADMIN_REQUIRED};
use crate::ipc::{
    AddView, Command, DelayView, GroupView, LogsView, Reply, Request, ServerView, StatusView, UpdateView, VERSION,
};
use crate::store::{Mode, Settings, Store, DEFAULT_GROUP};
use crate::{tray, AppState};

/// Applies the setting: starts or stops listening, and installs or removes the command.
pub fn apply(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let state = app.state::<AppState>();
    if enabled {
        listen(app)?;
        if let Some(bin) = bin_dir(&state) {
            if let Err(e) = install::add(&bin) {
                pipe::stop();
                return Err(format!("Console control couldn't be turned on: {e}"));
            }
        }
        connection::log(&state, "[app] Console control on");
    } else {
        // Off means off, even if tidying up fails: the app stops listening first.
        pipe::stop();
        if let Some(bin) = bin_dir(&state) {
            if let Err(e) = install::remove(&bin) {
                connection::log(&state, format!("[app] Console control: {e}"));
            }
        }
        connection::log(&state, "[app] Console control off");
    }
    Ok(())
}

/// At startup, when the setting is on: listen again, and refresh the tool (a new version of
/// Phi2ray brings a new tool) and the record of where the app is.
pub fn startup(app: &AppHandle) {
    let state = app.state::<AppState>();
    if !state.store.lock().unwrap().settings.console {
        return;
    }
    if let Err(e) = listen(app) {
        connection::log(&state, format!("[app] Console control: {e}"));
    }
    if let Some(bin) = bin_dir(&state) {
        if let Err(e) = install::add(&bin) {
            connection::log(&state, format!("[app] Console control: {e}"));
        }
    }
}

#[cfg(windows)]
fn listen(app: &AppHandle) -> Result<(), String> {
    let (a, b, c) = (app.clone(), app.clone(), app.clone());
    pipe::start(pipe::Hooks {
        handle: Box::new(move |request, send| handle(&a, request, send)),
        quit: Box::new(move || b.exit(0)),
        log: Box::new(move |line| connection::log(&c.state::<AppState>(), line)),
    })
}

#[cfg(not(windows))]
fn listen(_app: &AppHandle) -> Result<(), String> {
    Err("console control is only supported on Windows for now".into())
}

/// `Program Files\Phi2ray\bin`, next to the cores. Builds without embedded cores have no
/// administrator-only folder, so they don't install the command (the tool can still be run
/// from where it was built).
fn bin_dir(state: &AppState) -> Option<PathBuf> {
    crate::cores::EMBEDDED.then(|| state.paths.core.parent().map(|p| p.join("bin"))).flatten()
}

// ---------- Running commands ----------

/// Reads one request and answers it. `send` writes one reply line to the tool.
/// Returns true if the app should quit once the answer is delivered.
fn handle(app: &AppHandle, request: &[u8], send: &mut dyn FnMut(&Reply)) -> bool {
    let request: Request = match serde_json::from_slice(request) {
        Ok(r) => r,
        Err(_) => {
            send(&Reply::Failed { error: "Unrecognized request. Use the phi2ray command that came with this version.".into() });
            return false;
        }
    };
    if request.version != VERSION {
        send(&Reply::Failed {
            error: "This phi2ray command belongs to a different version of the app. Turn console control off and on again in Settings.".into(),
        });
        return false;
    }
    let quit = matches!(request.command, Command::Quit);
    let mut progress = |data: Value| send(&Reply::Progress { data });
    let reply = match run(app, request.command, &mut progress) {
        Ok(data) => Reply::Done { data },
        Err(e) if e == ADMIN_REQUIRED => Reply::Failed {
            error: "VPN mode and the kill switch need administrator rights. Restart Phi2ray as administrator.".into(),
        },
        Err(error) => Reply::Failed { error },
    };
    let ok = matches!(reply, Reply::Done { .. });
    send(&reply);
    quit && ok
}

fn run(app: &AppHandle, command: Command, progress: &mut dyn FnMut(Value)) -> Result<Value, String> {
    let state = app.state::<AppState>();
    let state = &*state;
    match command {
        Command::Status => to_value(status(app, state)),
        Command::Servers { group } => {
            let store = state.store.lock().unwrap();
            let group = group.map(|g| find_group(&store, &g)).transpose()?;
            let servers: Vec<ServerView> = server_views(&store)
                .into_iter()
                .filter(|s| group.as_ref().is_none_or(|g| store.profiles[s.number - 1].group_id == *g))
                .collect();
            to_value(servers)
        }
        Command::Groups => {
            let store = state.store.lock().unwrap();
            let groups: Vec<GroupView> = store
                .groups
                .iter()
                .enumerate()
                .map(|(i, g)| GroupView {
                    number: i + 1,
                    id: g.id.clone(),
                    name: g.name.clone(),
                    servers: store.profiles.iter().filter(|p| p.group_id == g.id).count(),
                    subscription: g.subscription.is_some(),
                    auto_update: g.subscription.as_ref().is_some_and(|s| s.auto_update),
                    updated_at: g.subscription.as_ref().and_then(|s| s.updated_at),
                    last_error: g.subscription.as_ref().and_then(|s| s.last_error.clone()),
                })
                .collect();
            to_value(groups)
        }
        Command::Connect { server } => {
            let id = {
                let store = state.store.lock().unwrap();
                match server {
                    Some(s) => find_server(&store, &s)?,
                    None => store.settings.selected.clone().ok_or("No server is selected. Name one: phi2ray connect <server>")?,
                }
            };
            connection::log(state, "[console] connect");
            let result = connection::connect(app, state, &id);
            changed(app);
            result?;
            to_value(status(app, state))
        }
        Command::Disconnect => {
            connection::log(state, "[console] disconnect");
            connection::disconnect(state);
            changed(app);
            to_value(status(app, state))
        }
        Command::Test { servers, group } => test(app, state, servers, group, progress),
        Command::Mode { mode } => {
            let Some(mode) = mode else { return Ok(json!(mode_name(state.store.lock().unwrap().settings.mode))) };
            let mode = match mode.to_ascii_lowercase().as_str() {
                "vpn" | "tun" => Mode::Tun,
                "proxy" | "system" => Mode::System,
                "manual" => Mode::Manual,
                _ => return Err(format!("Unknown mode \"{mode}\". Use vpn, proxy or manual.")),
            };
            connection::log(state, format!("[console] mode {}", mode_name(mode)));
            change_settings(app, state, |s| s.mode = mode)?;
            to_value(status(app, state))
        }
        Command::KillSwitch { on } => {
            let Some(on) = on else { return Ok(json!(state.store.lock().unwrap().settings.kill_switch)) };
            connection::log(state, format!("[console] kill switch {}", if on { "on" } else { "off" }));
            change_settings(app, state, |s| s.kill_switch = on)?;
            to_value(status(app, state))
        }
        Command::Add { text, group } => add(app, state, &text, group),
        Command::Update { group } => update(app, state, group, progress),
        Command::Logs { since, last } => {
            let (lines, next) = state.logs.lock().unwrap().since(since, last);
            to_value(LogsView { lines, next })
        }
        Command::Info => {
            let target = connection::info_target(state)?;
            to_value(tauri::async_runtime::block_on(crate::netinfo::lookup(target))?)
        }
        Command::Show => {
            tray::show_window(app);
            Ok(Value::Null)
        }
        Command::Quit => {
            connection::log(state, "[console] quit");
            connection::disconnect(state);
            Ok(Value::Null)
        }
    }
}

fn to_value(v: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

/// Tells the window to reload: what it shows changed behind its back.
fn changed(app: &AppHandle) {
    let _ = app.emit("groups-changed", ());
    let _ = app.emit("state-changed", ());
}

fn status(app: &AppHandle, state: &AppState) -> StatusView {
    let session = state.link.lock().unwrap().as_ref().map(|l| l.session.clone());
    let session = session.as_ref();
    let store = state.store.lock().unwrap();
    let server = session
        .and_then(|s| server_views(&store).into_iter().find(|v| v.id == s.profile_id))
        .or_else(|| server_views(&store).into_iter().find(|v| v.selected));
    StatusView {
        app_version: app.package_info().version.to_string(),
        state: match session.map(|s| s.state) {
            Some(LinkState::Connected) => "connected",
            Some(LinkState::Reconnecting) => "reconnecting",
            None => "disconnected",
        }
        .into(),
        server,
        mode: mode_name(session.map_or(store.settings.mode, |s| s.mode)).into(),
        kill_switch: crate::firewall::is_active() || store.settings.kill_switch,
        blocked: state.blocked.load(Ordering::SeqCst),
        healthy: session.and_then(|s| s.health.as_ref()).map(|h| h.ok),
        latency_ms: session.and_then(|s| s.health.as_ref()).and_then(|h| h.ms),
        exit_ip: session.and_then(|s| s.exit.as_ref()).map(|e| e.ip.clone()),
        exit_country: session.and_then(|s| s.exit.as_ref()).and_then(|e| e.country.clone()),
        connected_since: session.map(|s| s.started_at),
        reconnects: session.map_or(0, |s| s.reconnects),
        up_speed: session.map_or(0, |s| s.traffic.up_speed),
        down_speed: session.map_or(0, |s| s.traffic.down_speed),
        up_total: session.map_or(0, |s| s.traffic.up_total),
        down_total: session.map_or(0, |s| s.traffic.down_total),
        socks_port: session.map(|s| s.socks_port),
        http_port: session.filter(|s| s.mode != Mode::Tun).map(|s| s.http_port),
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Tun => "vpn",
        Mode::System => "proxy",
        Mode::Manual => "manual",
    }
}

/// Changes settings the way the window does. A connection keeps running on what it started
/// with, except the mode: like the window, a mode change reconnects right away.
fn change_settings(app: &AppHandle, state: &AppState, edit: impl FnOnce(&mut Settings)) -> Result<(), String> {
    let mut settings = state.store.lock().unwrap().settings.clone();
    let old_mode = settings.mode;
    edit(&mut settings);
    let new_mode = settings.mode;
    crate::save_settings(app, state, settings)?;
    changed(app);
    let reconnect = state.link.lock().unwrap().as_ref().filter(|_| new_mode != old_mode).map(|l| l.session.profile_id.clone());
    if let Some(id) = reconnect {
        let result = connection::connect(app, state, &id);
        changed(app);
        result?;
    }
    Ok(())
}

fn server_views(store: &Store) -> Vec<ServerView> {
    store
        .profiles
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let view = p.view();
            ServerView {
                number: i + 1,
                id: p.id.clone(),
                name: p.name.clone(),
                protocol: serde_json::to_value(&view.protocol).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
                address: p.address.clone(),
                port: p.port,
                transport: [view.stream.network, view.stream.security].into_iter().filter(|s| !s.is_empty() && s != "none").collect::<Vec<_>>().join("+"),
                group: store.group(&p.group_id).map(|g| g.name.clone()).unwrap_or_default(),
                selected: store.settings.selected.as_deref() == Some(&p.id),
                insecure: view.insecure.map(String::from),
            }
        })
        .collect()
}

/// A server by its number in the list, its id, its name, or a part of its name that only
/// one server has.
fn find_server(store: &Store, query: &str) -> Result<String, String> {
    let names: Vec<(&str, &str)> = store.profiles.iter().map(|p| (p.id.as_str(), p.name.as_str())).collect();
    find(&names, query, "server", "phi2ray servers")
}

fn find_group(store: &Store, query: &str) -> Result<String, String> {
    let names: Vec<(&str, &str)> = store.groups.iter().map(|g| (g.id.as_str(), g.name.as_str())).collect();
    find(&names, query, "group", "phi2ray groups")
}

/// `items` are (id, name) pairs; numbers count from 1.
fn find(items: &[(&str, &str)], query: &str, what: &str, list: &str) -> Result<String, String> {
    let query = query.trim();
    if let Ok(n) = query.parse::<usize>() {
        return items
            .get(n.wrapping_sub(1))
            .map(|(id, _)| id.to_string())
            .ok_or_else(|| format!("There's no {what} number {n}. See `{list}`."));
    }
    if let Some((id, _)) = items.iter().find(|(id, _)| *id == query) {
        return Ok(id.to_string());
    }
    let lower = query.to_lowercase();
    let exact: Vec<_> = items.iter().filter(|(_, name)| name.to_lowercase() == lower).collect();
    let matches = if exact.is_empty() { items.iter().filter(|(_, name)| name.to_lowercase().contains(&lower)).collect() } else { exact };
    match matches.as_slice() {
        [] => Err(format!("No {what} matches \"{query}\". See `{list}`.")),
        [(id, _)] => Ok(id.to_string()),
        many => {
            let names: Vec<String> = many.iter().take(5).map(|(_, n)| format!("\"{n}\"")).collect();
            Err(format!("\"{query}\" matches {} {what}s ({}{}). Use its number from `{list}`.", many.len(), names.join(", "), if many.len() > 5 { ", …" } else { "" }))
        }
    }
}

fn test(app: &AppHandle, state: &AppState, servers: Vec<String>, group: Option<String>, progress: &mut dyn FnMut(Value)) -> Result<Value, String> {
    let (ids, names) = {
        let store = state.store.lock().unwrap();
        let mut ids = servers.iter().map(|s| find_server(&store, s)).collect::<Result<Vec<_>, _>>()?;
        if ids.is_empty() {
            let group = group.map(|g| find_group(&store, &g)).transpose()?;
            ids = store.profiles.iter().filter(|p| group.as_ref().is_none_or(|g| p.group_id == *g)).map(|p| p.id.clone()).collect();
        }
        if ids.is_empty() {
            return Err("There are no servers to test.".into());
        }
        let names: Vec<(String, usize, String)> =
            store.profiles.iter().enumerate().map(|(i, p)| (p.id.clone(), i + 1, p.name.clone())).collect();
        (ids, names)
    };
    let total = ids.len();
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    let app2 = app.clone();
    let task = tauri::async_runtime::spawn(async move {
        crate::run_delay_tests(&app2, ids, move |r| {
            let _ = tx.lock().unwrap().send((r.id.clone(), r.ms));
        })
        .await
    });
    let mut ok = 0;
    for (id, ms) in rx {
        ok += ms.is_some() as usize;
        let (number, name) = names.iter().find(|(i, ..)| *i == id).map(|(_, n, name)| (*n, name.clone())).unwrap_or_default();
        progress(serde_json::to_value(DelayView { number, name, ms }).unwrap_or_default());
    }
    tauri::async_runtime::block_on(task).map_err(|e| e.to_string())??;
    Ok(json!({ "tested": total, "reachable": ok }))
}

fn add(app: &AppHandle, state: &AppState, text: &str, group: Option<String>) -> Result<Value, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("Nothing to add.".into());
    }
    let is_url = !text.contains(char::is_whitespace) && (text.starts_with("https://") || text.starts_with("http://"));
    let view = if is_url {
        connection::log(state, "[console] add subscription");
        let result = tauri::async_runtime::block_on(crate::add_subscription_url(app, text))?;
        let name = state.store.lock().unwrap().group(&result.group_id).map(|g| g.name.clone());
        let mut errors = Vec::new();
        if result.skipped > 0 {
            errors.push(format!("{} links in the subscription couldn't be read.", result.skipped));
        }
        if text.starts_with("http://") {
            errors.push("This subscription uses http, so it isn't updated automatically: its servers could be changed on the way.".into());
        }
        AddView { added: result.count, errors, group: name }
    } else {
        let group = {
            let store = state.store.lock().unwrap();
            group.map(|g| find_group(&store, &g)).transpose()?.unwrap_or_else(|| DEFAULT_GROUP.to_string())
        };
        connection::log(state, "[console] add servers");
        let result = crate::add_links(state, text, &group)?;
        AddView { added: result.added, errors: result.errors, group: None }
    };
    changed(app);
    to_value(view)
}

fn update(app: &AppHandle, state: &AppState, group: Option<String>, progress: &mut dyn FnMut(Value)) -> Result<Value, String> {
    let groups: Vec<(String, String)> = {
        let store = state.store.lock().unwrap();
        let only = group.map(|g| find_group(&store, &g)).transpose()?;
        let subs: Vec<_> = store
            .groups
            .iter()
            .filter(|g| g.subscription.is_some() && only.as_ref().is_none_or(|id| g.id == *id))
            .map(|g| (g.id.clone(), g.name.clone()))
            .collect();
        if subs.is_empty() {
            return Err(if only.is_some() { "That group isn't a subscription.".into() } else { "There are no subscriptions.".into() });
        }
        subs
    };
    connection::log(state, "[console] update subscriptions");
    let mut failed = 0;
    for (id, name) in groups {
        let result = tauri::async_runtime::block_on(crate::refresh_subscription(app, &id));
        failed += result.is_err() as usize;
        let view = match result {
            Ok(r) => UpdateView { group: name, servers: Some(r.count), error: None },
            Err(e) => UpdateView { group: name, servers: None, error: Some(e) },
        };
        progress(serde_json::to_value(view).unwrap_or_default());
    }
    changed(app);
    if failed > 0 {
        return Err(format!("{failed} subscription update(s) failed."));
    }
    Ok(Value::Null)
}

// ---------- The pipe ----------

#[cfg(windows)]
mod pipe {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    use crate::ipc::{Reply, MAX_REQUEST};

    /// Answers one request through the given sender; true if the app should then quit.
    pub type Handler = Box<dyn Fn(&[u8], &mut dyn FnMut(&Reply)) -> bool + Send + Sync>;

    /// What the pipe does with requests, kept apart from the app so it can be tested alone.
    pub struct Hooks {
        pub handle: Handler,
        pub quit: Box<dyn Fn() + Send + Sync>,
        pub log: Box<dyn Fn(String) + Send + Sync>,
    }

    /// What the account running Phi2ray may do with the pipe (see `security`).
    const CLIENT_ACCESS: u32 = 0x120083;
    /// Requests handled at once; more get a "busy" answer instead of a thread each.
    const MAX_CLIENTS: usize = 4;
    /// A tool that connects but doesn't send its request in time is dropped.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    const BUFFER: u32 = 64 * 1024;

    struct Listening {
        name: String,
        stop: Arc<AtomicBool>,
    }

    static LISTENING: Mutex<Option<Listening>> = Mutex::new(None);
    static ACTIVE: AtomicUsize = AtomicUsize::new(0);

    /// A pipe handle, closed on drop. Raw handles aren't Send, but a pipe can be used from any
    /// thread.
    struct Pipe(HANDLE);
    unsafe impl Send for Pipe {}
    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    struct Security(PSECURITY_DESCRIPTOR);
    unsafe impl Send for Security {}
    impl Drop for Security {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0 as _) };
        }
    }

    /// Who may open the pipe: the system and administrators fully, and the account running
    /// Phi2ray only to read and write (0x120083: read/write data, read attributes, read the
    /// security descriptor, synchronize).
    ///
    /// That account deliberately doesn't get FILE_CREATE_PIPE_INSTANCE (the same bit as
    /// "append data", so plain GENERIC_WRITE would include it): with it, any program of the
    /// user's could open more server ends of this very pipe and answer the tool in Phi2ray's
    /// name. The owner is set to Administrators (only an elevated process can), which is what
    /// the tool checks. Medium integrity, so the tool needn't run elevated.
    ///
    /// An unelevated (development) app has neither: it needs full access itself to add
    /// instances, and a release build of the tool refuses its pipe.
    fn security(sid: &str, elevated: bool) -> Result<Security, String> {
        let (owner, access) = if elevated { ("O:BA", format!("{CLIENT_ACCESS:#x}")) } else { ("", "GA".into()) };
        let sddl = format!("{owner}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;{access};;;{sid})S:(ML;;NW;;;ME)");
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
        };
        if ok == 0 {
            return Err(format!("cannot set up the pipe's permissions ({})", std::io::Error::last_os_error()));
        }
        Ok(Security(sd))
    }

    fn create(name: &[u16], first: bool, security: &Security) -> Result<Pipe, std::io::Error> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        };
        // The first instance must be new: if another program already holds the name, it fails
        // instead of joining that program's pipe.
        let flags = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER,
                BUFFER,
                0,
                &attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Pipe(handle))
    }

    pub fn start(hooks: Hooks) -> Result<(), String> {
        let mut listening = LISTENING.lock().unwrap();
        if listening.is_some() {
            return Ok(());
        }
        let sid = crate::win::current_user_sid().ok_or("cannot tell which Windows account runs Phi2ray")?;
        let name = crate::ipc::pipe_name(&sid);
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let security = security(&sid, crate::win::is_elevated())?;
        // Right after turning it off and on again, the old pipe may take a moment to close.
        let mut first = create(&wide, true, &security);
        for _ in 0..10 {
            if first.is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
            first = create(&wide, true, &security);
        }
        let first = first.map_err(|e| format!("cannot listen for console commands: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        thread::spawn(move || accept(Arc::new(hooks), wide, security, first, flag));
        *listening = Some(Listening { name, stop });
        Ok(())
    }

    pub fn stop() {
        let Some(listening) = LISTENING.lock().unwrap().take() else { return };
        listening.stop.store(true, Ordering::SeqCst);
        // Wake the waiting thread by connecting once; it sees the flag and closes the pipe.
        let wide: Vec<u16> = listening.name.encode_utf16().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(wide.as_ptr(), CLIENT_ACCESS, 0, std::ptr::null(), OPEN_EXISTING, 0, null_mut())
        };
        if handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(handle) };
        }
    }

    /// Hands each connection to its own thread. A new instance is always created before the
    /// connected one is handed off, so the name is never free for another program to take.
    fn accept(hooks: Arc<Hooks>, name: Vec<u16>, security: Security, first: Pipe, stop: Arc<AtomicBool>) {
        let mut listening = first;
        loop {
            let connected = unsafe { ConnectNamedPipe(listening.0, null_mut()) } != 0
                || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if stop.load(Ordering::SeqCst) {
                return;
            }
            let next = match create(&name, false, &security) {
                Ok(p) => p,
                Err(e) => {
                    (hooks.log)(format!("[app] Console control stopped: {e}"));
                    LISTENING.lock().unwrap().take();
                    return;
                }
            };
            let client = std::mem::replace(&mut listening, next);
            if !connected {
                continue;
            }
            if ACTIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
                ACTIVE.fetch_sub(1, Ordering::SeqCst);
                let mut file = into_file(client);
                let _ = reply(&mut file, &Reply::Failed { error: "Phi2ray is busy with other commands. Try again.".into() });
                finish(file);
                continue;
            }
            let hooks = hooks.clone();
            thread::spawn(move || {
                serve(&hooks, client);
                ACTIVE.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }

    fn into_file(pipe: Pipe) -> File {
        let file = unsafe { File::from_raw_handle(pipe.0) };
        std::mem::forget(pipe);
        file
    }

    fn serve(hooks: &Hooks, pipe: Pipe) {
        let mut file = into_file(pipe);
        let Some(request) = read_request(&mut file) else { return };
        let mut gone = false;
        let quit = (hooks.handle)(&request, &mut |r| {
            // Once the tool is gone (Ctrl+C), the rest of the answer has nowhere to go.
            if !gone && reply(&mut file, r).is_err() {
                gone = true;
            }
        });
        finish(file);
        if quit {
            (hooks.quit)();
        }
    }

    /// One line, waiting without blocking so a client that never sends can't hold a thread.
    fn read_request(file: &mut File) -> Option<Vec<u8>> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let mut data = Vec::new();
        loop {
            let mut available = 0u32;
            let ok = unsafe {
                PeekNamedPipe(file.as_raw_handle() as HANDLE, null_mut(), 0, null_mut(), &mut available, null_mut())
            };
            if ok == 0 {
                return None;
            }
            if available == 0 {
                if Instant::now() > deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            let mut buf = vec![0u8; available.min(BUFFER) as usize];
            let n = file.read(&mut buf).ok()?;
            data.extend_from_slice(&buf[..n]);
            if let Some(end) = data.iter().position(|&b| b == b'\n') {
                data.truncate(end);
                return Some(data);
            }
            if data.len() > MAX_REQUEST {
                return None;
            }
        }
    }

    fn reply(file: &mut File, reply: &Reply) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(reply).unwrap_or_default();
        line.push(b'\n');
        file.write_all(&line)
    }

    /// Lets the tool read everything before the connection closes.
    fn finish(file: File) {
        let handle = file.as_raw_handle() as HANDLE;
        unsafe {
            FlushFileBuffers(handle);
            DisconnectNamedPipe(handle);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The account may talk over the pipe but not open server ends of it (the release
        /// rules, minus the Administrators owner, which needs elevation).
        #[test]
        fn the_user_can_connect_but_not_serve() {
            let sid = crate::win::current_user_sid().unwrap();
            let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;{CLIENT_ACCESS:#x};;;{sid})S:(ML;;NW;;;ME)");
            let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) }, 0);
            let security = Security(sd);
            let name: Vec<u16> = format!(r"\\.\pipe\phi2ray-test-{}",std::process::id()).encode_utf16().chain(Some(0)).collect();

            let _server = create(&name, true, &security).unwrap();
            if crate::win::is_elevated() {
                return; // Administrators may create instances; the rest only holds for the user.
            }
            let err = create(&name, false, &security).err().expect("a second server end was allowed");
            assert_eq!(err.raw_os_error(), Some(5), "{err}");
            let client = unsafe { CreateFileW(name.as_ptr(), CLIENT_ACCESS, 0, std::ptr::null(), OPEN_EXISTING, 0, null_mut()) };
            assert_ne!(client, INVALID_HANDLE_VALUE, "{}", std::io::Error::last_os_error());
            unsafe { CloseHandle(client) };
        }

        /// The real console tool against the real pipe, with canned answers instead of the app.
        /// Needs a debug build of the tool: `cargo build --manifest-path cli/Cargo.toml`.
        #[test]
        #[ignore]
        fn the_console_tool_talks_to_the_pipe() {
            use crate::ipc::{Command, Request};
            let tool = concat!(env!("CARGO_MANIFEST_DIR"), "/cli/target/debug/phi2ray.exe");
            start(Hooks {
                handle: Box::new(|request, send| {
                    let request: Request = serde_json::from_slice(request).unwrap();
                    match request.command {
                        Command::Test { .. } => {
                            for (n, ms) in [(1, Some(120)), (2, None)] {
                                let data = serde_json::json!({ "number": n, "name": format!("Server {n}"), "ms": ms });
                                send(&Reply::Progress { data });
                            }
                            send(&Reply::Done { data: serde_json::json!({ "tested": 2, "reachable": 1 }) });
                        }
                        Command::Mode { mode: None } => send(&Reply::Done { data: serde_json::json!("vpn") }),
                        _ => send(&Reply::Failed { error: "not in this test".into() }),
                    }
                    false
                }),
                quit: Box::new(|| {}),
                log: Box::new(|line| eprintln!("{line}")),
            })
            .unwrap();
            let run = |args: &[&str]| {
                let out = std::process::Command::new(tool).args(args).output().expect("build the console tool first");
                let text = |b: Vec<u8>| String::from_utf8_lossy(&b).replace("\r\n", "\n");
                (out.status.code(), text(out.stdout), text(out.stderr))
            };
            assert_eq!(run(&["mode"]), (Some(0), "vpn\n".into(), String::new()));
            let (code, out, _) = run(&["test"]);
            assert_eq!(code, Some(0));
            assert!(out.contains("Server 1") && out.contains("120 ms") && out.contains("timeout"), "{out}");
            assert!(out.contains("1 of 2 servers answered. Fastest: 1 Server 1 (120 ms)."), "{out}");
            let (code, _, err) = run(&["disconnect"]);
            assert_eq!((code, err.trim()), (Some(1), "phi2ray: not in this test"));
            let (code, _, err) = run(&["frobnicate"]);
            assert_eq!(code, Some(2), "{err}");
            stop();
            let (code, _, err) = run(&["status"]);
            assert_eq!(code, Some(3), "{err}");
        }
    }
}

#[cfg(not(windows))]
mod pipe {
    pub fn stop() {}
}

// ---------- Installing the command ----------

/// Puts the tool in `bin` and `bin` on the user's PATH, or takes them away again.
#[cfg(feature = "embed-cores")]
mod install {
    use std::fs;
    use std::path::Path;

    use sha2::{Digest, Sha256};
    use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::{RegKey, RegValue};

    /// The tool's name on PATH.
    const TOOL_EXE: &str = "phi2ray.exe";
    /// Written next to the tool: the app's path and hash (see `write_app_record`).
    const APP_RECORD: &str = "app.json";

    /// Built by `npm run build:exe` from `src-tauri/cli` before the app itself.
    static TOOL: &[u8] = include_bytes!(env!("PHI2RAY_CLI_ZST"));
    const TOOL_SHA256: &str = env!("PHI2RAY_CLI_SHA256");

    pub fn add(bin: &Path) -> Result<(), String> {
        fs::create_dir_all(bin).map_err(|e| format!("cannot create {}: {e}", bin.display()))?;
        write_tool(bin)?;
        write_app_record(bin);
        let dir = bin.to_string_lossy().into_owned();
        edit_path(|entries| {
            if !entries.iter().any(|e| same_dir(e, &dir)) {
                entries.push(dir.clone());
            }
        })
    }

    pub fn remove(bin: &Path) -> Result<(), String> {
        let dir = bin.to_string_lossy().into_owned();
        edit_path(|entries| entries.retain(|e| !same_dir(e, &dir)))?;
        // A tool that is running right now can't be deleted; it's replaced or removed next time.
        let _ = fs::remove_file(bin.join(TOOL_EXE));
        let _ = fs::remove_file(bin.join(APP_RECORD));
        Ok(())
    }

    fn write_tool(bin: &Path) -> Result<(), String> {
        let path = bin.join(TOOL_EXE);
        let old = path.with_extension("old");
        let _ = fs::remove_file(&old);
        if fs::read(&path).is_ok_and(|b| hex::encode(Sha256::digest(&b)) == TOOL_SHA256) {
            return Ok(());
        }
        let data = zstd::decode_all(TOOL).map_err(|e| format!("cannot unpack the phi2ray command: {e}"))?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &data).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        // A running tool can't be overwritten, but it can be moved aside.
        if fs::rename(&tmp, &path).is_err() {
            let _ = fs::rename(&path, &old);
            fs::rename(&tmp, &path).map_err(|e| format!("cannot replace {}: {e}", path.display()))?;
        }
        Ok(())
    }

    /// Where this exe is and its hash, so `phi2ray start` can launch the app, and only this
    /// exact file. Hashing takes a moment, so it happens in the background.
    fn write_app_record(bin: &Path) {
        let record = bin.join(APP_RECORD);
        std::thread::spawn(move || {
            let Ok(exe) = std::env::current_exe() else { return };
            let Ok(bytes) = fs::read(&exe) else { return };
            let json = serde_json::json!({ "path": exe, "sha256": hex::encode(Sha256::digest(&bytes)) });
            let tmp = record.with_extension("tmp");
            if fs::write(&tmp, json.to_string()).is_ok() {
                let _ = fs::rename(&tmp, &record);
            }
        });
    }

    fn same_dir(a: &str, b: &str) -> bool {
        a.trim().trim_end_matches('\\').eq_ignore_ascii_case(b.trim_end_matches('\\'))
    }

    /// Edits the user's own PATH (not the system one), keeping its type and every other entry
    /// exactly as it was, then tells open programs (Explorer, new terminals) about it.
    fn edit_path(edit: impl FnOnce(&mut Vec<String>)) -> Result<(), String> {
        let env = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
            .map_err(|e| format!("cannot open the user's environment: {e}"))?;
        let (text, vtype) = match env.get_raw_value("Path") {
            Ok(v) if matches!(v.vtype, RegType::REG_SZ | RegType::REG_EXPAND_SZ) => {
                let wide: Vec<u16> = v.bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                (String::from_utf16_lossy(&wide).trim_end_matches('\0').to_string(), v.vtype)
            }
            Ok(_) => return Err("the user's PATH has an unexpected format, so it was left alone".into()),
            Err(_) => (String::new(), RegType::REG_EXPAND_SZ),
        };
        let mut entries: Vec<String> = text.split(';').filter(|e| !e.is_empty()).map(String::from).collect();
        let before = entries.clone();
        edit(&mut entries);
        if entries == before {
            return Ok(());
        }
        let joined = entries.join(";");
        let bytes = joined.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect();
        env.set_raw_value("Path", &RegValue { bytes, vtype }).map_err(|e| format!("cannot update PATH: {e}"))?;
        std::thread::spawn(announce);
        Ok(())
    }

    fn announce() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE};
        let what: Vec<u16> = "Environment".encode_utf16().chain(Some(0)).collect();
        unsafe {
            SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, what.as_ptr() as isize, SMTO_ABORTIFHUNG, 2000, std::ptr::null_mut());
        }
    }
}

#[cfg(not(feature = "embed-cores"))]
mod install {
    use std::path::Path;

    pub fn add(_bin: &Path) -> Result<(), String> {
        Ok(())
    }

    pub fn remove(_bin: &Path) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::find;

    #[test]
    fn finds_by_number_id_or_name() {
        let items = [("a1", "Germany 1"), ("b2", "Germany 2"), ("c3", "Netherlands")];
        assert_eq!(find(&items, "2", "server", "list").unwrap(), "b2");
        assert_eq!(find(&items, "c3", "server", "list").unwrap(), "c3");
        assert_eq!(find(&items, "nether", "server", "list").unwrap(), "c3");
        assert_eq!(find(&items, "GERMANY 1", "server", "list").unwrap(), "a1");
        assert!(find(&items, "germany", "server", "list").unwrap_err().contains("matches 2"));
        assert!(find(&items, "0", "server", "list").is_err());
        assert!(find(&items, "9", "server", "list").is_err());
        assert!(find(&items, "france", "server", "list").is_err());
    }
}
