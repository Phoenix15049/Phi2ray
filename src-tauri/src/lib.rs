// Release builds run as administrator. Without embedded cores they would run xray and sing-box
// from a folder next to the exe that normal users can usually write to.
#[cfg(all(not(debug_assertions), not(feature = "embed-cores")))]
compile_error!("Release builds must embed the cores: use `npm run build:exe`.");

mod config;
mod connection;
mod cores;
mod delay;
mod dns;
mod firewall;
mod netinfo;
mod parser;
mod probe;
mod proxy;
mod split;
mod store;
mod subscription;
mod tray;
mod tun;
mod win;
mod xray;

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rand::Rng;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WindowEvent};
use tokio::sync::Semaphore;

use crate::connection::{now_ms, Health, Link, Session};
use crate::parser::{Profile, ProfileView};
use crate::store::{Group, Settings, Store, DEFAULT_GROUP};
use crate::subscription::Subscription;
use crate::xray::{Core, Logs, SING_BOX_EXE, XRAY_EXE};

/// How many throwaway xray processes the delay test runs at once.
const DELAY_TEST_PARALLEL: usize = 4;
/// How often due subscriptions are looked for.
const SUBSCRIPTION_CHECK: Duration = Duration::from_secs(10 * 60);

pub(crate) struct Paths {
    data: PathBuf,
    store: PathBuf,
    proxy_marker: PathBuf,
    core: PathBuf,
    /// sing-box's working folder (its cache). Next to the cores in single-exe builds, where only
    /// administrators can write, since sing-box runs elevated.
    work: PathBuf,
}

impl Paths {
    fn xray(&self) -> PathBuf {
        self.core.join(XRAY_EXE)
    }

    fn sing_box(&self) -> PathBuf {
        self.core.join(SING_BOX_EXE)
    }
}

/// A core binary's identity when its hash was last checked.
type FileStamp = (Option<SystemTime>, u64);

pub(crate) struct AppState {
    store: Mutex<Store>,
    core: Mutex<Core>,
    link: Mutex<Option<Link>>,
    /// Bumped whenever a connection is replaced or stopped; supervisors exit when it changes.
    generation: AtomicU64,
    /// The kill switch is holding the internet blocked after the connection gave up.
    blocked: AtomicBool,
    logs: Logs,
    /// Serializes connect, disconnect and supervisor restarts.
    switching: Mutex<()>,
    verified: Mutex<HashMap<PathBuf, FileStamp>>,
    /// Why the bundled cores couldn't be unpacked, shown to the user.
    core_error: Option<String>,
    paths: Paths,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    groups: Vec<Group>,
    /// Without credentials: the window never needs them.
    profiles: Vec<ProfileView>,
    settings: Settings,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    session: Option<Session>,
    /// The kill switch firewall is active.
    firewall: bool,
    /// Blocked by the kill switch with no connection (auto-reconnect is off).
    blocked: bool,
    xray_found: bool,
    tun_found: bool,
    elevated: bool,
    core_error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportResult {
    added: usize,
    errors: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionResult {
    group_id: String,
    count: usize,
    skipped: usize,
}

#[derive(Clone, Serialize)]
struct DelayResult {
    id: String,
    ms: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AboutInfo {
    app: String,
    xray: Option<String>,
    sing_box: Option<String>,
    core_dir: String,
    data_dir: String,
}

/// Runs blocking work on a worker thread. Tauri runs plain (non-async) commands on the
/// UI thread, so anything slow must go through here to keep the window responsive.
async fn blocking<T: Send + 'static>(
    app: AppHandle,
    work: impl FnOnce(&AppHandle, &AppState) -> T + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(move || work(&app, &app.state::<AppState>()))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_state(state: State<AppState>) -> Snapshot {
    let store = state.store.lock().unwrap();
    Snapshot { groups: store.groups.clone(), profiles: store.profiles.iter().map(Profile::view).collect(), settings: store.settings.clone() }
}

// ---------- Servers and groups ----------

#[tauri::command]
fn import_links(state: State<AppState>, text: String, group_id: String) -> Result<ImportResult, String> {
    let mut store = state.store.lock().unwrap();
    match store.group(&group_id) {
        None => return Err("That group no longer exists.".into()),
        Some(g) if g.subscription.is_some() => {
            return Err("Servers can't be added to a subscription; they'd be replaced on the next update.".into())
        }
        _ => {}
    }
    let parser::Parsed { mut profiles, errors, .. } = parser::parse_many(&text);
    for p in &mut profiles {
        p.group_id = group_id.clone();
    }
    let added = profiles.len();
    store.profiles.extend(profiles);
    store.fix_selection();
    store.save(&state.paths.store)?;
    Ok(ImportResult { added, errors })
}

#[tauri::command]
fn delete_profile(state: State<AppState>, id: String) -> Result<(), String> {
    let mut store = state.store.lock().unwrap();
    store.profiles.retain(|p| p.id != id);
    store.fix_selection();
    store.save(&state.paths.store)
}

#[tauri::command]
fn create_group(state: State<AppState>, name: String) -> Result<String, String> {
    let name = clean_name(&name)?;
    let mut store = state.store.lock().unwrap();
    let id = new_id();
    store.groups.push(Group { id: id.clone(), name, subscription: None });
    store.save(&state.paths.store)?;
    Ok(id)
}

#[tauri::command]
fn update_group(
    state: State<AppState>,
    id: String,
    name: String,
    url: Option<String>,
    auto_update: Option<bool>,
) -> Result<(), String> {
    let name = clean_name(&name)?;
    let mut store = state.store.lock().unwrap();
    let group = store.group_mut(&id).ok_or("That group no longer exists.")?;
    group.name = name;
    if let Some(sub) = group.subscription.as_mut() {
        if let Some(url) = url {
            let url = url.trim().to_string();
            url::Url::parse(&url).map_err(|_| "That doesn't look like a valid link.")?;
            sub.url = url;
        }
        if let Some(auto) = auto_update {
            sub.auto_update = auto;
        }
    }
    store.save(&state.paths.store)
}

#[tauri::command]
fn delete_group(state: State<AppState>, id: String) -> Result<(), String> {
    if id == DEFAULT_GROUP {
        return Err("The default group can't be deleted.".into());
    }
    let mut store = state.store.lock().unwrap();
    store.groups.retain(|g| g.id != id);
    store.profiles.retain(|p| p.group_id != id);
    store.fix_selection();
    store.save(&state.paths.store)
}

#[tauri::command]
async fn add_subscription(app: AppHandle, url: String) -> Result<SubscriptionResult, String> {
    let url = url.trim().to_string();
    let state = app.state::<AppState>();
    if state.store.lock().unwrap().groups.iter().any(|g| g.subscription.as_ref().is_some_and(|s| s.url == url)) {
        return Err("This subscription is already added.".into());
    }
    let fetched = subscription::fetch(&url, proxy_port(&state).as_ref()).await?;

    let id = new_id();
    let name = fetched.title.clone().unwrap_or_else(|| {
        url::Url::parse(&url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_else(|| "Subscription".into())
    });
    // An http link can be read and its servers swapped by anyone on the way, so it isn't
    // fetched again on its own; the user can still update it (or turn auto-update on) by hand.
    let auto_update = url.to_ascii_lowercase().starts_with("https:");
    let mut sub = Subscription { url, auto_update, ..Subscription::default() };
    let (count, skipped) = (fetched.profiles.len(), fetched.skipped);
    apply_fetched(&mut sub, &fetched);

    let mut store = state.store.lock().unwrap();
    store.profiles.extend(subscription::merge(&[], fetched.profiles, &id));
    store.groups.push(Group { id: id.clone(), name: clean_name(&name).unwrap_or_else(|_| "Subscription".into()), subscription: Some(sub) });
    store.fix_selection();
    store.save(&state.paths.store)?;
    Ok(SubscriptionResult { group_id: id, count, skipped })
}

#[tauri::command]
async fn update_subscription(app: AppHandle, id: String) -> Result<SubscriptionResult, String> {
    let result = refresh_subscription(&app, &id).await;
    let _ = app.emit("groups-changed", ());
    result
}

async fn refresh_subscription(app: &AppHandle, id: &str) -> Result<SubscriptionResult, String> {
    let state = app.state::<AppState>();
    let url = {
        let store = state.store.lock().unwrap();
        let group = store.group(id).ok_or("That group no longer exists.")?;
        group.subscription.as_ref().ok_or("This group isn't a subscription.")?.url.clone()
    };
    let fetched = subscription::fetch(&url, proxy_port(&state).as_ref()).await;

    let mut store = state.store.lock().unwrap();
    let old: Vec<Profile> = store.profiles.iter().filter(|p| p.group_id == id).cloned().collect();
    let sub = store
        .group_mut(id)
        .and_then(|g| g.subscription.as_mut())
        .ok_or("This group was removed during the update.")?;
    let result = match fetched {
        Err(e) => {
            sub.last_error = Some(e.clone());
            Err(e)
        }
        Ok(fetched) => {
            apply_fetched(sub, &fetched);
            let (count, skipped) = (fetched.profiles.len(), fetched.skipped);
            let merged = subscription::merge(&old, fetched.profiles, id);
            store.profiles.retain(|p| p.group_id != id);
            store.profiles.extend(merged);
            store.fix_selection();
            Ok(SubscriptionResult { group_id: id.to_string(), count, skipped })
        }
    };
    store.save(&state.paths.store)?;
    result
}

fn apply_fetched(sub: &mut Subscription, f: &subscription::Fetched) {
    sub.updated_at = Some(now_ms());
    sub.last_error = None;
    sub.upload = f.upload;
    sub.download = f.download;
    sub.total = f.total;
    sub.expire = f.expire;
    if let Some(hours) = f.interval_hours {
        sub.interval_hours = hours.clamp(1, 168);
    }
}

/// Updates due subscriptions in the background.
async fn subscription_updater(app: AppHandle) {
    tokio::time::sleep(Duration::from_secs(30)).await;
    loop {
        let due: Vec<String> = {
            let state = app.state::<AppState>();
            let store = state.store.lock().unwrap();
            let now = now_ms();
            store
                .groups
                .iter()
                .filter(|g| g.subscription.as_ref().is_some_and(|s| s.is_due(now)))
                .map(|g| g.id.clone())
                .collect()
        };
        for id in &due {
            let result = refresh_subscription(&app, id).await;
            let state = app.state::<AppState>();
            match result {
                Ok(r) => connection::log(&state, format!("[app] Subscription updated: {} servers", r.count)),
                Err(e) => connection::log(&state, format!("[app] Subscription update failed: {e}")),
            }
        }
        if !due.is_empty() {
            let _ = app.emit("groups-changed", ());
        }
        tokio::time::sleep(SUBSCRIPTION_CHECK).await;
    }
}

/// When connected, subscription downloads go through the connection, always to the server
/// (split tunnel rules don't apply to Phi2ray's own requests).
fn proxy_port(state: &AppState) -> Option<probe::LocalProxy> {
    connection::internal_proxy(state)
}

// ---------- Settings ----------

#[tauri::command]
async fn update_settings(app: AppHandle, mut settings: Settings) -> Result<Settings, String> {
    settings.validate()?;
    settings.split.normalize()?;
    blocking(app, move |app, state| {
        let kill_switch_changed = state.store.lock().unwrap().settings.kill_switch != settings.kill_switch;
        if kill_switch_changed {
            connection::apply_kill_switch(state, &settings)?;
        }
        apply_window_settings(app, &settings);
        let mut store = state.store.lock().unwrap();
        store.settings = settings.clone();
        store.save(&state.paths.store)?;
        // The cleaned-up version (e.g. canonical split tunnel entries) goes back to the UI.
        Ok(settings)
    })
    .await?
}

fn apply_window_settings(app: &AppHandle, settings: &Settings) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_always_on_top(settings.always_on_top);
    }
}

/// Tests DNS-over-HTTPS servers. When connected, through the connection, as VPN mode uses them.
#[tauri::command]
async fn ping_dns(app: AppHandle, servers: Vec<String>) -> Result<Vec<Option<u32>>, String> {
    let proxy = proxy_port(&app.state::<AppState>());
    let tasks: Vec<_> = servers
        .into_iter()
        .map(|server| {
            let proxy = proxy.clone();
            tauri::async_runtime::spawn(async move { dns::ping(&server, proxy.as_ref()).await.ok().flatten() })
        })
        .collect();
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.ok().flatten());
    }
    Ok(results)
}

/// Disconnects (restoring the network) and exits.
#[tauri::command]
async fn quit_app(app: AppHandle) -> Result<(), String> {
    blocking(app, |app, state| {
        connection::disconnect(state);
        app.exit(0);
    })
    .await
}

/// Running programs, for picking split tunnel apps.
#[tauri::command]
async fn running_apps() -> Result<Vec<win::RunningApp>, String> {
    tauri::async_runtime::spawn_blocking(win::running_apps).await.map_err(|e| e.to_string())
}

#[tauri::command]
fn hide_window(app: AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

// ---------- Connection ----------

#[tauri::command]
async fn connect(app: AppHandle, id: String) -> Result<Session, String> {
    blocking(app, move |app, state| connection::connect(app, state, &id)).await?
}

#[tauri::command]
async fn disconnect(app: AppHandle) -> Result<(), String> {
    blocking(app, |_, state| connection::disconnect(state)).await
}

#[tauri::command]
async fn status(app: AppHandle) -> Result<Status, String> {
    blocking(app, |_, state| Status {
        session: state.link.lock().unwrap().as_ref().map(|l| l.session.clone()),
        firewall: firewall::is_active(),
        blocked: state.blocked.load(Ordering::SeqCst),
        xray_found: state.paths.xray().exists(),
        tun_found: state.paths.sing_box().exists(),
        elevated: win::is_elevated(),
        core_error: state.core_error.clone(),
    })
    .await
}

#[tauri::command]
async fn check_connection(app: AppHandle) -> Result<Health, String> {
    blocking(app, |_, state| connection::check_now(state)).await?
}

/// The SOCKS link with its password, asked for only when the user copies it.
#[tauri::command]
fn socks_url(state: State<AppState>) -> Result<String, String> {
    let link = state.link.lock().unwrap();
    let s = &link.as_ref().ok_or("Not connected.")?.session;
    Ok(format!("socks5://{}:{}@127.0.0.1:{}", s.socks_user, s.socks_pass, s.socks_port))
}

/// The only pages the window may open: a fixed list, so the WebView can't open arbitrary URLs.
const LINKS: [(&str, &str); 2] = [("github", "https://github.com/Phoenix15049"), ("site", "https://inosila.com/")];

#[tauri::command]
async fn open_link(name: String) -> Result<(), String> {
    let url = LINKS.iter().find(|(n, _)| *n == name).map(|(_, url)| *url).ok_or("Unknown link.")?;
    win::open_url(url)
}

/// Only on request: it asks several outside services, so it never runs on its own.
#[tauri::command]
async fn connection_info(app: AppHandle) -> Result<netinfo::Report, String> {
    let target = blocking(app, |_, state| connection::info_target(state)).await??;
    netinfo::lookup(target).await
}

#[tauri::command]
fn get_logs(state: State<AppState>) -> Vec<String> {
    state.logs.lock().unwrap().iter().cloned().collect()
}

#[tauri::command]
fn clear_logs(state: State<AppState>) {
    state.logs.lock().unwrap().clear();
}

/// Tests the given profiles (all if `ids` is empty) and emits a `delay` event per result.
#[tauri::command]
async fn test_delays(app: AppHandle, ids: Vec<String>) -> Result<(), String> {
    let (profiles, target, exe, assets) = blocking(app.clone(), move |_, state| -> Result<_, String> {
        let exe = state.paths.xray();
        if !exe.exists() {
            return Err(format!("Xray core not found. Put {XRAY_EXE} in {}", state.paths.core.display()));
        }
        verify_cached(state, &exe)?;
        let store = state.store.lock().unwrap();
        let target = delay::TestTarget::parse(&store.settings.test_url)?;
        let profiles: Vec<Profile> =
            store.profiles.iter().filter(|p| ids.is_empty() || ids.contains(&p.id)).cloned().collect();
        Ok((profiles, target, exe, state.paths.core.clone()))
    })
    .await??;

    let target = Arc::new(target);
    let limit = Arc::new(Semaphore::new(DELAY_TEST_PARALLEL));
    let tasks: Vec<_> = profiles
        .into_iter()
        .map(|p| {
            let (app, exe, assets, target, limit) = (app.clone(), exe.clone(), assets.clone(), target.clone(), limit.clone());
            tauri::async_runtime::spawn(async move {
                let _permit = limit.acquire_owned().await;
                let ms = delay::test(&exe, &assets, &p, &target).await;
                let _ = app.emit("delay", DelayResult { id: p.id, ms });
            })
        })
        .collect();
    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

#[tauri::command]
async fn about(app: AppHandle) -> Result<AboutInfo, String> {
    let version = app.package_info().version.to_string();
    blocking(app, move |_, state| {
        // Only run a core binary after its hash check passed.
        let core_version = |exe: PathBuf| {
            (exe.exists() && verify_cached(state, &exe).is_ok()).then(|| xray::version(&exe)).flatten()
        };
        AboutInfo {
            app: version,
            xray: core_version(state.paths.xray()),
            sing_box: core_version(state.paths.sing_box()),
            core_dir: state.paths.core.display().to_string(),
            data_dir: state.paths.data.display().to_string(),
        }
    })
    .await
}

#[tauri::command]
fn relaunch_as_admin(app: AppHandle) -> Result<(), String> {
    win::relaunch_as_admin()?;
    app.exit(0);
    Ok(())
}

/// Checks a core's hash once per file version instead of re-reading it on every use.
fn verify_cached(state: &AppState, exe: &Path) -> Result<(), String> {
    if cores::EMBEDDED {
        // Verified at startup and locked against changes since, so nothing to re-check.
        return if cores::trusted(exe) {
            Ok(())
        } else {
            Err(format!("{} didn't pass the integrity check. Restart Phi2ray.", exe.display()))
        };
    }
    let meta = std::fs::metadata(exe).map_err(|e| format!("Cannot read {}: {e}", exe.display()))?;
    let stamp = (meta.modified().ok(), meta.len());
    if state.verified.lock().unwrap().get(exe) == Some(&stamp) {
        return Ok(());
    }
    xray::verify(exe)?;
    state.verified.lock().unwrap().insert(exe.to_path_buf(), stamp);
    Ok(())
}

fn clean_name(name: &str) -> Result<String, String> {
    let name: String = name.trim().chars().take(60).collect();
    if name.is_empty() {
        Err("Please enter a name.".into())
    } else {
        Ok(name)
    }
}

fn new_id() -> String {
    hex::encode(rand::thread_rng().gen::<[u8; 8]>())
}

fn find_core_dir(app: &AppHandle) -> PathBuf {
    let mut candidates = Vec::new();
    if let Ok(dir) = app.path().resource_dir() {
        candidates.push(dir.join("core"));
    }
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())) {
        candidates.push(dir.join("core"));
    }
    #[cfg(debug_assertions)]
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("core"));

    let fallback = candidates.last().cloned().unwrap_or_else(|| PathBuf::from("core"));
    candidates.into_iter().find(|d| d.join(XRAY_EXE).exists()).unwrap_or(fallback)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    // Opening the exe again brings the running window forward instead of starting a second copy
    // (two copies would fight over the tunnel and the firewall). Release builds only: in
    // development the "restart as administrator" flow briefly needs two instances.
    #[cfg(not(debug_assertions))]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| tray::show_window(app)));

    builder
        .setup(|app| {
            let data = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data)?;
            let paths = Paths {
                store: data.join("store.bin"),
                proxy_marker: data.join("proxy-backup.json"),
                core: find_core_dir(app.handle()),
                work: data.join("sing-box"),
                data,
            };
            let logs: Logs = Arc::new(Mutex::new(VecDeque::new()));
            // Single-exe builds unpack their cores first; other builds use the core folder.
            // When unpacking fails they run no core at all: never one found next to the exe,
            // where anyone could have put it.
            let mut paths = paths;
            let core_error = match cores::target_dir() {
                None => None,
                Some(Ok(dir)) => {
                    if let Some(parent) = dir.parent() {
                        paths.work = parent.join("sing-box");
                    }
                    paths.core = dir;
                    cores::install(&paths.core).err()
                }
                Some(Err(e)) => Some(e),
            };
            if let Some(e) = &core_error {
                logs.lock().unwrap().push_back(format!("[app] {e}"));
            }
            // Recover the user's proxy settings if we crashed while connected.
            if let Err(e) = proxy::restore(&paths.proxy_marker) {
                logs.lock().unwrap().push_back(format!("[app] {e}"));
            }
            // Kill switch rules left by a crash keep blocking until the user reconnects or unblocks.
            let blocked = firewall::recover();
            if blocked {
                logs.lock().unwrap().push_back(
                    "[app] Phi2ray closed unexpectedly while the kill switch was on. The internet stays blocked until you reconnect or unblock.".into(),
                );
            }
            app.manage(AppState {
                store: Mutex::new(Store::load(&paths.store)),
                core: Mutex::new(Core::new(logs.clone())),
                link: Mutex::new(None),
                generation: AtomicU64::new(0),
                blocked: AtomicBool::new(blocked),
                logs,
                switching: Mutex::new(()),
                verified: Mutex::new(HashMap::new()),
                core_error,
                paths,
            });
            tauri::async_runtime::spawn(subscription_updater(app.handle().clone()));
            let settings = app.state::<AppState>().store.lock().unwrap().settings.clone();
            apply_window_settings(app.handle(), &settings);
            tray::create(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                tray::request_quit(window.app_handle());
            }
            WindowEvent::Resized(_) => {
                let to_tray = window.app_handle().state::<AppState>().store.lock().unwrap().settings.minimize_to_tray;
                if to_tray && window.is_minimized().unwrap_or(false) {
                    let _ = window.hide();
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            import_links,
            delete_profile,
            create_group,
            update_group,
            delete_group,
            add_subscription,
            update_subscription,
            update_settings,
            connect,
            disconnect,
            status,
            check_connection,
            connection_info,
            socks_url,
            open_link,
            get_logs,
            clear_logs,
            test_delays,
            about,
            relaunch_as_admin,
            ping_dns,
            quit_app,
            hide_window,
            running_apps
        ])
        .build(tauri::generate_context!())
        .expect("error while building Phi2ray")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(state) = app.try_state::<AppState>() {
                    connection::disconnect(&state);
                }
            }
        });
}
