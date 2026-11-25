// Windows release builds run as administrator. Without embedded cores they would run xray and
// sing-box from a folder next to the exe that normal users can usually write to. On Linux the app
// runs as the user and packages keep the cores in a folder only root can change.
#[cfg(all(windows, not(debug_assertions), not(feature = "embed-cores")))]
compile_error!("Release builds must embed the cores: use `npm run build:exe`.");

mod absolute;
mod config;
mod connection;
mod console;
mod cores;
mod delay;
mod dns;
mod firewall;
#[cfg(not(windows))]
mod helper;
#[allow(dead_code)]
mod helper_protocol;
mod ipc;
mod netinfo;
mod parser;
mod platform;
mod probe;
mod proxy;
mod split;
mod store;
mod subscription;
mod tray;
mod tun;
mod xray;

use std::collections::HashMap;
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
    absolute: Mutex<absolute::Status>,
    absolute_guard: Mutex<Option<std::process::Child>>,
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
    absolute: absolute::Status,
    absolute_supported: bool,
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
pub(crate) struct ImportResult {
    group_id: String,
    added: usize,
    errors: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubscriptionResult {
    group_id: String,
    count: usize,
    skipped: usize,
}

#[derive(Clone, Serialize)]
pub(crate) struct DelayResult {
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
async fn import_links(app: AppHandle, text: String, group_id: String, new_group_name: Option<String>) -> Result<ImportResult, String> {
    blocking(app, move |_, state| import_into(state, &text, &group_id, new_group_name.as_deref())).await?
}

pub(crate) fn add_links(state: &AppState, text: &str, group_id: &str) -> Result<ImportResult, String> {
    import_into(state, text, group_id, None)
}

fn edit_library<T>(state: &AppState, edit: impl FnOnce(&mut Store) -> Result<T, String>) -> Result<T, String> {
    let mut store = state.store.lock().unwrap();
    let mut updated = store.clone();
    let result = edit(&mut updated)?;
    updated.save(&state.paths.store)?;
    *store = updated;
    Ok(result)
}

fn import_into(state: &AppState, text: &str, group_id: &str, new_group_name: Option<&str>) -> Result<ImportResult, String> {
    let name = new_group_name.map(clean_name).transpose()?;
    let parser::Parsed { mut profiles, errors, .. } = parser::parse_many(text);
    let added = profiles.len();
    if added == 0 {
        return Ok(ImportResult { group_id: group_id.into(), added, errors });
    }
    edit_library(state, |store| {
        let group_id = if let Some(name) = name {
            let id = new_id();
            store.groups.push(Group { id: id.clone(), name, subscription: None, sort_by_delay: false });
            id
        } else {
            store.group(group_id).ok_or("That group no longer exists.")?;
            group_id.into()
        };
        for p in &mut profiles {
            p.group_id = group_id.clone();
            p.library.local = true;
        }
        store.profiles.extend(profiles);
        store.fix_selection();
        Ok(ImportResult { group_id, added, errors })
    })
}

#[tauri::command]
fn delete_profile(state: State<AppState>, id: String) -> Result<(), String> {
    edit_library(&state, |store| {
        let Some(profile) = store.profiles.iter().find(|p| p.id == id) else { return Ok(()) };
        if !profile.library.local && store.group(&profile.group_id).is_some_and(|g| g.subscription.is_some()) {
            let fingerprint = subscription::fingerprint(profile);
            let group_id = profile.group_id.clone();
            let another_copy = store.profiles.iter().any(|p| p.id != id && p.group_id == group_id &&
                !p.library.local && subscription::fingerprint(p) == fingerprint);
            if !another_copy { store.hidden_profiles.entry(group_id).or_default().insert(fingerprint); }
        }
        store.profiles.retain(|p| p.id != id);
        store.fix_selection();
        Ok(())
    })
}

#[tauri::command]
fn update_profile(state: State<AppState>, id: String, name: Option<String>, starred: Option<bool>) -> Result<(), String> {
    let name = name.as_deref().map(clean_name).transpose()?;
    edit_library(&state, |store| {
        let profile = store.profiles.iter_mut().find(|p| p.id == id).ok_or("Server no longer exists.")?;
        if let Some(name) = name {
            profile.name = name;
            profile.library.custom_name = true;
        }
        if let Some(starred) = starred { profile.library.starred = starred; }
        Ok(())
    })
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum LibraryKind { Group, Profile }

fn move_in_list<T>(
    list: &mut [T], index: usize, earlier: bool, target: Option<usize>, eligible: impl Fn(&T) -> bool,
) -> Result<(), String> {
    let positions: Vec<_> = list.iter().enumerate().filter_map(|(i, item)| eligible(item).then_some(i)).collect();
    let from = positions.iter().position(|&i| i == index).ok_or("Item cannot be moved.")?;
    let to = match target {
        Some(index) => positions.iter().position(|&i| i == index).ok_or("Item cannot be moved to that position.")?,
        None if earlier => from.saturating_sub(1),
        None => (from + 1).min(positions.len() - 1),
    };
    if from < to {
        for pair in positions[from..=to].windows(2) { list.swap(pair[0], pair[1]); }
    } else {
        for pair in positions[to..=from].windows(2).rev() { list.swap(pair[0], pair[1]); }
    }
    Ok(())
}

#[tauri::command]
fn move_library_item(state: State<AppState>, kind: LibraryKind, id: String, earlier: bool, target_id: Option<String>) -> Result<(), String> {
    edit_library(&state, |store| {
        match kind {
            LibraryKind::Group => {
                let index = store.groups.iter().position(|g| g.id == id).ok_or("Group no longer exists.")?;
                let target = target_id.as_ref().map(|id| store.groups.iter().position(|g| &g.id == id).ok_or("Group no longer exists.")).transpose()?;
                move_in_list(&mut store.groups, index, earlier, target, |_| true)?;
            }
            LibraryKind::Profile => {
                let index = store.profiles.iter().position(|p| p.id == id).ok_or("Server no longer exists.")?;
                let profile = &store.profiles[index];
                if store.group(&profile.group_id).is_some_and(|g| g.sort_by_delay) {
                    return Err("Turn off delay sorting to change the manual order.".into());
                }
                let (group_id, starred) = (profile.group_id.clone(), profile.library.starred);
                let target = target_id.as_ref().map(|id| store.profiles.iter().position(|p| &p.id == id).ok_or("Server no longer exists.")).transpose()?;
                move_in_list(&mut store.profiles, index, earlier, target, |p| p.group_id == group_id && p.library.starred == starred)?;
            }
        }
        Ok(())
    })
}

#[cfg(test)]
#[test]
fn moving_through_a_partition_keeps_other_items_in_place() {
    let mut list = ['a', 'x', 'b', 'y', 'c'];
    let eligible = |ch: &char| *ch <= 'c';
    move_in_list(&mut list, 0, false, Some(4), eligible).unwrap();
    assert_eq!(list, ['b', 'x', 'c', 'y', 'a']);
    assert!(move_in_list(&mut list, 4, true, Some(1), eligible).is_err());
    move_in_list(&mut list, 4, true, None, eligible).unwrap();
    assert_eq!(list, ['b', 'x', 'a', 'y', 'c']);
}

#[tauri::command]
fn set_group_sort(state: State<AppState>, id: String, by_delay: bool) -> Result<(), String> {
    edit_library(&state, |store| {
        store.group_mut(&id).ok_or("Group no longer exists.")?.sort_by_delay = by_delay;
        Ok(())
    })
}

#[tauri::command]
fn export_library_item(state: State<AppState>, kind: LibraryKind, id: String) -> Result<String, String> {
    let store = state.store.lock().unwrap();
    let export = match kind {
        LibraryKind::Profile => config::for_export(store.profiles.iter().find(|p| p.id == id).ok_or("Server no longer exists.")?),
        LibraryKind::Group => {
            store.group(&id).ok_or("Group no longer exists.")?;
            let profiles: Vec<_> = store.profiles.iter().filter(|p| p.group_id == id).map(config::for_export).collect();
            if profiles.is_empty() { return Err("This group has no servers to export.".into()); }
            serde_json::Value::Array(profiles)
        }
    };
    serde_json::to_string_pretty(&export).map_err(|_| "Could not export the configuration.".into())
}

#[tauri::command]
fn create_group(state: State<AppState>, name: String) -> Result<String, String> {
    let name = clean_name(&name)?;
    edit_library(&state, |store| {
        let id = new_id();
        store.groups.push(Group { id: id.clone(), name, subscription: None, sort_by_delay: false });
        Ok(id)
    })
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
    edit_library(&state, |store| {
        let group = store.group_mut(&id).ok_or("That group no longer exists.")?;
        group.name = name;
        if let Some(sub) = group.subscription.as_mut() {
            if let Some(url) = url {
                let url = url.trim().to_string();
                let parsed = url::Url::parse(&url).map_err(|_| "That doesn't look like a valid link.")?;
                if !matches!(parsed.scheme(), "https" | "http") { return Err("Subscription links must use HTTPS or HTTP.".into()); }
                if sub.url != url { sub.updated_at = None; }
                sub.url = url;
            }
            if let Some(auto) = auto_update { sub.auto_update = auto; }
            sub.enforce_policy();
        }
        Ok(())
    })
}

#[tauri::command]
fn delete_group(state: State<AppState>, id: String) -> Result<(), String> {
    if id == DEFAULT_GROUP {
        return Err("The default group can't be deleted.".into());
    }
    edit_library(&state, |store| {
        store.groups.retain(|g| g.id != id);
        store.hidden_profiles.remove(&id);
        store.profiles.retain(|p| p.group_id != id);
        store.fix_selection();
        Ok(())
    })
}

#[tauri::command]
async fn add_subscription(app: AppHandle, url: String) -> Result<SubscriptionResult, String> {
    add_subscription_url(&app, &url).await
}

pub(crate) async fn add_subscription_url(app: &AppHandle, url: &str) -> Result<SubscriptionResult, String> {
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
    let mut sub = Subscription { url, ..Subscription::default() };
    sub.enforce_policy();
    let (count, skipped) = (fetched.profiles.len(), fetched.skipped);
    apply_fetched(&mut sub, &fetched);

    edit_library(&state, |store| {
        if store.groups.iter().any(|g| g.subscription.as_ref().is_some_and(|current| current.url == sub.url)) {
            return Err("This subscription is already added.".into());
        }
        store.profiles.extend(subscription::merge(&[], fetched.profiles, &id));
        store.groups.push(Group { id: id.clone(), name: clean_name(&name).unwrap_or_else(|_| "Subscription".into()), subscription: Some(sub), sort_by_delay: false });
        store.fix_selection();
        Ok(SubscriptionResult { group_id: id, count, skipped })
    })
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

    edit_library(&state, |store| {
        let sub = store.group_mut(id).and_then(|g| g.subscription.as_mut()).ok_or("This group was removed during the update.")?;
        if sub.url != url { return Err("The subscription link changed during the update. Refresh it again.".into()); }
        let fetched = match fetched {
            Ok(fetched) => fetched,
            Err(error) => {
                sub.last_error = Some(error.clone());
                return Ok(Err(error));
            }
        };
        apply_fetched(sub, &fetched);
        let hidden = store.hidden_profiles.get(id).filter(|hidden| !hidden.is_empty());
        let fresh = fetched.profiles.into_iter().filter(|p| hidden.is_none_or(|hidden| !hidden.contains(&subscription::fingerprint(p)))).collect();
        let old: Vec<Profile> = store.profiles.iter().filter(|p| p.group_id == id).cloned().collect();
        let merged = subscription::merge(&old, fresh, id);
        let count = merged.len();
        store.profiles.retain(|p| p.group_id != id);
        store.profiles.extend(merged);
        store.fix_selection();
        Ok(Ok(SubscriptionResult { group_id: id.to_string(), count, skipped: fetched.skipped }))
    })?
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
async fn update_settings(app: AppHandle, patch: serde_json::Map<String, serde_json::Value>) -> Result<Settings, String> {
    let retry_absolute = patch.get("absoluteMode").and_then(serde_json::Value::as_bool) == Some(false);
    blocking(app, move |app, state| edit_settings(app, state, retry_absolute, |settings| {
        *settings = settings.patched(patch)?;
        Ok(())
    }))
    .await?
}

/// Checks, applies and saves new settings. Blocking: changing the kill switch or console
/// control can take a moment. Returns the cleaned-up version (e.g. canonical split tunnel
/// entries).
pub(crate) fn edit_settings(
    app: &AppHandle,
    state: &AppState,
    retry_absolute: bool,
    edit: impl FnOnce(&mut Settings) -> Result<(), String>,
) -> Result<Settings, String> {
    // Share the connection lock so no connect/disconnect observes a half-applied update.
    let _guard = state.switching.lock().unwrap();
    let mut settings = state.store.lock().unwrap().settings.clone();
    let previous = settings.clone();
    edit(&mut settings)?;
    settings.validate()?;
    settings.split.normalize()?;
    let (kill_switch_changed, console_changed) = {
        let store = state.store.lock().unwrap();
        (store.settings.kill_switch != settings.kill_switch, store.settings.console != settings.console)
    };
    let absolute_changed = previous.absolute_mode != settings.absolute_mode;
    if previous.absolute_mode && settings.absolute_mode
        && previous.absolute_browser_location != settings.absolute_browser_location
    {
        return Err("Turn off Absolute before changing its browser location protection.".into());
    }
    let recovery_pending = !previous.absolute_mode &&
        (absolute::marker(state).exists() || state.absolute.lock().unwrap().phase == "error");
    let release_absolute = !settings.absolute_mode && (absolute_changed || (retry_absolute && recovery_pending));
    if absolute_changed || release_absolute || (settings.absolute_mode && previous.absolute_timezone != settings.absolute_timezone) {
        if settings.absolute_mode {
            platform::elevate()?;
            if let Err(e) = connection::absolute_barrier(state, &settings, false)
                .map(|_| {
                    connection::teardown(state);
                    state.blocked.store(true, Ordering::SeqCst);
                })
                .and_then(|_| absolute::arm(state, &settings))
            {
                absolute::phase(state, "error", Some(e.clone()));
                return Err(e);
            }
        } else {
            // Keep the barrier until all system state has been restored successfully.
            if let Err(e) = connection::absolute_barrier(state, &settings, false) {
                absolute::phase(state, "error", Some(e.clone()));
                return Err(e);
            }
            connection::teardown(state);
            state.blocked.store(true, Ordering::SeqCst);
            if let Err(e) = absolute::restore_owned(state) {
                absolute::phase(state, "error", Some(e.clone()));
                return Err(e);
            }
        }
    } else if kill_switch_changed && !settings.absolute_mode && !recovery_pending {
        connection::apply_kill_switch(state, &settings)?;
    }
    if console_changed {
        console::apply(app, settings.console)?;
    }
    apply_window_settings(app, &settings);
    state.logs.lock().unwrap().set_limit(settings.log_lines as usize);
    let mut store = state.store.lock().unwrap();
    store.settings = settings.clone();
    if let Err(e) = store.save(&state.paths.store) {
        store.settings = previous;
        drop(store);
        if absolute_changed { absolute::phase(state,"error",Some("Settings could not be saved; traffic remains protected. Retry the change.".into())); }
        return Err(e);
    }
    drop(store);
    if release_absolute {
        if let Err(e) = firewall::disable() {
            absolute::phase(state, "error", Some(e.clone()));
            state.blocked.store(firewall::is_active(), Ordering::SeqCst);
            return Err(e);
        }
        absolute::phase(state, "off", None);
        state.blocked.store(firewall::is_active(),Ordering::SeqCst);
    }
    Ok(settings)
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
        connection::shutdown(state)?;
        app.exit(0);
        Ok(())
    })
    .await?
}

/// Running programs, for picking split tunnel apps.
#[tauri::command]
async fn running_apps() -> Result<Vec<platform::RunningApp>, String> {
    tauri::async_runtime::spawn_blocking(platform::running_apps).await.map_err(|e| e.to_string())
}

#[tauri::command]
fn hide_window(app: AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

/// The title bar is drawn by the window itself, so its buttons come here. Minimizing still goes
/// to the tray through the window event below.
#[tauri::command]
fn minimize_window(app: AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.minimize();
    }
}

/// Same as the system close button: asks first while connected.
#[tauri::command]
fn close_window(app: AppHandle) {
    tray::request_quit(&app);
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
        absolute: state.absolute.lock().unwrap().clone(),
        absolute_supported: cfg!(windows),
        session: state.link.lock().unwrap().as_ref().map(|l| l.session.clone()),
        firewall: firewall::is_active(),
        blocked: state.blocked.load(Ordering::SeqCst),
        xray_found: state.paths.xray().exists(),
        tun_found: state.paths.sing_box().exists(),
        elevated: platform::is_elevated(),
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
    platform::open_url(url)
}

/// Only on request: it asks several outside services, so it never runs on its own.
#[tauri::command]
async fn connection_info(app: AppHandle) -> Result<netinfo::Report, String> {
    let (target, generation) = blocking(app.clone(), |_, state| {
        let generation = state.generation.load(Ordering::SeqCst);
        connection::info_target(state).map(|target| (target, generation))
    }).await??;
    let report = netinfo::lookup(target).await?;
    if app.state::<AppState>().generation.load(Ordering::SeqCst) != generation {
        return Err("The connection changed during the IP check. Try again.".into());
    }
    Ok(report)
}

#[tauri::command]
fn get_logs(state: State<AppState>) -> Vec<String> {
    state.logs.lock().unwrap().all()
}

#[tauri::command]
fn clear_logs(state: State<AppState>) {
    state.logs.lock().unwrap().clear();
}

/// Tests the given profiles (all if `ids` is empty) and emits a `delay` event per result.
#[tauri::command]
async fn test_delays(app: AppHandle, ids: Vec<String>) -> Result<(), String> {
    run_delay_tests(&app, ids, |_| {}).await
}

/// Tests the given profiles (all if `ids` is empty). Each result is emitted as a `delay` event
/// for the window and handed to `on_result`.
pub(crate) async fn run_delay_tests(
    app: &AppHandle,
    ids: Vec<String>,
    on_result: impl Fn(&DelayResult) + Send + Sync + 'static,
) -> Result<(), String> {
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
    let on_result = Arc::new(on_result);
    let tasks: Vec<_> = profiles
        .into_iter()
        .map(|p| {
            let (app, exe, assets, target, limit) = (app.clone(), exe.clone(), assets.clone(), target.clone(), limit.clone());
            let on_result = on_result.clone();
            tauri::async_runtime::spawn(async move {
                let _permit = limit.acquire_owned().await;
                let id = p.id.clone();
                let prepared = if p.protocol == parser::Protocol::Wireguard && p.address.parse::<std::net::IpAddr>().is_err() {
                    blocking(app.clone(), move |_, state| {
                        connection::resolve_server(state, &p.address, p.port).map(|ip| connection::pin_address(&p, ip))
                    }).await.ok().and_then(Result::ok)
                } else { Some(p) };
                let ms = match prepared {
                    Some(profile) => delay::test(&exe, &assets, &profile, &target).await,
                    None => None,
                };
                let result = DelayResult { id, ms };
                on_result(&result);
                let _ = app.emit("delay", result);
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
    platform::relaunch_as_admin()?;
    // On Linux the app stays as it is: the helper is what needed starting.
    if cfg!(windows) {
        app.exit(0);
    }
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

/// Single-exe builds keep the store and proxy backup in `Program Files\Phi2ray\data\<account>`.
/// Phi2ray runs as administrator, and writing in the user's own AppData would let any program
/// running as that user redirect the writes with links. Under Program Files only administrators
/// can change anything; the store stays encrypted for the account (DPAPI) as before.
fn admin_data_dir(base: &Path) -> Option<PathBuf> {
    let dir = base.join("data").join(platform::current_user_sid()?);
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn find_core_dir(app: &AppHandle) -> PathBuf {
    let mut candidates = Vec::new();
    if let Ok(dir) = app.path().resource_dir() {
        candidates.push(dir.join("core"));
    }
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())) {
        candidates.push(dir.join("core"));
    }
    #[cfg(not(windows))]
    {
        candidates.insert(0, PathBuf::from("/usr/lib/phi2ray"));
        candidates.insert(1, PathBuf::from("/opt/phi2ray"));
        if let Some(app_dir) = std::env::var_os("APPDIR") {
            candidates.insert(2, PathBuf::from(app_dir).join("usr/lib/phi2ray"));
        }
    }
    #[cfg(debug_assertions)]
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("core"));

    let fallback = candidates.last().cloned().unwrap_or_else(|| PathBuf::from("core"));
    candidates.into_iter().find(|d| d.join(XRAY_EXE).exists()).unwrap_or(fallback)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    if absolute::watchdog_entry() { return; }
    // WebKitGTK draws an empty window with NVIDIA's driver unless this is off.
    #[cfg(not(windows))]
    if Path::new("/proc/driver/nvidia").exists() && std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
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
            let logs: Logs = Arc::new(Mutex::new(xray::LogBuf::default()));
            #[cfg(not(windows))]
            {
                helper::init(logs.clone());
                store::set_key_folder(paths.data.clone());
            }
            let mut legacy_marker = None;
            // Single-exe builds unpack their cores first; other builds use the core folder.
            // When unpacking fails they run no core at all: never one found next to the exe,
            // where anyone could have put it.
            let mut paths = paths;
            let core_error = match cores::target_dir() {
                None => None,
                Some(Ok(dir)) => {
                    if let Some(parent) = dir.parent() {
                        paths.work = parent.join("sing-box");
                        if let Some(secure) = admin_data_dir(parent) {
                            legacy_marker = Some(paths.proxy_marker.clone());
                            Store::migrate(&paths.store, &secure.join("store.bin"));
                            paths.store = secure.join("store.bin");
                            paths.proxy_marker = secure.join("proxy-backup.json");
                            paths.data = secure;
                        }
                    }
                    paths.core = dir;
                    cores::install(&paths.core).err()
                }
                Some(Err(e)) => Some(e),
            };
            if let Some(e) = &core_error {
                logs.lock().unwrap().push(format!("[app] {e}"));
            }
            // Recover the user's proxy settings if we crashed while connected (also from a backup
            // an earlier version left in the old data folder).
            for marker in legacy_marker.iter().chain([&paths.proxy_marker]) {
                if let Err(e) = proxy::restore(marker) {
                    logs.lock().unwrap().push(format!("[app] {e}"));
                }
            }
            // Kill switch rules left by a crash keep blocking until the user reconnects or unblocks.
            let blocked = firewall::recover();
            if blocked {
                logs.lock().unwrap().push(
                    "[app] Phi2ray closed unexpectedly while the kill switch was on. The internet stays blocked until you reconnect or unblock.".into(),
                );
            }
            let recovery_error = absolute::recover(&paths.data.join("absolute-backup.json")).err();
            let store = Store::load(&paths.store);
            let absolute_enabled = store.settings.absolute_mode;
            let core_error = core_error.or_else(|| {
                store.locked.then(|| "Your saved servers are locked. Unlock your keyring and restart Phi2ray.".to_string())
            });
            app.manage(AppState {
                absolute_guard: Mutex::new(None),
                absolute: Mutex::new(absolute::Status {phase: if recovery_error.is_some() {"error"} else if absolute_enabled {"armed"} else {"off"}.into(), error: recovery_error, ..Default::default()}),
                store: Mutex::new(store),
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
            if settings.absolute_mode {
                let state = app.state::<AppState>();
                if let Err(e) = connection::absolute_barrier(&state, &settings, false).and_then(|_| absolute::arm(&state, &settings)) {
                    absolute::phase(&state, "error", Some(e.clone()));
                    connection::log(&state, format!("[absolute] Startup protection failed: {e}"));
                    // Do not start ordinary connections after a failed protected startup.
                    state.store.lock().unwrap().settings.auto_connect = false;
                }
                state.blocked.store(firewall::is_active(), Ordering::SeqCst);
            }
            apply_window_settings(app.handle(), &settings);
            app.state::<AppState>().logs.lock().unwrap().set_limit(settings.log_lines as usize);
            tray::create(app.handle())?;
            console::startup(app.handle());
            // `phi2ray start` launches the app into the tray; otherwise the window opens.
            if !std::env::args().any(|a| a == "--hidden") {
                tray::show_window(app.handle());
            }
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
            update_profile,
            move_library_item,
            set_group_sort,
            export_library_item,
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
            minimize_window,
            close_window,
            running_apps
        ])
        .build(tauri::generate_context!())
        .expect("error while building Phi2ray")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(state) = app.try_state::<AppState>() {
                    if let Err(e) = connection::shutdown(&state) { connection::log(&state, format!("[absolute] Exit recovery failed: {e}")); }
                }
            }
        });
}
