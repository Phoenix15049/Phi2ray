//! System tray icon: shows the connection state and offers connect/disconnect,
//! open and quit. Minimizing the window hides it here.

use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::connection::{self, LinkState};
use crate::AppState;

const TRAY_ID: &str = "main";

struct Tray {
    status: MenuItem<Wry>,
    toggle: MenuItem<Wry>,
    show: MenuItem<Wry>,
    quit: MenuItem<Wry>,
    /// Last texts applied, so the menu is only touched when something changed.
    shown: Mutex<Option<Texts>>,
}

#[derive(Clone, PartialEq)]
struct Texts {
    status: String,
    toggle: &'static str,
    show: &'static str,
    quit: &'static str,
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "Phi2ray", false, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Connect", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Open Phi2ray", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[&status, &PredefinedMenuItem::separator(app)?, &toggle, &show, &PredefinedMenuItem::separator(app)?, &quit],
    )?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Phi2ray")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "toggle" => toggle_connection(app),
            "show" => show_window(app),
            "quit" => request_quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;

    app.manage(Tray { status, toggle, show, quit, shown: Mutex::new(None) });
    let app = app.clone();
    thread::spawn(move || loop {
        refresh(&app);
        thread::sleep(Duration::from_secs(1));
    });
    Ok(())
}

pub fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Quitting while connected asks the user first (in the window); otherwise it just quits.
pub fn request_quit(app: &AppHandle) {
    let state = app.state::<AppState>();
    let connected = state.link.lock().unwrap().is_some();
    if connected || state.blocked.load(std::sync::atomic::Ordering::SeqCst) {
        show_window(app);
        let _ = app.emit("close-requested", ());
    } else {
        app.exit(0);
    }
}

fn toggle_connection(app: &AppHandle) {
    let app = app.clone();
    thread::spawn(move || {
        let state = app.state::<AppState>();
        let connected = state.link.lock().unwrap().is_some();
        if connected {
            connection::disconnect(&state);
        } else {
            let selected = state.store.lock().unwrap().settings.selected.clone();
            let result = match selected {
                Some(id) => connection::connect(&app, &state, &id).map(drop),
                None => Err("Add a server first.".to_string()),
            };
            if let Err(e) = result {
                // The window explains the problem (and offers a restart as administrator).
                show_window(&app);
                let _ = app.emit("connect-error", e);
            }
        }
        let _ = app.emit("state-changed", ());
        refresh(&app);
    });
}

fn refresh(app: &AppHandle) {
    let state = app.state::<AppState>();
    let tray = app.state::<Tray>();
    let persian = state.store.lock().unwrap().settings.language == "fa";
    let link_state = state.link.lock().unwrap().as_ref().map(|l| l.session.state);
    let server = link_state.and_then(|_| {
        let id = state.link.lock().unwrap().as_ref()?.session.profile_id.clone();
        let store = state.store.lock().unwrap();
        store.profiles.iter().find(|p| p.id == id).map(|p| p.name.chars().take(32).collect::<String>())
    });

    let label = |en: &'static str, fa: &'static str| if persian { fa } else { en };
    let status = match (link_state, server) {
        (Some(LinkState::Connected), Some(name)) => format!("{} · {name}", label("Connected", "متصل")),
        (Some(LinkState::Connected), None) => label("Connected", "متصل").to_string(),
        (Some(LinkState::Reconnecting), _) => label("Reconnecting…", "در حال اتصال مجدد…").to_string(),
        (None, _) => label("Not connected", "متصل نیست").to_string(),
    };
    let texts = Texts {
        status,
        toggle: if link_state.is_some() { label("Disconnect", "قطع اتصال") } else { label("Connect", "اتصال") },
        show: label("Open Phi2ray", "باز کردن Phi2ray"),
        quit: label("Quit", "خروج"),
    };

    let mut shown = tray.shown.lock().unwrap();
    if shown.as_ref() == Some(&texts) {
        return;
    }
    let _ = tray.status.set_text(&texts.status);
    let _ = tray.toggle.set_text(texts.toggle);
    let _ = tray.show.set_text(texts.show);
    let _ = tray.quit.set_text(texts.quit);
    if let Some(icon) = app.tray_by_id(TRAY_ID) {
        let _ = icon.set_tooltip(Some(format!("Phi2ray — {}", texts.status)));
    }
    *shown = Some(texts);
}
