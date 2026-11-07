//! The system proxy on Linux. There is no single setting: GNOME and the desktops built on it keep
//! theirs in GSettings, and KDE in `kioslaverc`. Browsers read the one that matches the desktop,
//! so both are set where they exist. The app runs as the user, as these settings expect.

use std::fs;
use std::path::Path;
use std::process::Stdio;

use serde::{Deserialize, Serialize};

use crate::platform::host_command;

const GNOME: &str = "org.gnome.system.proxy";
/// Keys saved and restored, as (schema, key). Values are kept in GSettings' own text form.
const GNOME_KEYS: [(&str, &str); 8] = [
    (GNOME, "mode"),
    (GNOME, "ignore-hosts"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
];
/// Only this computer skips the proxy, as on Windows.
const IGNORE_HOSTS: &str = "['localhost', '127.0.0.0/8', '::1']";

const KDE_GROUP: &str = "Proxy Settings";
const KDE_KEYS: [&str; 5] = ["ProxyType", "httpProxy", "httpsProxy", "socksProxy", "NoProxyFor"];

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    /// Values of `GNOME_KEYS`, in order. Empty when this desktop doesn't have them.
    gnome: Vec<String>,
    /// Values of `KDE_KEYS`, in order.
    kde: Vec<String>,
    /// The proxy port Phi2ray set, to tell whether the settings are still ours.
    ours: u16,
}

fn gsettings(args: &[&str]) -> Option<String> {
    let out = host_command("gsettings").args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn has_gnome() -> bool {
    gsettings(&["writable", GNOME, "mode"]).as_deref() == Some("true")
}

/// `kwriteconfig6` on Plasma 6, `kwriteconfig5` before it.
fn kde_tool(kind: &str) -> Option<String> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    if !desktop.to_ascii_uppercase().contains("KDE") {
        return None;
    }
    ["6", "5"].into_iter().map(|v| format!("k{kind}config{v}")).find(|tool| {
        host_command(tool).arg("--help").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
    })
}

fn kde_read(tool: &str, key: &str) -> String {
    host_command(tool)
        .args(["--file", "kioslaverc", "--group", KDE_GROUP, "--key", key])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

fn kde_write(tool: &str, key: &str, value: &str) -> Result<(), String> {
    let status = host_command(tool)
        .args(["--file", "kioslaverc", "--group", KDE_GROUP, "--key", key, value])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{tool} failed ({status})"))
    }
}

/// Tells running KDE programs to read the settings again.
fn kde_notify() {
    let _ = host_command("dbus-send")
        .args(["--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn read_marker(marker: &Path) -> Option<Saved> {
    serde_json::from_slice(&fs::read(marker).ok()?).ok()
}

fn write_marker(marker: &Path, saved: &Saved) -> Result<(), String> {
    crate::platform::check_write_target(marker)?;
    // Written to a temporary file and renamed, so a crash can't leave half a backup.
    let tmp = marker.with_extension("tmp");
    crate::platform::check_write_target(&tmp)?;
    fs::write(&tmp, serde_json::to_vec(saved).unwrap()).map_err(|e| e.to_string())?;
    fs::rename(&tmp, marker).map_err(|e| e.to_string())
}

pub fn enable(port: u16, marker: &Path) -> Result<(), String> {
    let gnome = has_gnome();
    let kde = kde_tool("read").zip(kde_tool("write"));
    if !gnome && kde.is_none() {
        return Err("This desktop has no system proxy setting Phi2ray can change. Use VPN or Proxy only mode.".into());
    }
    // A backup left by a crash still holds the user's own settings: keep it.
    let mut saved = read_marker(marker).unwrap_or_else(|| Saved {
        gnome: if gnome {
            GNOME_KEYS.iter().map(|(schema, key)| gsettings(&["get", schema, key]).unwrap_or_default()).collect()
        } else {
            Vec::new()
        },
        kde: kde.as_ref().map_or_else(Vec::new, |(read, _)| KDE_KEYS.iter().map(|key| kde_read(read, key)).collect()),
        ours: 0,
    });
    saved.ours = port;
    write_marker(marker, &saved)?;

    if gnome {
        let port = port.to_string();
        // Manual: automatic detection and setup scripts are off, since a fake one on the network
        // could send traffic around the proxy. There is no password on the HTTP port, and SOCKS
        // needs one these settings can't hold, so only HTTP is set.
        for (schema, key, value) in [
            ("org.gnome.system.proxy.http", "host", "127.0.0.1"),
            ("org.gnome.system.proxy.http", "port", port.as_str()),
            ("org.gnome.system.proxy.https", "host", "127.0.0.1"),
            ("org.gnome.system.proxy.https", "port", port.as_str()),
            ("org.gnome.system.proxy.socks", "host", ""),
            (GNOME, "ignore-hosts", IGNORE_HOSTS),
            (GNOME, "mode", "manual"),
        ] {
            gsettings(&["set", schema, key, value]).ok_or("cannot set the system proxy")?;
        }
    }
    if let Some((_, write)) = &kde {
        let address = format!("http://127.0.0.1:{port}");
        for (key, value) in [
            ("httpProxy", address.as_str()),
            ("httpsProxy", address.as_str()),
            ("socksProxy", ""),
            ("NoProxyFor", "localhost,127.0.0.0/8,::1"),
            ("ProxyType", "1"),
        ] {
            kde_write(write, key, value).map_err(|e| format!("cannot set the system proxy: {e}"))?;
        }
        kde_notify();
    }
    Ok(())
}

pub fn restore(marker: &Path) -> Result<(), String> {
    let Ok(bytes) = fs::read(marker) else { return Ok(()) };
    let Ok(saved) = serde_json::from_slice::<Saved>(&bytes) else {
        // The backup is unreadable, so the earlier settings are unknown. Undo only what is
        // certainly ours (a proxy on this computer) and leave everything else alone.
        if gsettings(&["get", "org.gnome.system.proxy.http", "host"]).as_deref() == Some("'127.0.0.1'") {
            let _ = gsettings(&["set", GNOME, "mode", "none"]);
        }
        let _ = fs::remove_file(marker);
        return Err("The saved proxy settings were damaged, so only Phi2ray's own proxy was turned off. Check your proxy settings.".into());
    };

    let mut changed = false;
    if saved.gnome.len() == GNOME_KEYS.len() {
        let current = gsettings(&["get", "org.gnome.system.proxy.http", "port"]);
        if current.as_deref() == Some(saved.ours.to_string().as_str()) {
            // The mode comes back last, so nothing uses a half-restored proxy.
            for ((schema, key), value) in GNOME_KEYS.iter().zip(&saved.gnome).skip(1) {
                let _ = gsettings(&["set", schema, key, value]);
            }
            gsettings(&["set", GNOME, "mode", &saved.gnome[0]]).ok_or("cannot restore the system proxy")?;
        } else {
            changed = true;
        }
    }
    if saved.kde.len() == KDE_KEYS.len() {
        if let Some((read, write)) = kde_tool("read").zip(kde_tool("write")) {
            if kde_read(&read, "httpProxy") == format!("http://127.0.0.1:{}", saved.ours) {
                for (key, value) in KDE_KEYS.iter().zip(&saved.kde).rev() {
                    kde_write(&write, key, value).map_err(|e| format!("cannot restore the system proxy: {e}"))?;
                }
                kde_notify();
            } else {
                changed = true;
            }
        }
    }
    fs::remove_file(marker).map_err(|e| e.to_string())?;
    if changed {
        // Someone set another proxy since Phi2ray set its own: their choice stays.
        return Err("The proxy settings were changed by another program, so they were left as they are.".into());
    }
    Ok(())
}
