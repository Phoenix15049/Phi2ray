//! Windows system proxy. The user's previous settings are saved to a marker file
//! before we change them, so they can be restored even after a crash.

use std::path::Path;

#[cfg(windows)]
mod imp {
    use std::fs;
    use std::path::Path;
    use std::ptr::null;

    use serde::{Deserialize, Serialize};
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

    #[derive(Default, Serialize, Deserialize)]
    struct Saved {
        enable: u32,
        server: String,
        overrides: String,
    }

    fn open() -> Result<RegKey, String> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(KEY, KEY_READ | KEY_WRITE)
            .map_err(|e| format!("cannot open proxy settings: {e}"))
    }

    pub fn enable(port: u16, marker: &Path) -> Result<(), String> {
        let key = open()?;
        if !marker.exists() {
            let saved = Saved {
                enable: key.get_value("ProxyEnable").unwrap_or(0),
                server: key.get_value("ProxyServer").unwrap_or_default(),
                overrides: key.get_value("ProxyOverride").unwrap_or_default(),
            };
            // Written to a temporary file and renamed, so a crash can't leave half a backup.
            let tmp = marker.with_extension("tmp");
            fs::write(&tmp, serde_json::to_vec(&saved).unwrap()).map_err(|e| e.to_string())?;
            fs::rename(&tmp, marker).map_err(|e| e.to_string())?;
        }
        let err = |e: std::io::Error| format!("cannot set system proxy: {e}");
        key.set_value("ProxyServer", &format!("127.0.0.1:{port}")).map_err(err)?;
        key.set_value("ProxyOverride", &BYPASS.to_string()).map_err(err)?;
        key.set_value("ProxyEnable", &1u32).map_err(err)?;
        notify();
        Ok(())
    }

    pub fn restore(marker: &Path) -> Result<(), String> {
        let Ok(bytes) = fs::read(marker) else { return Ok(()) };
        let key = open()?;
        let Ok(saved) = serde_json::from_slice::<Saved>(&bytes) else {
            // The backup is unreadable, so the earlier settings are unknown. Undo only what is
            // certainly ours (a proxy on this computer) and leave everything else alone.
            let server: String = key.get_value("ProxyServer").unwrap_or_default();
            if server.starts_with("127.0.0.1:") {
                key.set_value("ProxyEnable", &0u32).map_err(|e| format!("cannot restore system proxy: {e}"))?;
                notify();
            }
            let _ = fs::remove_file(marker);
            return Err(
                "The saved proxy settings were damaged, so only Phi2ray's own proxy was turned off. \
                 Check the proxy settings in Windows."
                    .into(),
            );
        };
        let err = |e: std::io::Error| format!("cannot restore system proxy: {e}");
        key.set_value("ProxyEnable", &saved.enable).map_err(err)?;
        key.set_value("ProxyServer", &saved.server).map_err(err)?;
        key.set_value("ProxyOverride", &saved.overrides).map_err(err)?;
        notify();
        fs::remove_file(marker).map_err(|e| e.to_string())
    }

    /// Tells WinINet-based apps (browsers, etc.) to reload proxy settings.
    fn notify() {
        unsafe {
            InternetSetOptionW(null(), INTERNET_OPTION_SETTINGS_CHANGED, null(), 0);
            InternetSetOptionW(null(), INTERNET_OPTION_REFRESH, null(), 0);
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    pub fn enable(_port: u16, _marker: &Path) -> Result<(), String> {
        Err("system proxy is only supported on Windows for now".into())
    }

    pub fn restore(_marker: &Path) -> Result<(), String> {
        Ok(())
    }
}

pub fn enable(port: u16, marker: &Path) -> Result<(), String> {
    imp::enable(port, marker)
}

pub fn restore(marker: &Path) -> Result<(), String> {
    imp::restore(marker)
}
