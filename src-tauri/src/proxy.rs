//! Windows system proxy. The user's previous settings are saved to a marker file
//! before we change them, so they can be restored even after a crash.

use std::path::Path;

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::fs;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use serde::{Deserialize, Serialize};
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::Networking::WinInet::{
        InternetQueryOptionW, InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_REFRESH,
        INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTIONW,
        INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER,
    };
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    /// Only this computer skips the proxy. Wildcards like `10.*` would also match host names
    /// such as `10.example.com`, which a web page could use to reach out without the proxy.
    /// Local network addresses still connect directly through xray's own LAN rule.
    const BYPASS: &str = "localhost;127.0.0.1;[::1];<local>";

    const PROXY_TYPE_DIRECT: u32 = 0x1;
    const PROXY_TYPE_PROXY: u32 = 0x2;

    #[derive(Default, Serialize, Deserialize)]
    #[serde(default)]
    struct Saved {
        enable: u32,
        server: String,
        overrides: String,
        /// The connection flags before Phi2ray (automatic detection, setup script, proxy).
        /// Missing in backups from earlier versions, which didn't change them.
        flags: Option<u32>,
        /// The proxy address Phi2ray set, to tell whether the settings are still ours.
        ours: String,
    }

    fn open() -> Result<RegKey, String> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(KEY, KEY_READ | KEY_WRITE)
            .map_err(|e| format!("cannot open proxy settings: {e}"))
    }

    fn read_marker(marker: &Path) -> Option<Saved> {
        serde_json::from_slice(&fs::read(marker).ok()?).ok()
    }

    fn write_marker(marker: &Path, saved: &Saved) -> Result<(), String> {
        crate::win::check_write_target(marker)?;
        // Written to a temporary file and renamed, so a crash can't leave half a backup.
        let tmp = marker.with_extension("tmp");
        crate::win::check_write_target(&tmp)?;
        fs::write(&tmp, serde_json::to_vec(saved).unwrap()).map_err(|e| e.to_string())?;
        fs::rename(&tmp, marker).map_err(|e| e.to_string())
    }

    pub fn enable(port: u16, marker: &Path) -> Result<(), String> {
        let key = open()?;
        // A backup left by a crash still holds the user's own settings: keep it.
        let mut saved = read_marker(marker).unwrap_or_else(|| Saved {
            enable: key.get_value("ProxyEnable").unwrap_or(0),
            server: key.get_value("ProxyServer").unwrap_or_default(),
            overrides: key.get_value("ProxyOverride").unwrap_or_default(),
            flags: query_flags(),
            ours: String::new(),
        });
        saved.ours = format!("127.0.0.1:{port}");
        write_marker(marker, &saved)?;
        // Proxy only: automatic detection (WPAD) and setup scripts (PAC) are switched off, since
        // Windows asks them first and a fake one on the network could send traffic around us.
        set(PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY, &saved.ours, BYPASS).map_err(|e| format!("cannot set system proxy: {e}"))
    }

    pub fn restore(marker: &Path) -> Result<(), String> {
        let Ok(bytes) = fs::read(marker) else { return Ok(()) };
        let key = open()?;
        let current = query_text(INTERNET_PER_CONN_PROXY_SERVER).unwrap_or_else(|| key.get_value("ProxyServer").unwrap_or_default());
        let Ok(saved) = serde_json::from_slice::<Saved>(&bytes) else {
            // The backup is unreadable, so the earlier settings are unknown. Undo only what is
            // certainly ours (a proxy on this computer) and leave everything else alone.
            if current.starts_with("127.0.0.1:") {
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
        if !saved.ours.is_empty() && query_text(INTERNET_PER_CONN_PROXY_SERVER).is_some_and(|s| s != saved.ours) {
            // Someone set another proxy since Phi2ray set its own: their choice stays.
            let _ = fs::remove_file(marker);
            return Err("The Windows proxy settings were changed by another program, so they were left as they are.".into());
        }
        let err = |e: String| format!("cannot restore system proxy: {e}");
        match saved.flags {
            Some(saved_flags) => {
                // If automatic detection or a setup script was switched on meanwhile (by the user
                // or another program), that stays; only Phi2ray's own proxy is taken back.
                let flags = match query_flags() {
                    Some(now) if now & 0xF != PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY => {
                        (now & !PROXY_TYPE_PROXY) | (saved_flags & PROXY_TYPE_PROXY)
                    }
                    _ => saved_flags,
                };
                set(flags, &saved.server, &saved.overrides).map_err(err)?
            }
            None => {
                let err = |e: std::io::Error| err(e.to_string());
                key.set_value("ProxyEnable", &saved.enable).map_err(err)?;
                key.set_value("ProxyServer", &saved.server).map_err(err)?;
                key.set_value("ProxyOverride", &saved.overrides).map_err(err)?;
                notify();
            }
        }
        fs::remove_file(marker).map_err(|e| e.to_string())
    }

    /// The LAN connection's flags, or None if they can't be read.
    fn query_flags() -> Option<u32> {
        let mut option: INTERNET_PER_CONN_OPTIONW = unsafe { std::mem::zeroed() };
        option.dwOption = INTERNET_PER_CONN_FLAGS;
        let mut list = option_list(std::slice::from_mut(&mut option));
        let mut size = list.dwSize;
        let ok = unsafe {
            InternetQueryOptionW(null(), INTERNET_OPTION_PER_CONNECTION_OPTION, &mut list as *mut _ as *mut c_void, &mut size)
        };
        (ok != 0).then(|| unsafe { option.Value.dwValue })
    }

    /// A text setting of the LAN connection (proxy address or bypass list), as WinINet sees it.
    fn query_text(which: u32) -> Option<String> {
        let mut option: INTERNET_PER_CONN_OPTIONW = unsafe { std::mem::zeroed() };
        option.dwOption = which;
        let mut list = option_list(std::slice::from_mut(&mut option));
        let mut size = list.dwSize;
        let ok = unsafe {
            InternetQueryOptionW(null(), INTERNET_OPTION_PER_CONNECTION_OPTION, &mut list as *mut _ as *mut c_void, &mut size)
        };
        if ok == 0 {
            return None;
        }
        let raw = unsafe { option.Value.pszValue };
        if raw.is_null() {
            return Some(String::new());
        }
        let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        let server = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
        unsafe { GlobalFree(raw as _) };
        Some(server)
    }

    /// Sets the LAN connection's flags, proxy and bypass list in one step, then tells apps.
    fn set(flags: u32, server: &str, bypass: &str) -> Result<(), String> {
        let mut server = wide(server);
        let mut bypass = wide(bypass);
        let mut options: [INTERNET_PER_CONN_OPTIONW; 3] = unsafe { std::mem::zeroed() };
        options[0].dwOption = INTERNET_PER_CONN_FLAGS;
        options[0].Value.dwValue = flags;
        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        options[1].Value.pszValue = server.as_mut_ptr();
        options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        options[2].Value.pszValue = bypass.as_mut_ptr();
        let list = option_list(&mut options);
        let ok = unsafe {
            InternetSetOptionW(null(), INTERNET_OPTION_PER_CONNECTION_OPTION, &list as *const _ as *const c_void, list.dwSize)
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        notify();
        Ok(())
    }

    /// Options for the LAN connection (no dial-up entry name).
    fn option_list(options: &mut [INTERNET_PER_CONN_OPTIONW]) -> INTERNET_PER_CONN_OPTION_LISTW {
        let mut list: INTERNET_PER_CONN_OPTION_LISTW = unsafe { std::mem::zeroed() };
        list.dwSize = std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32;
        list.pszConnection = null_mut();
        list.dwOptionCount = options.len() as u32;
        list.pOptions = options.as_mut_ptr();
        list
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
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
