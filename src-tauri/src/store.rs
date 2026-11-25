//! Profiles and settings, saved encrypted for the current user: with DPAPI on Windows, and with a
//! key in the desktop's keyring on Linux (`vault_linux.rs`).

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::parser::Profile;
use crate::split::SplitTunnel;
use crate::subscription::Subscription;

/// Bump when a default changes in a way existing users should get.
const SETTINGS_VERSION: u32 = 2;

/// The key exists but can't be reached right now (a locked or missing keyring). The store isn't
/// damaged, so it must be left alone. Windows never reports this.
const KEY_UNAVAILABLE: &str = "KEY_UNAVAILABLE";

/// The built-in group for servers added by hand. It can be renamed but not deleted.
pub const DEFAULT_GROUP: &str = "default";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub name: String,
    /// Set for subscription groups; their servers are replaced on every update.
    #[serde(default)]
    pub subscription: Option<Subscription>,
    #[serde(default)]
    pub sort_by_delay: bool,
}

impl Group {
    fn default_group() -> Self {
        Self { id: DEFAULT_GROUP.into(), name: "My servers".into(), subscription: None, sort_by_delay: false }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Whole-system VPN through a TUN adapter.
    #[default]
    Tun,
    /// The system's proxy setting.
    System,
    /// Only local SOCKS/HTTP ports.
    Manual,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    #[serde(default)]
    pub version: u32,
    pub mode: Mode,
    pub selected: Option<String>,
    pub auto_connect: bool,
    /// Seconds to wait for the initial server probe; None keeps automatic health checks.
    pub connect_timeout: Option<u16>,

    // Protection
    /// Block all traffic outside the connection while connected or reconnecting.
    pub kill_switch: bool,
    pub absolute_mode: bool,
    pub absolute_browser_location: bool,
    /// Empty means derive the IANA zone from the VPN exit; otherwise an explicit override.
    pub absolute_timezone: String,
    /// Recover from drops without tearing the tunnel down.
    pub auto_reconnect: bool,

    // Routing
    pub bypass_lan: bool,
    pub iran_direct: bool,
    pub block_ads: bool,
    /// Reject QUIC (UDP 443) so browsers use TCP, which tunnels far better over TCP-based proxies.
    pub block_quic: bool,
    pub split: SplitTunnel,

    // DNS (VPN mode)
    pub remote_dns: String,
    pub ipv6: bool,

    // VPN adapter
    pub tun_stack: String,
    pub tun_mtu: u32,
    pub strict_route: bool,

    // Local proxy ports
    pub fixed_ports: bool,
    pub socks_port: u16,
    pub http_port: u16,

    // Diagnostics
    pub log_level: String,
    /// How many log lines are kept in memory.
    pub log_lines: u32,
    pub test_url: String,

    // Appearance and window
    /// "en" or "fa".
    pub language: String,
    /// "system", "light" or "dark".
    pub theme: String,
    pub always_on_top: bool,
    pub minimize_to_tray: bool,

    /// The `phi2ray` console command: on PATH, and the running app takes its commands.
    pub console: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: SETTINGS_VERSION,
            mode: Mode::Tun,
            selected: None,
            auto_connect: false,
            connect_timeout: None,
            kill_switch: true,
            absolute_mode: false,
            absolute_browser_location: false,
            absolute_timezone: String::new(),
            auto_reconnect: true,
            bypass_lan: true,
            iran_direct: false,
            block_ads: false,
            block_quic: true,
            split: SplitTunnel::default(),
            remote_dns: "https://1.1.1.1/dns-query".into(),
            ipv6: false,
            tun_stack: "mixed".into(),
            tun_mtu: 9000,
            strict_route: true,
            fixed_ports: false,
            socks_port: 10808,
            http_port: 10809,
            log_level: "warning".into(),
            log_lines: 1000,
            test_url: "http://www.gstatic.com/generate_204".into(),
            language: "en".into(),
            theme: "system".into(),
            always_on_top: false,
            // Some Linux desktops show no tray icons, and a hidden window would seem lost there.
            minimize_to_tray: cfg!(windows),
            console: false,
        }
    }
}

impl Settings {
    /// Applies only the fields the caller edited, keeping other callers' newer settings.
    pub fn patched(&self, patch: serde_json::Map<String, serde_json::Value>) -> Result<Self, String> {
        let mut value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        let fields = value.as_object_mut().ok_or("Invalid settings.")?;
        for (key, value) in patch {
            let field = fields.get_mut(&key).ok_or_else(|| format!("Unknown setting: {key}"))?;
            *field = value;
        }
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.absolute_mode && !cfg!(windows) { return Err("Absolute mode is currently available on Windows only.".into()); }
        if !self.absolute_timezone.is_empty() { crate::absolute::windows_zone(&self.absolute_timezone)?; }
        if self.connect_timeout.is_some_and(|seconds| !(5..=120).contains(&seconds)) {
            return Err("Connection timeout must be between 5 and 120 seconds.".into());
        }
        if !matches!(self.tun_stack.as_str(), "mixed" | "system" | "gvisor") {
            return Err("Unknown network stack.".into());
        }
        if !(1280..=9000).contains(&self.tun_mtu) {
            return Err("MTU must be between 1280 and 9000.".into());
        }
        if !matches!(self.log_level.as_str(), "warning" | "info" | "debug") {
            return Err("Unknown log level.".into());
        }
        if !(100..=5000).contains(&self.log_lines) {
            return Err("Log length must be between 100 and 5000 lines.".into());
        }
        if !matches!(self.language.as_str(), "en" | "fa") {
            return Err("Unknown language.".into());
        }
        if !matches!(self.theme.as_str(), "system" | "light" | "dark") {
            return Err("Unknown theme.".into());
        }
        if self.fixed_ports {
            if self.socks_port < 1024 || self.http_port < 1024 {
                return Err("Ports must be 1024 or higher.".into());
            }
            if self.socks_port == self.http_port {
                return Err("SOCKS and HTTP ports must be different.".into());
            }
        }
        self.split.clone().normalize()?;
        crate::tun::dns_server(&self.remote_dns)?;
        crate::delay::TestTarget::parse(&self.test_url)?;
        Ok(())
    }

    fn migrate(&mut self) {
        if self.version < 1 {
            // "Iranian sites direct" used to be on by default; it is now opt-in.
            self.iran_direct = false;
        }
        if self.version < 2 {
            // Leak protection and QUIC blocking are now on by default.
            self.kill_switch = true;
            self.block_quic = true;
        }
        self.version = SETTINGS_VERSION;
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Store {
    pub groups: Vec<Group>,
    pub profiles: Vec<Profile>,
    pub settings: Settings,
    /// Provider entries removed by the user, keyed by group and connection fingerprint.
    pub hidden_profiles: std::collections::HashMap<String, std::collections::HashSet<String>>,
    /// Last good IP of each server address. Reconnecting still works when DNS can't be
    /// reached, for example while the kill switch holds the internet blocked after a crash.
    pub resolved: std::collections::HashMap<String, std::net::IpAddr>,
    /// When each address in `resolved` was last confirmed (Unix seconds).
    pub resolved_at: std::collections::HashMap<String, u64>,
    /// The saved store exists but its key can't be reached, so nothing may overwrite it.
    #[serde(skip)]
    pub locked: bool,
}

impl Store {
    pub fn load(path: &Path) -> Self {
        let Ok(bytes) = fs::read(path) else { return Self::fresh() };
        match vault::unprotect(&bytes).and_then(|b| serde_json::from_slice::<Store>(&b).map_err(|e| e.to_string())) {
            Err(e) if e == KEY_UNAVAILABLE => Self { locked: true, ..Self::fresh() },
            Ok(mut store) => {
                store.settings.migrate();
                if store.settings.validate().is_err() {
                    let selected = store.settings.selected.take();
                    store.settings = Settings { selected, ..Settings::default() };
                }
                store.repair_groups();
                store
            }
            Err(_) => {
                // Keep the unreadable file instead of silently overwriting it (or an older backup).
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _ = fs::rename(path, path.with_extension(format!("{stamp}.bak")));
                Self::fresh()
            }
        }
    }

    /// Copies a store from an earlier location into `new`, once (only while `new` doesn't exist).
    /// The old file is only read, and only a store that decrypts and parses is carried over;
    /// nothing at the old location is renamed or deleted.
    pub fn migrate(old: &Path, new: &Path) {
        if new.exists() {
            return;
        }
        let Ok(bytes) = fs::read(old) else { return };
        if let Ok(store) = vault::unprotect(&bytes).and_then(|b| serde_json::from_slice::<Store>(&b).map_err(|e| e.to_string())) {
            let _ = store.save(new);
        }
    }

    fn fresh() -> Self {
        Self { groups: vec![Group::default_group()], ..Self::default() }
    }

    /// Makes sure the default group exists and every server belongs to an existing group
    /// (stores from before groups existed have none).
    fn repair_groups(&mut self) {
        if !self.groups.iter().any(|g| g.id == DEFAULT_GROUP) {
            self.groups.insert(0, Group::default_group());
        }
        // Stores from earlier versions may have http subscriptions set to update by themselves.
        for sub in self.groups.iter_mut().filter_map(|g| g.subscription.as_mut()) {
            sub.enforce_policy();
        }
        for p in &mut self.profiles {
            if !self.groups.iter().any(|g| g.id == p.group_id) {
                p.group_id = DEFAULT_GROUP.into();
            }
        }
    }

    pub fn group(&self, id: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.id == id)
    }

    pub fn group_mut(&mut self, id: &str) -> Option<&mut Group> {
        self.groups.iter_mut().find(|g| g.id == id)
    }

    /// Keeps the selection valid after servers were removed.
    pub fn fix_selection(&mut self) {
        let valid = self.settings.selected.as_ref().is_some_and(|id| self.profiles.iter().any(|p| &p.id == id));
        if !valid {
            self.settings.selected = self.profiles.first().map(|p| p.id.clone());
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if self.locked {
            return Err("Your saved servers are locked. Unlock your keyring and restart Phi2ray.".into());
        }
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("tmp");
        crate::platform::check_write_target(path)?;
        crate::platform::check_write_target(&tmp)?;
        fs::write(&tmp, vault::protect(&json)?).map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| e.to_string())
    }
}

#[cfg(windows)]
mod vault {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB};

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        run(data, true)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        run(data, false)
    }

    fn run(data: &[u8], encrypt: bool) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
        let ok = unsafe {
            if encrypt {
                CryptProtectData(&input, null(), null(), null(), null(), 0, &mut output)
            } else {
                CryptUnprotectData(&input, null_mut(), null(), null(), null(), 0, &mut output)
            }
        };
        if ok == 0 {
            return Err("DPAPI failed".into());
        }
        let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { LocalFree(output.pbData as _) };
        Ok(bytes)
    }
}

#[cfg(not(windows))]
#[path = "vault_linux.rs"]
mod vault;

#[cfg(not(windows))]
pub use vault::set_folder as set_key_folder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_settings_keep_other_edits_and_reject_bad_fields() {
        let patch = |value: serde_json::Value| value.as_object().unwrap().clone();
        let settings = Settings::default().patched(patch(serde_json::json!({ "console": true }))).unwrap();
        let settings = settings.patched(patch(serde_json::json!({ "theme": "dark", "killSwitch": false }))).unwrap();
        assert!(settings.console);
        assert_eq!(settings.theme, "dark");
        assert!(!settings.kill_switch);
        assert!(settings.auto_reconnect);
        settings.validate().unwrap();
        assert!(settings.patched(patch(serde_json::json!({ "killSwitch": "off" }))).is_err());
        assert!(settings.patched(patch(serde_json::json!({ "killSwtich": false }))).is_err());
        let invalid = settings.patched(patch(serde_json::json!({ "tunMtu": 100 }))).unwrap();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn old_settings_turn_iran_direct_off() {
        let mut s: Settings = serde_json::from_str(r#"{"mode":"tun","iranDirect":true}"#).unwrap();
        assert_eq!(s.version, 0);
        s.migrate();
        assert!(!s.iran_direct);
        assert!(s.bypass_lan);
        assert!(s.kill_switch);
        assert_eq!(s.version, SETTINGS_VERSION);
    }

    #[test]
    fn old_stores_get_a_default_group() {
        let mut store: Store = serde_json::from_str(
            r#"{"profiles":[{"id":"1","name":"a","protocol":"trojan","address":"a.com","port":443,
            "secret":"pw","method":"","flow":"","alterId":0,"stream":{}}]}"#,
        )
        .unwrap();
        store.repair_groups();
        assert_eq!(store.groups[0].id, DEFAULT_GROUP);
        assert_eq!(store.profiles[0].group_id, DEFAULT_GROUP);
    }

    #[test]
    fn defaults_are_valid() {
        Settings::default().validate().unwrap();
        let bad = Settings { tun_mtu: 100, ..Settings::default() };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn connection_timeout_defaults_to_automatic_and_has_bounds() {
        let settings: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(settings.connect_timeout, None);
        for seconds in [5, 30, 120] {
            assert!(Settings { connect_timeout: Some(seconds), ..Settings::default() }.validate().is_ok());
        }
        for seconds in [0, 4, 121] {
            assert!(Settings { connect_timeout: Some(seconds), ..Settings::default() }.validate().is_err());
        }
    }
}
