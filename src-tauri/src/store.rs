//! Profiles and settings, saved encrypted with Windows DPAPI (bound to the current user).

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::parser::Profile;
use crate::split::SplitTunnel;
use crate::subscription::Subscription;

/// Bump when a default changes in a way existing users should get.
const SETTINGS_VERSION: u32 = 2;

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
}

impl Group {
    fn default_group() -> Self {
        Self { id: DEFAULT_GROUP.into(), name: "My servers".into(), subscription: None }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Whole-system VPN through a TUN adapter.
    #[default]
    Tun,
    /// Windows system proxy.
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

    // Protection
    /// Block all traffic outside the connection while connected or reconnecting.
    pub kill_switch: bool,
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
    pub test_url: String,

    // Appearance and window
    /// "en" or "fa".
    pub language: String,
    /// "system", "light" or "dark".
    pub theme: String,
    pub always_on_top: bool,
    pub minimize_to_tray: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: SETTINGS_VERSION,
            mode: Mode::Tun,
            selected: None,
            auto_connect: false,
            kill_switch: true,
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
            test_url: "http://www.gstatic.com/generate_204".into(),
            language: "en".into(),
            theme: "system".into(),
            always_on_top: false,
            minimize_to_tray: true,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.tun_stack.as_str(), "mixed" | "system" | "gvisor") {
            return Err("Unknown network stack.".into());
        }
        if !(1280..=9000).contains(&self.tun_mtu) {
            return Err("MTU must be between 1280 and 9000.".into());
        }
        if !matches!(self.log_level.as_str(), "warning" | "info" | "debug") {
            return Err("Unknown log level.".into());
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

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Store {
    pub groups: Vec<Group>,
    pub profiles: Vec<Profile>,
    pub settings: Settings,
}

impl Store {
    pub fn load(path: &Path) -> Self {
        let Ok(bytes) = fs::read(path) else { return Self::fresh() };
        match dpapi::unprotect(&bytes).and_then(|b| serde_json::from_slice::<Store>(&b).map_err(|e| e.to_string())) {
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
                // Keep the unreadable file instead of silently overwriting it.
                let _ = fs::rename(path, path.with_extension("bak"));
                Self::fresh()
            }
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
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, dpapi::protect(&json)?).map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| e.to_string())
    }
}

#[cfg(windows)]
mod dpapi {
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
mod dpapi {
    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
