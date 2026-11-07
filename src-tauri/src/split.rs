//! Split tunnelling: choose which apps and sites skip the VPN (exclude mode), or which are the
//! only ones that use it (include mode).
//!
//! Sites work in every mode (sing-box routes on the sniffed domain in VPN mode, xray does it in
//! proxy modes). Apps need VPN mode: only the TUN adapter sees which process sent a packet.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

const MAX_ENTRIES: usize = 500;
const WINDOWS: bool = cfg!(windows);

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitMode {
    /// Listed apps and sites bypass the VPN; everything else uses it.
    #[default]
    Exclude,
    /// Only listed apps and sites use the VPN; everything else goes direct.
    Include,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SplitTunnel {
    pub enabled: bool,
    pub mode: SplitMode,
    /// Process names (`Telegram.exe`, or `telegram-desktop` on Linux) or full paths.
    pub apps: Vec<String>,
    /// Domains (subdomains included), IPs or CIDR ranges.
    pub sites: Vec<String>,
}

/// The rules a split tunnel turns into.
#[derive(Default)]
pub struct Rules {
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    /// Regexes over the full executable path.
    pub app_patterns: Vec<String>,
}

impl Rules {
    pub fn has_sites(&self) -> bool {
        !self.domains.is_empty() || !self.cidrs.is_empty()
    }
}

impl SplitTunnel {
    /// Rules to apply, or None when split tunnelling is off or empty.
    pub fn rules(&self) -> Option<Rules> {
        if !self.enabled || (self.apps.is_empty() && self.sites.is_empty()) {
            return None;
        }
        let mut rules = Rules::default();
        for site in &self.sites {
            match normalize_site(site) {
                Ok(Site::Domain(d)) => rules.domains.push(d),
                Ok(Site::Cidr(c)) => rules.cidrs.push(c),
                Err(_) => {}
            }
        }
        rules.app_patterns = self.apps.iter().filter_map(|a| app_pattern(a)).collect();
        Some(rules)
    }

    /// Cleans up user input: canonical sites, trimmed apps, no duplicates. Fails on entries
    /// that can't work, so the user sees the problem instead of a silently ignored rule.
    pub fn normalize(&mut self) -> Result<(), String> {
        let mut sites: Vec<String> = Vec::new();
        for raw in &self.sites {
            let site = match normalize_site(raw)? {
                Site::Domain(d) => d,
                Site::Cidr(c) => c,
            };
            if !sites.contains(&site) {
                sites.push(site);
            }
        }
        let mut apps: Vec<String> = Vec::new();
        for raw in &self.apps {
            let app = normalize_app(raw)?;
            if !apps.iter().any(|a| if WINDOWS { a.eq_ignore_ascii_case(&app) } else { *a == app }) {
                apps.push(app);
            }
        }
        if sites.len() > MAX_ENTRIES || apps.len() > MAX_ENTRIES {
            return Err(format!("Split tunnel lists are limited to {MAX_ENTRIES} entries."));
        }
        self.sites = sites;
        self.apps = apps;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum Site {
    Domain(String),
    Cidr(String),
}

/// Accepts `example.com`, `*.example.com`, `https://www.example.com/path`, `1.2.3.4`,
/// `10.0.0.0/8` and `2001:db8::/32`.
pub fn normalize_site(raw: &str) -> Result<Site, String> {
    let s = raw.trim().to_ascii_lowercase();
    let invalid = || format!("\"{}\" isn't a valid site, IP or IP range.", raw.trim());
    if s.is_empty() {
        return Err(invalid());
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Site::Cidr(match ip {
            IpAddr::V4(_) => format!("{ip}/32"),
            IpAddr::V6(_) => format!("{ip}/128"),
        }));
    }
    if let Some((addr, prefix)) = s.split_once('/') {
        if let (Ok(ip), Ok(prefix)) = (addr.parse::<IpAddr>(), prefix.parse::<u8>()) {
            let max = if ip.is_ipv4() { 32 } else { 128 };
            return if prefix <= max { Ok(Site::Cidr(format!("{ip}/{prefix}"))) } else { Err(invalid()) };
        }
    }

    let s = s.split_once("://").map_or(s.as_str(), |(_, rest)| rest);
    let host = s.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = host.split(':').next().unwrap_or_default();
    let host = host.trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.');
    let host = host.strip_prefix("www.").unwrap_or(host);
    let valid = host.contains('.')
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if valid {
        Ok(Site::Domain(host.to_string()))
    } else {
        Err(invalid())
    }
}

fn normalize_app(raw: &str) -> Result<String, String> {
    normalize_app_for(raw, WINDOWS)
}

/// On Windows `chrome` becomes `chrome.exe`, and paths use backslashes. Elsewhere a name is
/// already the file's name.
fn normalize_app_for(raw: &str, windows: bool) -> Result<String, String> {
    let app = raw.trim().trim_matches('"').trim();
    if app.is_empty() || app.chars().any(|c| c.is_control() || matches!(c, '*' | '?' | '<' | '>' | '|')) {
        return Err(format!("\"{}\" isn't a valid app name or path.", raw.trim()));
    }
    if !windows {
        return Ok(app.to_string());
    }
    let is_path = app.contains(['\\', '/']);
    let file = app.rsplit(['\\', '/']).next().unwrap_or(app);
    if is_path || file.contains('.') {
        Ok(app.replace('/', "\\"))
    } else {
        Ok(format!("{app}.exe"))
    }
}

/// A regex matching the executable's full path: either exactly the given path, or any path ending
/// in the given file name. File names only ignore case on Windows.
pub(crate) fn app_pattern(entry: &str) -> Option<String> {
    app_pattern_for(entry, WINDOWS)
}

fn app_pattern_for(entry: &str, windows: bool) -> Option<String> {
    let app = normalize_app_for(entry, windows).ok()?;
    let (flags, separator) = if windows { ("(?i)", "\\\\") } else { ("", "/") };
    if app.contains(if windows { '\\' } else { '/' }) {
        Some(format!("{flags}^{}$", regex_escape(&app)))
    } else {
        Some(format!("{flags}(^|{separator}){}$", regex_escape(&app)))
    }
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sites() {
        let d = |s: &str| normalize_site(s).unwrap();
        assert_eq!(d("Example.com"), Site::Domain("example.com".into()));
        assert_eq!(d("https://www.YouTube.com/watch?v=1"), Site::Domain("youtube.com".into()));
        assert_eq!(d("*.digikala.com"), Site::Domain("digikala.com".into()));
        assert_eq!(d("user@host.ir:8443/x"), Site::Domain("host.ir".into()));
        assert_eq!(d("1.2.3.4"), Site::Cidr("1.2.3.4/32".into()));
        assert_eq!(d("10.0.0.0/8"), Site::Cidr("10.0.0.0/8".into()));
        assert_eq!(d("2001:db8::/32"), Site::Cidr("2001:db8::/32".into()));
        assert!(normalize_site("localhost").is_err());
        assert!(normalize_site("bad_domain.com").is_err());
        assert!(normalize_site("10.0.0.0/40").is_err());
        assert!(normalize_site("  ").is_err());
    }

    #[test]
    fn apps() {
        let normalize = |app| normalize_app_for(app, true);
        assert_eq!(normalize("telegram").unwrap(), "telegram.exe");
        assert_eq!(normalize(" \"C:/Apps/My App/app.exe\" ").unwrap(), "C:\\Apps\\My App\\app.exe");
        assert!(normalize("a|b").is_err());
        assert_eq!(app_pattern_for("Telegram.exe", true).unwrap(), r"(?i)(^|\\)Telegram\.exe$");
        assert_eq!(app_pattern_for(r"C:\Program Files (x86)\x.exe", true).unwrap(), r"(?i)^C:\\Program Files \(x86\)\\x\.exe$");
    }

    #[test]
    fn apps_on_linux() {
        assert_eq!(normalize_app_for(" firefox ", false).unwrap(), "firefox");
        assert_eq!(normalize_app_for("/usr/lib/firefox/firefox", false).unwrap(), "/usr/lib/firefox/firefox");
        assert!(normalize_app_for("a|b", false).is_err());
        // Case matters here: another program may differ only in that.
        assert_eq!(app_pattern_for("telegram-desktop", false).unwrap(), "(^|/)telegram-desktop$");
        assert_eq!(app_pattern_for("/opt/my.app/run", false).unwrap(), r"^/opt/my\.app/run$");
    }

    #[test]
    fn normalize_dedupes() {
        let mut s = SplitTunnel {
            enabled: true,
            sites: vec!["www.a.com".into(), "A.com".into(), "1.1.1.1".into()],
            apps: vec!["Steam.exe".into(), if WINDOWS { "steam.exe".into() } else { "Steam.exe".into() }],
            ..Default::default()
        };
        s.normalize().unwrap();
        assert_eq!(s.sites, ["a.com", "1.1.1.1/32"]);
        assert_eq!(s.apps, ["Steam.exe"]);
        let r = s.rules().unwrap();
        assert_eq!((r.domains.len(), r.cidrs.len(), r.app_patterns.len()), (1, 1, 1));
        assert!(SplitTunnel { enabled: false, ..s }.rules().is_none());
    }
}
