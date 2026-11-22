//! Absolute is an effective settings overlay, plus a recoverable Windows timezone lease.
//! It does not erase application caches or spoof a device's identity.
use crate::{
    probe::LocalProxy,
    store::{Mode, Settings},
    AppState,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const ZONES: &str = include_str!("windows-time-zones.json");

fn zones() -> &'static std::collections::BTreeMap<String, String> {
    static MAP: std::sync::OnceLock<std::collections::BTreeMap<String, String>> = std::sync::OnceLock::new();
    MAP.get_or_init(|| serde_json::from_str(ZONES).expect("bundled CLDR mapping"))
}

pub fn windows_zone(iana: &str) -> Result<String, String> {
    zones().get(iana).cloned().ok_or_else(|| "Unknown IANA timezone. Use a name such as America/Toronto.".into())
}

pub fn effective(s: &Settings) -> Settings {
    let mut s = s.clone();
    if s.absolute_mode {
        s.mode = Mode::Tun;
        s.kill_switch = true;
        s.auto_reconnect = true;
        s.bypass_lan = false;
        s.iran_direct = false;
        s.split.enabled = false;
        s.strict_route = true;
        s.ipv6 = false;
        s.remote_dns = "https://1.1.1.1/dns-query".into();
    }
    s
}

pub fn validate_profile(p: &crate::parser::Profile) -> Result<(),String> {
    if !matches!(p.stream.security.as_str(), "" | "none" | "tls" | "reality") || p.insecure().is_some() {
        return Err("Absolute requires an encrypted connection with verified security. Choose TLS/REALITY or a supported encrypted protocol.".into());
    }
    if p.protocol == crate::parser::Protocol::Wireguard && !crate::parser::wireguard::full_ipv4(p) {
        return Err("Absolute requires a WireGuard interface with IPv4 and a full IPv4 AllowedIPs route.".into());
    }
    Ok(())
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    #[serde(skip)]
    pub guarded: bool,
    pub phase: String,
    pub timezone: Option<String>,
    pub exit_ip: Option<String>,
    pub error: Option<String>,
}

pub fn phase(state: &AppState, phase: &str, error: Option<String>) {
    let mut status = state.absolute.lock().unwrap();
    status.phase = phase.into();
    status.error = error;
    if phase == "off" {
        status.timezone = None;
        status.exit_ip = None;
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Backup {
    #[serde(default)]
    lease: String,
    id: String,
    dst_disabled: bool,
    auto_start: u32,
    auto_running: bool,
    location: Option<String>,
}

impl Backup {
    fn same_settings(&self, other: &Self) -> bool {
        self.id == other.id && self.dst_disabled == other.dst_disabled && self.auto_start == other.auto_start && self.location == other.location
    }
}

trait System {
    fn read(&self) -> Result<Backup, String>;
    fn apply(&self, windows_id: &str) -> Result<(), String>;
    fn restore(&self, backup: &Backup) -> Result<(), String>;
    fn create_backup(&self, path: &Path) -> Result<std::fs::File, String> {
        std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|e| e.to_string())
    }
}

pub fn marker(state: &AppState) -> std::path::PathBuf {
    state.paths.data.join("absolute-backup.json")
}

fn save_backup(path: &Path, system: &impl System, lease: &str) -> Result<(), String> {
    use std::io::Write;
    if path.exists() {
        // Never replace the original timezone on reconnect or a server switch.
        read_backup(path)?;
        return Ok(());
    }
    let mut backup = system.read()?;
    backup.lease = lease.into();
    let data = serde_json::to_vec(&backup).map_err(|e| e.to_string())?;
    let temp = path.with_file_name(format!("absolute-{lease}.tmp"));
    let result = (|| {
        let mut file = system.create_backup(&temp)?;
        file.write_all(&data).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
        drop(file);
        std::fs::rename(&temp, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn read_backup(path: &Path) -> Result<Backup, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len() > 4096 {
        return Err("Absolute recovery record is too large.".into());
    }
    let b: Backup = serde_json::from_slice(&bytes).map_err(|_| "Invalid Absolute recovery record")?;
    if b.lease.len() != 16
        || !b.lease.bytes().all(|b| b.is_ascii_hexdigit())
        || !zones().values().any(|id| id == &b.id)
        || b.auto_start > 4
        || b.location.as_deref().is_some_and(|s| !matches!(s, "Allow" | "Deny"))
    {
        return Err("Invalid Absolute recovery settings.".into());
    }
    Ok(b)
}

fn restore_with(path: &Path, system: &impl System) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let backup = read_backup(path)?;
    system.restore(&backup)?;
    // Retain the record on every failed or partial restore so it can be retried.
    std::fs::remove_file(path).map_err(|e| format!("Timezone restored, but recovery record could not be removed: {e}"))
}

pub fn arm(state: &AppState) -> Result<(), String> {
    if !cfg!(windows) {
        return Err("Absolute mode needs Windows.".into());
    }
    crate::platform::elevate()?;
    let path = marker(state);
    let existed = path.exists();
    let lease = if existed { read_backup(&path)?.lease } else { crate::new_id() };
    let alive = state.absolute_guard.lock().unwrap().as_mut().is_some_and(|child| matches!(child.try_wait(), Ok(None)));
    if !state.absolute.lock().unwrap().guarded || !alive {
        let child = native::guard(&path, &lease)?;
        *state.absolute_guard.lock().unwrap() = Some(child);
        let mut status = state.absolute.lock().unwrap();
        status.guarded = true;
    }
    // Snapshot only after taking the machine-wide lease, never another session's timezone.
    if let Err(e) = save_backup(&path, &Native, &lease) {
        if let Some(mut child) = state.absolute_guard.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        state.absolute.lock().unwrap().guarded = false;
        return Err(e);
    }
    phase(state, "armed", None);
    Ok(())
}

pub fn restore(path: &Path) -> Result<(), String> {
    restore_with(path, &Native)
}

pub fn recover(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    // Acquire the machine-wide timezone lease before touching a leftover record.
    let mut guard = native::guard(path, &read_backup(path)?.lease)?;
    let result = restore(path);
    // Recovery is complete (or has reported its failure); do not strand its lease while
    // the main app starts a fresh guard or offers a retry. Its parent is still alive here.
    let _ = guard.kill();
    let _ = guard.wait();
    result
}

pub fn restore_owned(state: &AppState) -> Result<(), String> {
    let path = marker(state);
    if path.exists() {
        arm(state)?;
    }
    restore(&path)?;
    state.absolute.lock().unwrap().guarded = false;
    Ok(())
}

#[derive(Debug)]
struct Destination {
    ip: String,
    timezone: String,
}

fn destination(v: &serde_json::Value, manual: &str) -> Result<Destination, String> {
    let ip = v["ip"]
        .as_str()
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .filter(|ip| crate::netinfo::is_public(*ip))
        .ok_or("The exit lookup did not return a public IP.")?;
    let timezone = if manual.is_empty() {
        v["timezone"].as_str().ok_or("The exit lookup did not return a timezone. Set an IANA timezone manually.")?
    } else {
        manual
    };
    windows_zone(timezone)?;
    Ok(Destination { ip: ip.to_string(), timezone: timezone.into() })
}

async fn lookup(proxy: &LocalProxy, manual: &str) -> Result<Destination, String> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("Phi2ray/", env!("CARGO_PKG_VERSION")))
        .no_proxy()
        .proxy(proxy.for_reqwest()?)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(12))
        .build()
        .map_err(|_| "Could not create protected timezone lookup")?;
    async fn body(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
        let mut response = client.get(url).send().await.map_err(|_| "Timezone lookup through the VPN failed.")?;
        if !response.status().is_success() {
            return Err("Timezone provider did not return a successful response.".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "Incomplete timezone response")? {
            if bytes.len() + chunk.len() > 64 * 1024 {
                return Err("Timezone response is too large.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    // Query a literal IPv4 destination so the result matches IPv4-only user traffic.
    let trace = body(&client, "https://1.1.1.1/cdn-cgi/trace").await?;
    let trace = std::str::from_utf8(&trace).map_err(|_| "Invalid protected IP response")?;
    let ip = trace
        .lines()
        .find_map(|l| l.strip_prefix("ip="))
        .and_then(|s| s.trim().parse::<std::net::Ipv4Addr>().ok())
        .filter(|ip| crate::netinfo::is_public((*ip).into()))
        .ok_or("The protected IPv4 exit could not be verified")?;
    if !manual.is_empty() {
        return destination(&serde_json::json!({"ip":ip.to_string()}), manual);
    }
    let bytes = body(&client, &format!("https://ipapi.co/{ip}/json/")).await?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| "Invalid timezone response")?;
    if value["ip"].as_str().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()) != Some(ip) {
        return Err("Timezone lookup IP does not match the protected exit".into());
    }
    destination(&value, manual)
}

pub fn prepare(state: &AppState, proxy: &LocalProxy, manual: &str) -> Result<(), String> {
    phase(state, "preparing", None);
    let result: Result<(), String> = (|| {
        if !marker(state).exists() {
            return Err("Absolute recovery record is missing. Disable and enable Absolute again.".into());
        }
        let dest = tauri::async_runtime::block_on(lookup(proxy, manual))?;
        Native.apply(&windows_zone(&dest.timezone)?)?;
        let mut status = state.absolute.lock().unwrap();
        status.timezone = Some(dest.timezone);
        status.exit_ip = Some(dest.ip);
        Ok(())
    })();
    if let Err(e) = &result {
        phase(state, "error", Some(e.clone()));
    }
    result
}

/// A failed periodic verification must close the data path before recovery is attempted.
pub fn verify(state: &AppState, proxy: &LocalProxy, manual: &str) -> Result<String, String> {
    if !state.absolute_guard.lock().unwrap().as_mut().is_some_and(|child| matches!(child.try_wait(), Ok(None))) {
        return Err("Timezone recovery guard stopped; rebuilding protection.".into());
    }
    let dest = tauri::async_runtime::block_on(lookup(proxy, manual))?;
    let status = state.absolute.lock().unwrap().clone();
    if status.timezone.as_deref() != Some(&dest.timezone) {
        return Err("VPN exit timezone changed; revalidating protection.".into());
    }
    let current = Native.read()?;
    if current.id != windows_zone(&dest.timezone)?
        || current.auto_start != 4
        || current.auto_running
        || current.location.as_deref() != Some("Deny")
        || current.dst_disabled
    {
        return Err("Windows protection settings changed; revalidating Absolute.".into());
    }
    Ok(dest.ip)
}

struct Native;

#[cfg(windows)]
mod native {
    use super::*;
    use std::io::{BufRead, Write};
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    // Fixed scripts; data is read as JSON on stdin and is never interpolated into code.
    const READ: &str = r#"
$z=Get-TimeZone
$r=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
$a=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate'
$l=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -ErrorAction SilentlyContinue
@{id=$z.Id;dstDisabled=[bool]$r.DynamicDaylightTimeDisabled;autoStart=[uint32]$a.Start;autoRunning=((Get-Service tzautoupdate).Status -eq 'Running');location=$l.Value}|ConvertTo-Json -Compress
"#;
    const APPLY: &str = r#"
$d=[Console]::In.ReadToEnd()|ConvertFrom-Json
[void][TimeZoneInfo]::FindSystemTimeZoneById($d.id)
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' Start 4
Stop-Service tzautoupdate -ErrorAction Stop
$p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
if(!(Test-Path $p)){[void](New-Item $p -Force)}
Set-ItemProperty $p Value 'Deny'
& ([IO.Path]::Combine([Environment]::GetFolderPath('System'),'tzutil.exe')) /s $d.id
if($LASTEXITCODE -ne 0){throw 'Timezone update failed'}
if((Get-TimeZone).Id -ne $d.id){throw 'Timezone verification failed'}
"#;
    const RESTORE: &str = r#"
$d=[Console]::In.ReadToEnd()|ConvertFrom-Json
[void][TimeZoneInfo]::FindSystemTimeZoneById($d.id)
Stop-Service tzautoupdate -ErrorAction Stop
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' Start 4
$id=$d.id
if($d.dstDisabled){$id+='_dstoff'}
& ([IO.Path]::Combine([Environment]::GetFolderPath('System'),'tzutil.exe')) /s $id
if($LASTEXITCODE -ne 0){throw 'Timezone restore failed'}
if((Get-TimeZone).Id -ne $d.id){throw 'Timezone restore verification failed'}
$p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
if($null -eq $d.location){Remove-ItemProperty $p Value -ErrorAction SilentlyContinue}else{Set-ItemProperty $p Value $d.location}
if($d.autoRunning){
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' Start 3
    Start-Service tzautoupdate -ErrorAction Stop
}
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' Start $d.autoStart
"#;

    fn powershell(script: &str, input: &str) -> Result<String, String> {
        use base64::Engine;
        let script = format!("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);try{{{script}}}catch{{[Console]::Error.WriteLine($_.Exception.Message);exit 1}}");
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
        use std::os::windows::ffi::OsStringExt;
        let mut buffer = vec![0u16; 32768];
        let n = unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)
        } as usize;
        if n == 0 || n >= buffer.len() {
            return Err("Windows system directory unavailable".into());
        }
        let system = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..n]));
        let executable = system.join("WindowsPowerShell/v1.0/powershell.exe");
        let mut child = Command::new(executable)
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .env("PSModulePath", system.join("WindowsPowerShell/v1.0/Modules"))
            .env("PATH", &system)
            .creation_flags(crate::xray::CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Windows timezone control could not start: {e}"))?;
        if let Err(e) = crate::platform::bind_to_app(child.as_raw_handle()) {
            let _ = child.kill();
            return Err(e);
        }
        child.stdin.take().unwrap().write_all(input.as_bytes()).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Windows timezone control timed out. Recovery record retained.".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "Windows protection update failed: {}",
                String::from_utf8_lossy(&output.stderr).chars().take(300).collect::<String>()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim_start_matches('\u{feff}').trim().into())
    }

    impl System for Native {
        fn create_backup(&self, path: &Path) -> Result<std::fs::File, String> {
            use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
            use windows_sys::Win32::{
                Foundation::{LocalFree, INVALID_HANDLE_VALUE},
                Security::{
                    Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
                    SECURITY_ATTRIBUTES,
                },
                Storage::FileSystem::{
                    CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                    FILE_SHARE_READ,
                },
            };
            // Secure the original timezone before writing any bytes; ordinary apps cannot read it.
            let sddl: Vec<u16> = "O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)".encode_utf16().chain(Some(0)).collect();
            let mut descriptor = std::ptr::null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err("Could not secure the timezone recovery record".into());
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    FILE_GENERIC_WRITE | FILE_GENERIC_READ,
                    FILE_SHARE_READ,
                    &attributes,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
            let error = std::io::Error::last_os_error();
            unsafe {
                LocalFree(descriptor);
            }
            if handle == INVALID_HANDLE_VALUE {
                return Err(format!("Could not create protected timezone backup: {error}"));
            }
            Ok(unsafe { std::fs::File::from_raw_handle(handle) })
        }
        fn read(&self) -> Result<Backup, String> {
            serde_json::from_str(&powershell(READ, "")?)
                .map_err(|_| "Could not read Windows protection settings".into())
        }
        fn apply(&self, id: &str) -> Result<(), String> {
            powershell(APPLY, &serde_json::json!({"id": id}).to_string())?;
            let now = self.read()?;
            if now.id != id
                || now.dst_disabled
                || now.auto_start != 4
                || now.auto_running
                || now.location.as_deref() != Some("Deny")
            {
                return Err("Windows protection verification failed.".into());
            }
            Ok(())
        }
        fn restore(&self, b: &Backup) -> Result<(), String> {
            let before = self.read()?;
            if before.same_settings(b) && before.auto_running == b.auto_running {
                return Ok(());
            }
            powershell(RESTORE, &serde_json::to_string(b).map_err(|e| e.to_string())?)?;
            let now = self.read()?;
            // Windows may immediately idle or trigger this service again; verify its saved
            // startup configuration, not a transient running state after Start-Service.
            if !now.same_settings(b) {
                return Err("Windows settings were not fully restored. Recovery record retained.".into());
            }
            Ok(())
        }
    }

    pub fn guard(path: &Path, lease: &str) -> Result<Child, String> {
        let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("--absolute-watchdog")
            .arg(std::process::id().to_string())
            .arg(path)
            .arg(lease)
            .creation_flags(crate::xray::CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Could not start timezone recovery guard: {e}"))?;
        // The guard opens its parent process before acknowledging readiness.
        let stdout = child.stdout.take().ok_or("Recovery guard has no handshake")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        if rx.recv_timeout(Duration::from_secs(8)).ok().as_deref() != Some("ready\n") {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Timezone recovery guard did not start.".into());
        }
        Ok(child)
    }

    pub fn watchdog(parent: u32, path: &Path, lease: &str) -> Result<(), String> {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{CreateMutexW, OpenProcess, ReleaseMutex, WaitForSingleObject, PROCESS_SYNCHRONIZE},
        };
        // Only the same protected data folder the main executable uses is accepted.
        let base = crate::cores::target_dir()
            .and_then(Result::ok)
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .ok_or("Recovery guard requires an embedded Windows release")?;
        let expected =
            crate::admin_data_dir(&base).ok_or("Protected recovery folder unavailable")?.join("absolute-backup.json");
        if path != expected || parent == std::process::id() {
            return Err("Invalid recovery guard arguments".into());
        }
        if lease.len() != 16 || !lease.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid recovery lease".into());
        }
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, parent) };
        if handle.is_null() {
            return Err("Could not monitor timezone owner".into());
        }
        let name: Vec<u16> = "Global\\Phi2rayAbsoluteTimezone".encode_utf16().chain(Some(0)).collect();
        let mutex = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if mutex.is_null() {
            unsafe {
                CloseHandle(handle);
            }
            return Err("Could not acquire global timezone lease".into());
        }
        let wait = unsafe { WaitForSingleObject(mutex, 5000) };
        if wait != 0 && wait != 0x80 {
            unsafe {
                CloseHandle(mutex);
                CloseHandle(handle);
            }
            return Err("Another Absolute session owns the system timezone".into());
        }
        let result = (|| {
            if path.exists() && read_backup(path)?.lease != lease {
                return Err("Recovery lease changed".into());
            }
            println!("ready");
            std::io::stdout().flush().map_err(|e| e.to_string())?;
            let deadline = Instant::now() + Duration::from_secs(40);
            let backup = loop {
                if let Ok(backup) = read_backup(path) {
                    if backup.lease != lease {
                        return Ok(());
                    }
                    break backup;
                }
                if unsafe { WaitForSingleObject(handle, 100) } == 0 {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err("Recovery snapshot was not published".into());
                }
            };
            loop {
                if !path.exists() || read_backup(path).is_ok_and(|b| b.lease != lease) {
                    return Ok(());
                }
                let result = unsafe { WaitForSingleObject(handle, 1000) };
                if result == 0 {
                    break;
                }
                if result != 258 {
                    return Err("Could not monitor Absolute owner".into());
                }
            }
            std::thread::sleep(Duration::from_millis(500));
            for _ in 0..5 {
                if !path.exists() || read_backup(path).is_ok_and(|b| b.lease != lease) {
                    return Ok(());
                }
                // Keep the original in memory as well, in case the on-disk record was damaged.
                if Native.restore(&backup).is_ok() {
                    if std::fs::remove_file(path).is_ok() {
                        return Ok(());
                    }
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            Err("Recovery will be retried on next launch".into())
        })();
        unsafe {
            ReleaseMutex(mutex);
            CloseHandle(mutex);
            CloseHandle(handle);
        }
        result
    }
}

#[cfg(not(windows))]
mod native {
    use super::*;
    impl System for Native {
        fn read(&self) -> Result<Backup, String> {
            Err("Windows only".into())
        }
        fn apply(&self, _: &str) -> Result<(), String> {
            Err("Windows only".into())
        }
        fn restore(&self, _: &Backup) -> Result<(), String> {
            Err("Windows only".into())
        }
    }
    pub fn guard(_: &Path, _: &str) -> Result<std::process::Child, String> {
        Err("Windows only".into())
    }
    pub fn watchdog(_: u32, _: &Path, _: &str) -> Result<(), String> {
        Err("Windows only".into())
    }
}

pub fn watchdog_entry() -> bool {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_none_or(|s| s != "--absolute-watchdog") {
        return false;
    }
    if let (Some(pid), Some(path), Some(lease)) = (
        args.get(2).and_then(|s| s.to_str()).and_then(|s| s.parse().ok()),
        args.get(3),
        args.get(4).and_then(|s| s.to_str()),
    ) {
        let _ = native::watchdog(pid, Path::new(path), lease);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    struct Fake {
        fail: Cell<bool>,
        reads: Cell<u32>,
        restores: Cell<u32>,
    }
    impl System for Fake {
        fn read(&self) -> Result<Backup, String> {
            self.reads.set(self.reads.get() + 1);
            Ok(Backup {
                lease: String::new(),
                id: "Iran Standard Time".into(),
                dst_disabled: true,
                auto_start: 3,
                auto_running: true,
                location: Some("Allow".into()),
            })
        }
        fn apply(&self, _: &str) -> Result<(), String> {
            panic!("not used")
        }
        fn restore(&self, b: &Backup) -> Result<(), String> {
            assert_eq!(b.id, "Iran Standard Time");
            self.restores.set(self.restores.get() + 1);
            if self.fail.get() {
                Err("simulated partial failure".into())
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn original_backup_survives_reconnect_and_failed_restoration() {
        let dir = std::env::temp_dir().join(format!("phi2ray-absolute-test-{}", crate::new_id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("backup.json");
        let fake = Fake { fail: Cell::new(true), reads: Cell::new(0), restores: Cell::new(0) };
        save_backup(&path, &fake, "1234567890abcdef").unwrap();
        save_backup(&path, &fake, "fedcba0987654321").unwrap();
        assert_eq!(fake.reads.get(), 1);
        assert!(restore_with(&path, &fake).is_err());
        assert!(path.exists());
        fake.fail.set(false);
        restore_with(&path, &fake).unwrap();
        assert!(!path.exists());
        restore_with(&path, &fake).unwrap();
        assert_eq!(fake.restores.get(), 2);
        std::fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn restoration_checks_settings_without_failing_on_service_idle() {
        let fake = Fake { fail: Cell::new(false), reads: Cell::new(0), restores: Cell::new(0) };
        let original = fake.read().unwrap();
        let mut current = original.clone();
        current.auto_running = !current.auto_running;
        assert!(current.same_settings(&original));
        current.location = Some("Deny".into());
        assert!(!current.same_settings(&original));
        current = original.clone();
        current.id = "UTC".into();
        assert!(!current.same_settings(&original));
        current = original.clone();
        current.dst_disabled = !current.dst_disabled;
        assert!(!current.same_settings(&original));
    }
    #[test]
    fn overlay_preserves_user_settings_and_disables_direct_paths() {
        let s = Settings {
            absolute_mode: true,
            mode: Mode::Manual,
            kill_switch: false,
            iran_direct: true,
            ipv6: true,
            ..Settings::default()
        };
        let original = serde_json::to_string(&s).unwrap();
        let e = effective(&s);
        assert!(e.kill_switch && e.strict_route && e.auto_reconnect);
        assert_eq!(e.mode, Mode::Tun);
        assert!(!e.bypass_lan && !e.iran_direct && !e.ipv6 && !e.split.enabled);
        assert_eq!(serde_json::to_string(&s).unwrap(), original);
    }
    #[test]
    fn locations_require_a_real_zone_and_public_exit() {
        assert_eq!(windows_zone("America/Toronto").unwrap(), "Eastern Standard Time");
        assert_eq!(windows_zone("America/Vancouver").unwrap(), "Pacific Standard Time");
        assert_eq!(windows_zone("Asia/Kolkata").unwrap(), "India Standard Time");
        assert_eq!(windows_zone("Europe/Kyiv").unwrap(), "FLE Standard Time");
        assert_eq!(windows_zone("UTC").unwrap(), "UTC");
        assert!(destination(&serde_json::json!({"ip":"1.1.1.1","country":"CA"}), "").is_err());
        assert!(destination(&serde_json::json!({"ip":"127.0.0.1","timezone":"America/Toronto"}), "").is_err());
        assert!(destination(&serde_json::json!({"ip":"1.1.1.1","timezone":"bad"}), "").is_err());
        assert_eq!(
            destination(&serde_json::json!({"ip":"1.1.1.1"}), "America/Toronto").unwrap().timezone,
            "America/Toronto"
        );
    }

    #[test]
    fn absolute_requires_encryption_but_accepts_native_vless_encryption() {
        let plain = crate::parser::parse_link("vless://id@example.invalid:443?security=none").unwrap();
        assert!(validate_profile(&plain).is_err());
        let secure = crate::parser::parse_link("trojan://password@example.invalid:443").unwrap();
        assert!(validate_profile(&secure).is_ok());
        let mut unverified = secure;
        unverified.stream.allow_insecure = true;
        assert!(validate_profile(&unverified).is_err());
        let native = crate::parser::custom::tests::sample(false);
        let profile = crate::parser::parse_many(&native.to_string()).profiles.remove(0);
        assert!(validate_profile(&profile).is_ok());
    }
}
