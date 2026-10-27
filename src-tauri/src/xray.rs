//! Runs the cores as child processes: xray (the proxy itself) and, in VPN mode,
//! sing-box (only for the TUN adapter). Configs are passed on stdin,
//! so credentials never touch the disk in plain text.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

#[cfg(windows)]
pub const XRAY_EXE: &str = "xray.exe";
#[cfg(not(windows))]
pub const XRAY_EXE: &str = "xray";
#[cfg(windows)]
pub const SING_BOX_EXE: &str = "sing-box.exe";
#[cfg(not(windows))]
pub const SING_BOX_EXE: &str = "sing-box";

#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const MAX_LOG_LINES: usize = 1000;

pub type Logs = Arc<Mutex<VecDeque<String>>>;

pub struct Core {
    xray: Option<Child>,
    tun: Option<Child>,
    logs: Logs,
}

impl Core {
    pub fn new(logs: Logs) -> Self {
        Self { xray: None, tun: None, logs }
    }

    pub fn start_xray(&mut self, exe: &Path, asset_dir: &Path, config: &Value, socks_port: u16) -> Result<(), String> {
        if let Some(old) = self.xray.take() {
            kill(old);
        }
        let mut cmd = Command::new(exe);
        cmd.args(["run", "-format", "json", "-c", "stdin:"]).env("XRAY_LOCATION_ASSET", asset_dir);
        let mut child = self.launch("xray", cmd, &config.to_string())?;

        // Ready once the local SOCKS inbound accepts connections.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("Xray exited ({status}). See logs for details."));
            }
            let addr = ([127, 0, 0, 1], socks_port).into();
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                break;
            }
            if Instant::now() > deadline {
                kill(child);
                return Err("Xray did not start in time. See logs for details.".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.xray = Some(child);
        Ok(())
    }

    pub fn start_tun(&mut self, exe: &Path, work_dir: &Path, config: &Value) -> Result<(), String> {
        std::fs::create_dir_all(work_dir).map_err(|e| e.to_string())?;
        if let Some(old) = self.tun.take() {
            kill(old);
        }
        let mut cmd = Command::new(exe);
        cmd.args(["run", "-c", "stdin", "--disable-color", "-D"]).arg(work_dir);
        let mut child = self.launch("tun", cmd, &config.to_string())?;

        // Creating the adapter and routes takes a moment; fail fast if sing-box gives up.
        thread::sleep(Duration::from_millis(1500));
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("VPN adapter failed to start ({status}). See logs for details."));
        }
        self.tun = Some(child);
        Ok(())
    }

    /// Stops the TUN first, so traffic is never routed to a dead proxy.
    pub fn stop(&mut self) {
        for child in [self.tun.take(), self.xray.take()].into_iter().flatten() {
            kill(child);
        }
    }

    pub fn xray_alive(&mut self) -> bool {
        alive(&mut self.xray) == Some(true)
    }

    /// None when no VPN adapter was started (proxy modes).
    pub fn tun_alive(&mut self) -> Option<bool> {
        alive(&mut self.tun)
    }

    fn launch(&self, tag: &'static str, mut cmd: Command, config: &str) -> Result<Child, String> {
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd.spawn().map_err(|e| format!("Failed to start {tag}: {e}"))?;
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            crate::win::bind_to_app(child.as_raw_handle());
        }

        if let Some(mut stdin) = child.stdin.take() {
            // Dropping stdin afterwards sends EOF, which tells the core the config is complete.
            if let Err(e) = stdin.write_all(config.as_bytes()) {
                kill(child);
                return Err(format!("Failed to send config to {tag}: {e}"));
            }
        }
        if let Some(out) = child.stdout.take() {
            pipe(self.logs.clone(), tag, out);
        }
        if let Some(err) = child.stderr.take() {
            pipe(self.logs.clone(), tag, err);
        }
        Ok(child)
    }
}

/// Collects a core's output into the shared log buffer. The UI polls it only while
/// the log view is open, so a chatty core can't slow the window down.
fn pipe(logs: Logs, tag: &'static str, stream: impl Read + Send + 'static) {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            let mut logs = logs.lock().unwrap();
            if logs.len() >= MAX_LOG_LINES {
                logs.pop_front();
            }
            logs.push_back(format!("[{tag}] {line}"));
        }
    });
}

fn alive(child: &mut Option<Child>) -> Option<bool> {
    child.as_mut().map(|c| matches!(c.try_wait(), Ok(None)))
}

fn kill(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Returns the SHA-256 of a core binary. If `<name>.sha256` exists next to it,
/// the hash must match, otherwise the core is refused.
pub fn verify(exe: &Path) -> Result<String, String> {
    let bytes = std::fs::read(exe).map_err(|e| format!("Cannot read {}: {e}", exe.display()))?;
    let hash = hex::encode(Sha256::digest(&bytes));

    let name = exe.file_name().unwrap_or_default().to_string_lossy();
    let pin = exe.with_file_name(format!("{name}.sha256"));
    if let Ok(expected) = std::fs::read_to_string(pin) {
        let expected = expected.split_whitespace().next().unwrap_or_default().to_ascii_lowercase();
        if expected != hash {
            return Err(format!("{name} hash mismatch: expected {expected}, got {hash}"));
        }
    }
    Ok(hash)
}

/// The version number printed by `<core> version`, e.g. "26.10.21".
pub fn version(exe: &Path) -> Option<String> {
    let mut cmd = Command::new(exe);
    cmd.arg("version").stdin(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?;
    first.split_whitespace().find(|w| w.starts_with(|c: char| c.is_ascii_digit())).map(String::from)
}
