//! The app's end of `phi2ray-helper` on Linux (see `helper_protocol.rs` and `helper/src/main.rs`).
//!
//! The app itself runs as the user. The first time something needs root (VPN mode or the kill
//! switch), `ensure` starts the helper through `pkexec`, which is when the system asks for the
//! password. It then stays for as long as the app does, so that happens once per session at most.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crate::helper_protocol::{Command, Core, Message, Outcome, Request, VERSION};
use crate::platform::host_command;
use crate::xray::{push_log, Logs, PORT_TAKEN};

/// Where packages install the helper and the cores. Only root can write there.
const INSTALLED: &str = "/usr/lib/phi2ray";
/// Where the AppImage puts them, once, since root can't read inside a running AppImage.
const APPIMAGE_INSTALLED: &str = "/opt/phi2ray";
const HELPER: &str = "phi2ray-helper";

/// Time for the person at the keyboard to type a password.
const PASSWORD_TIMEOUT: Duration = Duration::from_secs(300);
/// Starting a core waits for it inside the helper, up to 25 seconds for the adapter.
const CALL_TIMEOUT: Duration = Duration::from_secs(40);

struct Link {
    stdin: Mutex<ChildStdin>,
    child: Mutex<Child>,
    pending: Mutex<HashMap<u64, Sender<Outcome>>>,
    next_id: AtomicU64,
    core_uid: AtomicU32,
    xray: AtomicBool,
    tun: AtomicBool,
    gone: AtomicBool,
    /// What the helper said on stderr, for when it couldn't start.
    complaint: Mutex<String>,
}

static LINK: Mutex<Option<Arc<Link>>> = Mutex::new(None);
/// One password prompt at a time.
static STARTING: Mutex<()> = Mutex::new(());
static LOGS: OnceLock<Logs> = OnceLock::new();

pub fn init(logs: Logs) {
    let _ = LOGS.set(logs);
}

fn log(line: String) {
    if let Some(logs) = LOGS.get() {
        push_log(logs, line);
    }
}

fn link() -> Option<Arc<Link>> {
    LINK.lock().unwrap().clone().filter(|l| !l.gone.load(Ordering::SeqCst))
}

fn require() -> Result<Arc<Link>, String> {
    link().ok_or_else(|| "Phi2ray's helper stopped. Connect again.".to_string())
}

pub fn running() -> bool {
    link().is_some()
}

/// The account the cores run as, once the helper is up.
pub fn core_uid() -> Option<u32> {
    link().map(|l| l.core_uid.load(Ordering::SeqCst))
}

/// Starts the helper if it isn't running. Blocks while the system asks for the password.
pub fn ensure() -> Result<(), String> {
    let _one = STARTING.lock().unwrap();
    if running() {
        return Ok(());
    }
    let helper = locate()?;
    let mut child = host_command("pkexec")
        .arg(&helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "pkexec wasn't found. Install polkit to use VPN mode and the kill switch.".to_string(),
            _ => format!("Cannot start Phi2ray's helper: {e}"),
        })?;
    let (stdin, stdout, stderr) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (Some(stdin), Some(stdout), Some(stderr)) = (stdin, stdout, stderr) else {
        return Err("Cannot talk to Phi2ray's helper.".into());
    };
    let link = Arc::new(Link {
        stdin: Mutex::new(stdin),
        child: Mutex::new(child),
        pending: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        core_uid: AtomicU32::new(0),
        xray: AtomicBool::new(false),
        tun: AtomicBool::new(false),
        gone: AtomicBool::new(false),
        complaint: Mutex::new(String::new()),
    });

    let listener = link.clone();
    thread::spawn(move || listener.listen(stdout));
    let reader = link.clone();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            // pkexec's own remarks and the helper's, both useful if starting fails.
            *reader.complaint.lock().unwrap() = line;
        }
    });

    match link.call(Command::Hello { version: VERSION }, PASSWORD_TIMEOUT) {
        Ok(Outcome::Hello { core_uid }) => {
            link.core_uid.store(core_uid, Ordering::SeqCst);
            *LINK.lock().unwrap() = Some(link);
            log("[app] Helper started".into());
            Ok(())
        }
        Ok(Outcome::Failed { error }) => {
            let _ = link.child.lock().unwrap().kill();
            Err(error)
        }
        _ => Err(link.why_not_started()),
    }
}

impl Link {
    fn listen(&self, stdout: impl std::io::Read) {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            match serde_json::from_str::<Message>(&line) {
                Ok(Message::Reply { id, outcome }) => {
                    if let Some(waiting) = self.pending.lock().unwrap().remove(&id) {
                        let _ = waiting.send(outcome);
                    }
                }
                Ok(Message::Log { tag, line }) => log(format!("[{tag}] {line}")),
                Ok(Message::Exited { core, status }) => {
                    self.flag(core).store(false, Ordering::SeqCst);
                    log(format!("[app] {core:?} exited ({status})"));
                }
                Err(_) => {}
            }
        }
        // Whatever still waits gets an error, and the supervisor sees the cores as stopped.
        self.gone.store(true, Ordering::SeqCst);
        self.xray.store(false, Ordering::SeqCst);
        self.tun.store(false, Ordering::SeqCst);
        self.pending.lock().unwrap().clear();
    }

    fn flag(&self, core: Core) -> &AtomicBool {
        match core {
            Core::Xray => &self.xray,
            Core::Tun => &self.tun,
        }
    }

    fn call(&self, command: Command, timeout: Duration) -> Result<Outcome, String> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (answer, wait) = mpsc::channel();
        self.pending.lock().unwrap().insert(id, answer);
        let mut line = serde_json::to_vec(&Request { id, command }).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let gone = || "Phi2ray's helper stopped. Connect again.".to_string();
        {
            let mut stdin = self.stdin.lock().unwrap();
            stdin.write_all(&line).and_then(|()| stdin.flush()).map_err(|_| gone())?;
        }
        let answer = wait.recv_timeout(timeout).map_err(|_| gone());
        self.pending.lock().unwrap().remove(&id);
        answer
    }

    /// `pkexec` says what happened through its exit code.
    fn why_not_started(&self) -> String {
        let status = self.child.lock().unwrap().wait().ok().and_then(|s| s.code());
        let complaint = self.complaint.lock().unwrap().clone();
        match status {
            Some(126) => "Administrator permission was not granted.".into(),
            Some(127) => "The system couldn't ask for your password. Make sure a polkit agent is running on this desktop.".into(),
            _ if !complaint.is_empty() => format!("Phi2ray's helper couldn't start: {complaint}"),
            _ => "Phi2ray's helper couldn't start.".into(),
        }
    }
}

fn expect_done(outcome: Outcome) -> Result<(), String> {
    match outcome {
        Outcome::Done => Ok(()),
        Outcome::Failed { error } => Err(error),
        other => Err(format!("Unexpected answer from Phi2ray's helper: {other:?}")),
    }
}

pub fn start_xray(config: &str, ports: &[u16]) -> Result<(), String> {
    let link = require()?;
    let command = Command::StartXray { config: config.to_string(), ports: ports.to_vec() };
    match link.call(command, CALL_TIMEOUT)? {
        Outcome::PortTaken { port } => {
            Err(format!("{PORT_TAKEN} {port} is being used by another program. Connect again to use new ports."))
        }
        outcome => {
            expect_done(outcome)?;
            link.xray.store(true, Ordering::SeqCst);
            Ok(())
        }
    }
}

pub fn start_tun(config: &str) -> Result<(), String> {
    let link = require()?;
    expect_done(link.call(Command::StartTun { config: config.to_string() }, CALL_TIMEOUT)?)?;
    link.tun.store(true, Ordering::SeqCst);
    Ok(())
}

pub fn stop(core: Core) {
    if let Some(link) = link() {
        link.flag(core).store(false, Ordering::SeqCst);
        if let Err(e) = link.call(Command::Stop { core }, CALL_TIMEOUT).and_then(expect_done) {
            log(format!("[app] {e}"));
        }
    }
}

pub fn alive(core: Core) -> bool {
    link().is_some_and(|l| l.flag(core).load(Ordering::SeqCst))
}

/// Starts a throwaway xray listening on `port`, and returns what `stop_test` needs.
pub fn start_test(config: String, port: u16) -> Option<u64> {
    match link()?.call(Command::StartTest { config, port }, CALL_TIMEOUT) {
        Ok(Outcome::Test { test }) => Some(test),
        _ => None,
    }
}

pub fn stop_test(test: u64) {
    if let Some(link) = link() {
        let _ = link.call(Command::StopTest { test }, CALL_TIMEOUT);
    }
}

pub fn kill_switch(on: bool, allow_lan: bool) -> Result<(), String> {
    expect_done(require()?.call(Command::KillSwitch { on, allow_lan }, CALL_TIMEOUT)?)
}

/// The helper to run: the one from the package, or the AppImage's own copy.
fn locate() -> Result<PathBuf, String> {
    let installed = Path::new(INSTALLED).join(HELPER);
    if installed.exists() {
        return Ok(installed);
    }
    if let Some(app_dir) = std::env::var_os("APPDIR") {
        install_from_appimage(&PathBuf::from(app_dir))?;
        return Ok(Path::new(APPIMAGE_INSTALLED).join(HELPER));
    }
    let copied = Path::new(APPIMAGE_INSTALLED).join(HELPER);
    if copied.exists() {
        return Ok(copied);
    }
    Err("Phi2ray's helper isn't installed. Install the package for your system to use VPN mode and the kill switch.".into())
}

/// Root can't read inside a mounted AppImage, and a copy in a folder the user can write to could
/// be swapped. So the helper and cores are streamed into `/opt/phi2ray`, which belongs to root,
/// the first time they're needed and after an update. This asks for the password once more.
fn install_from_appimage(app_dir: &Path) -> Result<(), String> {
    let version = env!("CARGO_PKG_VERSION");
    let target = Path::new(APPIMAGE_INSTALLED);
    if std::fs::read_to_string(target.join("VERSION")).is_ok_and(|v| v.trim() == version) {
        return Ok(());
    }
    const SCRIPT: &str = r#"set -e
new=/opt/phi2ray.new
rm -rf "$new"
mkdir -p "$new"
tar -xf - -C "$new" --no-same-owner
chown -R root:root "$new"
chmod -R go-w "$new"
if [ -f "$new/com.phi2ray.helper.policy" ] && [ -d /usr/share/polkit-1/actions ]; then
    install -m 644 "$new/com.phi2ray.helper.policy" /usr/share/polkit-1/actions/
fi
printf '%s\n' "$1" > "$new/VERSION"
rm -rf /opt/phi2ray
mv "$new" /opt/phi2ray
"#;
    let mut tar = host_command("tar")
        .arg("-C")
        .arg(app_dir.join("usr/lib/phi2ray"))
        .args(["-cf", "-", "."])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Cannot read the AppImage: {e}"))?;
    let files = tar.stdout.take().ok_or("Cannot read the AppImage.")?;
    let status = host_command("pkexec")
        .args(["/bin/sh", "-c", SCRIPT, "sh", version])
        .stdin(Stdio::from(files))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("Cannot run pkexec: {e}"))?;
    let _ = tar.wait();
    match status.code() {
        Some(0) => Ok(()),
        Some(126) => Err("Administrator permission was not granted.".into()),
        _ => Err("Phi2ray couldn't set up its helper in /opt/phi2ray.".into()),
    }
}
