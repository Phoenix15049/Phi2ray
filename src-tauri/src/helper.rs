//! The app's end of `phi2ray-helper` on Linux (see `helper_protocol.rs` and `helper/src/main.rs`).
//!
//! The app itself runs as the user. The first time something needs root (VPN mode or the kill
//! switch), `ensure` starts the helper through `pkexec`, which is when the system asks for the
//! password. It then stays for as long as the app does, so that happens once per session at most.

use std::collections::HashMap;
use std::io::{BufReader, Write};
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
const HELPER: &str = "phi2ray-helper";

/// Time for the person at the keyboard to type a password.
const PASSWORD_TIMEOUT: Duration = Duration::from_secs(300);
/// Starting a core waits for it inside the helper, up to 25 seconds for the adapter.
const CALL_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_RESPONSE_BYTES: usize = 32 * 1024;

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
        let mut stderr = BufReader::new(stderr);
        let mut bytes = Vec::new();
        while let Ok(Some(_)) = crate::bounded_lines::read(&mut stderr, &mut bytes, crate::bounded_lines::LOG_BYTES) {
            // pkexec's own remarks and the helper's, both useful if starting fails.
            *reader.complaint.lock().unwrap() = String::from_utf8_lossy(&bytes).trim_end_matches('\r').to_owned();
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
        let mut stdout = BufReader::new(stdout);
        let mut bytes = Vec::new();
        while let Ok(Some(truncated)) = crate::bounded_lines::read(&mut stdout, &mut bytes, MAX_RESPONSE_BYTES) {
            if truncated { continue; }
            match serde_json::from_slice::<Message>(&bytes) {
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
        let mut line = serde_json::to_vec(&Request { id, command }).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let (answer, wait) = mpsc::channel();
        self.pending.lock().unwrap().insert(id, answer);
        let gone = || "Phi2ray's helper stopped. Connect again.".to_string();
        let sent = {
            let mut stdin = self.stdin.lock().unwrap();
            stdin.write_all(&line).and_then(|()| stdin.flush())
        };
        let answer = sent.map_err(|_| gone()).and_then(|()| wait.recv_timeout(timeout).map_err(|_| gone()));
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
    link.xray.store(false, Ordering::SeqCst);
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
    link.tun.store(false, Ordering::SeqCst);
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

pub fn verify_kill_switch() -> Result<(), String> {
    expect_done(require()?.call(Command::VerifyKillSwitch, CALL_TIMEOUT)?)
}

pub fn verify_xray_listeners(ports: &[u16]) -> bool {
    require().and_then(|link| {
        expect_done(link.call(Command::VerifyXrayListeners { ports: ports.to_vec() }, Duration::from_secs(2))?)
    }).is_ok()
}

/// Only launch the helper installed by a system package. The AppImage runs as the user.
fn locate() -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;

    let installed = Path::new(INSTALLED).join(HELPER);
    let trusted = installed.ancestors().all(|path| {
        std::fs::symlink_metadata(path).is_ok_and(|meta| {
            !meta.is_symlink() && meta.uid() == 0 && meta.mode() & 0o022 == 0
                && if path == installed { meta.is_file() } else { meta.is_dir() }
        })
    });
    if trusted {
        Ok(installed)
    } else {
        Err("An installed Phi2ray helper is required. Install the matching system package to use VPN mode or the kill switch.".into())
    }
}
