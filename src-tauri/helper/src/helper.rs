use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as Process, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::protocol::{
    check_tun_config, listener_pids, nft_rules, ports_state, Command, Core, Message, Outcome, Ports, Request, CORE_USER,
    KILL_SWITCH_FLAG, MAX_REQUEST, NFT_REMOVE, VERSION,
};

/// sing-box's working folder (its cache).
const WORK_DIR: &str = "/var/lib/phi2ray";
const RUN_DIR: &str = "/run/phi2ray";
/// The VPN adapter's own address, which must match `tun.rs`.
const ADAPTER_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(172, 19, 0, 1);

// Capability numbers from <linux/capability.h>.
const CAP_DAC_READ_SEARCH: u32 = 2;
const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;
const CAP_SYS_PTRACE: u32 = 19;
/// What sing-box needs, the same list as its own systemd unit: the adapter and routes, and
/// (ptrace, read-search) seeing which program a connection belongs to, for split tunnelling.
const TUN_CAPS: [u32; 5] = [CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH];

#[derive(Clone, Copy)]
struct Account {
    uid: u32,
    gid: u32,
}

struct Running {
    xray: Option<Child>,
    tun: Option<Child>,
    tests: HashMap<u64, Child>,
}

struct Helper {
    cores: PathBuf,
    account: Account,
    running: Mutex<Running>,
    out: Mutex<std::io::Stdout>,
    next_test: AtomicU64,
}

pub fn run() {
    if let Err(e) = start() {
        eprintln!("phi2ray-helper: {e}");
        std::process::exit(1);
    }
}

fn start() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("this program is started by Phi2ray through pkexec".into());
    }
    let exe = fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?;
    let cores = exe.parent().ok_or("no folder")?.to_path_buf();
    for path in [cores.as_path(), &exe, &cores.join("xray"), &cores.join("sing-box")] {
        check_trusted(path)?;
    }
    make_dir(Path::new(RUN_DIR), 0o755, None)?;
    let _lock = single_instance()?;
    let account = core_account()?;
    make_dir(Path::new(WORK_DIR), 0o700, Some(account))?;

    let helper = Arc::new(Helper {
        cores,
        account,
        running: Mutex::new(Running { xray: None, tun: None, tests: HashMap::new() }),
        out: Mutex::new(std::io::stdout()),
        next_test: AtomicU64::new(1),
    });
    let watcher = helper.clone();
    thread::spawn(move || watcher.watch());

    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut line = Vec::new();
        match (&mut input).take(MAX_REQUEST).read_until(b'\n', &mut line) {
            Ok(n) if n > 0 && line.last() == Some(&b'\n') => {}
            // The app is gone (or sent something no app sends).
            _ => break,
        }
        let Ok(request) = serde_json::from_slice::<Request>(&line) else { break };
        helper.handle(request);
    }
    helper.stop_everything();
    Ok(())
}

/// The cores run from this folder, so nobody but root may be able to change anything in it.
fn check_trusted(path: &Path) -> Result<(), String> {
    let meta = fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(format!("{} must belong to root and be writable only by it", path.display()));
    }
    Ok(())
}

fn make_dir(path: &Path, mode: u32, owner: Option<Account>) -> Result<(), String> {
    let error = |e: std::io::Error| format!("cannot set up {}: {e}", path.display());
    fs::create_dir_all(path).map_err(error)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(error)?;
    if let Some(account) = owner {
        std::os::unix::fs::chown(path, Some(account.uid), Some(account.gid)).map_err(error)?;
    }
    Ok(())
}

/// Two helpers (two people logged in) would fight over the adapter and the firewall.
fn single_instance() -> Result<File, String> {
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(format!("{RUN_DIR}/helper.lock"))
        .map_err(|e| e.to_string())?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("Phi2ray is already connected from another account on this computer".into());
    }
    Ok(lock)
}

/// The cores' account, created the first time.
fn core_account() -> Result<Account, String> {
    if let Some(account) = find_account() {
        return Ok(account);
    }
    let useradd = ["/usr/sbin/useradd", "/sbin/useradd", "/usr/bin/useradd"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .ok_or("useradd wasn't found, so the cores' account can't be created")?;
    let status = Process::new(useradd)
        .args(["--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/bin/false", CORE_USER])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("cannot run useradd: {e}"))?;
    if !status.success() {
        return Err(format!("useradd failed ({status})"));
    }
    find_account().ok_or_else(|| format!("the {CORE_USER} account wasn't created"))
}

fn find_account() -> Option<Account> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    let fields: Vec<&str> = passwd.lines().find(|l| l.starts_with(&format!("{CORE_USER}:")))?.split(':').collect();
    let (uid, gid) = (fields.get(2)?.parse().ok()?, fields.get(3)?.parse().ok()?);
    (uid != 0 && gid != 0).then_some(Account { uid, gid })
}

impl Helper {
    fn send(&self, message: &Message) {
        let Ok(mut line) = serde_json::to_vec(message) else { return };
        line.push(b'\n');
        let mut out = self.out.lock().unwrap();
        // A write can only fail once the app is gone; stdin closes then too.
        let _ = out.write_all(&line).and_then(|()| out.flush());
    }

    fn reply(&self, id: u64, outcome: Outcome) {
        self.send(&Message::Reply { id, outcome });
    }

    /// Cores are started here, on the main thread: the signal that stops them if the helper dies
    /// is tied to the thread that started them. Waiting for them happens on a thread of its own.
    fn handle(self: &Arc<Self>, Request { id, command }: Request) {
        match command {
            Command::Hello { version } if version == VERSION => self.reply(id, Outcome::Hello { core_uid: self.account.uid }),
            Command::Hello { .. } => {
                self.reply(id, Outcome::Failed { error: "The helper belongs to a different version of Phi2ray. Reinstall it.".into() })
            }
            Command::StartXray { config, ports } => {
                let old = self.running.lock().unwrap().xray.take();
                stop(old);
                match self.xray(&config, "xray") {
                    Ok(child) => {
                        let pid = child.id();
                        self.running.lock().unwrap().xray = Some(child);
                        let helper = self.clone();
                        thread::spawn(move || helper.wait_for_xray(id, pid, ports));
                    }
                    Err(error) => self.reply(id, Outcome::Failed { error }),
                }
            }
            Command::StartTun { config } => {
                let old = self.running.lock().unwrap().tun.take();
                stop(old);
                match self.tun(&config) {
                    Ok(child) => {
                        self.running.lock().unwrap().tun = Some(child);
                        let helper = self.clone();
                        thread::spawn(move || helper.wait_for_adapter(id));
                    }
                    Err(error) => self.reply(id, Outcome::Failed { error }),
                }
            }
            Command::Stop { core } => {
                let mut running = self.running.lock().unwrap();
                let child = match core {
                    Core::Xray => running.xray.take(),
                    Core::Tun => running.tun.take(),
                };
                drop(running);
                stop(child);
                self.reply(id, Outcome::Done);
            }
            Command::StartTest { config, port } => match self.xray(&config, "") {
                Ok(child) => {
                    let (pid, test) = (child.id(), self.next_test.fetch_add(1, Ordering::SeqCst));
                    self.running.lock().unwrap().tests.insert(test, child);
                    let helper = self.clone();
                    thread::spawn(move || helper.wait_for_test(id, test, pid, port));
                }
                Err(error) => self.reply(id, Outcome::Failed { error }),
            },
            Command::StopTest { test } => {
                let child = self.running.lock().unwrap().tests.remove(&test);
                stop(child);
                self.reply(id, Outcome::Done);
            }
            Command::KillSwitch { on, allow_lan } => {
                let helper = self.clone();
                thread::spawn(move || {
                    let outcome = match helper.kill_switch(on, allow_lan) {
                        Ok(()) => Outcome::Done,
                        Err(error) => Outcome::Failed { error },
                    };
                    helper.reply(id, outcome);
                });
            }
        }
    }

    fn xray(self: &Arc<Self>, config: &str, tag: &'static str) -> Result<Child, String> {
        let mut process = Process::new(self.cores.join("xray"));
        process.env_clear().args(["run", "-format", "json", "-c", "stdin:"]).env("XRAY_LOCATION_ASSET", &self.cores);
        self.launch(process, config, tag, &[])
    }

    fn tun(self: &Arc<Self>, config: &str) -> Result<Child, String> {
        let parsed = serde_json::from_str(config).map_err(|e| format!("unreadable VPN config: {e}"))?;
        check_tun_config(&parsed, self.account.uid).map_err(|e| format!("refused VPN config: {e}"))?;
        let mut process = Process::new(self.cores.join("sing-box"));
        process.env_clear().args(["run", "-c", "stdin", "--disable-color", "-D", WORK_DIR]);
        self.launch(process, config, "tun", &TUN_CAPS)
    }

    /// Starts a core as the cores' account. Its config goes in through stdin, so no secret touches
    /// the disk. An empty `tag` discards its output.
    fn launch(self: &Arc<Self>, mut process: Process, config: &str, tag: &'static str, caps: &'static [u32]) -> Result<Child, String> {
        let account = self.account;
        process.current_dir("/").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // Runs in the new process, before the core does.
        unsafe { process.pre_exec(move || become_core(account, caps)) };
        let mut child = process.spawn().map_err(|e| format!("cannot start the core: {e}"))?;
        let mut stdin = child.stdin.take().ok_or("no stdin")?;
        let sent = stdin.write_all(config.as_bytes());
        drop(stdin);
        if let Err(e) = sent {
            stop(Some(child));
            return Err(format!("cannot send the core its config: {e}"));
        }
        if let Some(out) = child.stdout.take() {
            self.forward(tag, out);
        }
        if let Some(err) = child.stderr.take() {
            self.forward(tag, err);
        }
        Ok(child)
    }

    fn forward(self: &Arc<Self>, tag: &'static str, stream: impl Read + Send + 'static) {
        let helper = self.clone();
        thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if !tag.is_empty() {
                    helper.send(&Message::Log { tag: tag.to_string(), line });
                }
            }
        });
    }

    /// Ready once xray alone listens on all its ports; another program on one of them could pose
    /// as xray and receive what's meant for it.
    fn wait_for_xray(&self, id: u64, pid: u32, ports: Vec<u16>) {
        let outcome = match self.wait_ports(pid, &ports, |r| r.xray.as_mut()) {
            Ok(()) => Outcome::Done,
            Err(outcome) => {
                let mut running = self.running.lock().unwrap();
                if running.xray.as_ref().is_some_and(|c| c.id() == pid) {
                    let child = running.xray.take();
                    drop(running);
                    stop(child);
                }
                outcome
            }
        };
        self.reply(id, outcome);
    }

    fn wait_for_test(&self, id: u64, test: u64, pid: u32, port: u16) {
        let outcome = match self.wait_ports(pid, &[port], |r| r.tests.get_mut(&test)) {
            Ok(()) => Outcome::Test { test },
            Err(outcome) => {
                let child = self.running.lock().unwrap().tests.remove(&test);
                stop(child);
                outcome
            }
        };
        self.reply(id, outcome);
    }

    fn wait_ports(&self, pid: u32, ports: &[u16], child: impl Fn(&mut Running) -> Option<&mut Child>) -> Result<(), Outcome> {
        let failed = |error: &str| Outcome::Failed { error: error.to_string() };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            {
                let mut running = self.running.lock().unwrap();
                match child(&mut running).filter(|c| c.id() == pid).map(Child::try_wait) {
                    Some(Ok(None)) => {}
                    Some(Ok(Some(status))) => return Err(failed(&format!("Xray exited ({status}). See logs for details."))),
                    _ => return Err(failed("Xray was stopped.")),
                }
            }
            let owners = listener_pids(ports).ok_or_else(|| failed("Cannot read the list of open ports."))?;
            match ports_state(pid, ports, &owners) {
                Ports::Ready => return Ok(()),
                Ports::Taken(port) => return Err(Outcome::PortTaken { port }),
                Ports::Waiting => {}
            }
            if Instant::now() > deadline {
                return Err(failed("Xray did not start in time. See logs for details."));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Waits until the adapter actually has its address, so "connected" is never shown while
    /// traffic would still take the normal route.
    fn wait_for_adapter(&self, id: u64) {
        let deadline = Instant::now() + Duration::from_secs(25);
        let outcome = loop {
            {
                let mut running = self.running.lock().unwrap();
                match running.tun.as_mut().map(Child::try_wait) {
                    Some(Ok(None)) => {}
                    Some(Ok(Some(status))) => {
                        running.tun = None;
                        break Outcome::Failed { error: format!("VPN adapter failed to start ({status}). See logs for details.") };
                    }
                    _ => break Outcome::Failed { error: "The VPN adapter was stopped.".into() },
                }
            }
            if std::net::UdpSocket::bind((ADAPTER_V4, 0)).is_ok() {
                // Routes are set right after the address; give them a moment.
                thread::sleep(Duration::from_millis(300));
                break Outcome::Done;
            }
            if Instant::now() > deadline {
                let child = self.running.lock().unwrap().tun.take();
                stop(child);
                break Outcome::Failed { error: "The VPN adapter didn't come up in time. See logs for details.".into() };
            }
            thread::sleep(Duration::from_millis(100));
        };
        self.reply(id, outcome);
    }

    fn kill_switch(&self, on: bool, allow_lan: bool) -> Result<(), String> {
        let script = if on { nft_rules(self.account.uid, allow_lan) } else { NFT_REMOVE.to_string() };
        let nft = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .ok_or("The kill switch needs nftables, which isn't installed.")?;
        let mut process = Process::new(nft)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Kill switch: cannot run nft: {e}"))?;
        if let Some(mut stdin) = process.stdin.take() {
            stdin.write_all(script.as_bytes()).map_err(|e| format!("Kill switch: {e}"))?;
        }
        let result = process.wait_with_output().map_err(|e| format!("Kill switch: {e}"))?;
        if !result.status.success() {
            return Err(format!("Kill switch: nft failed: {}", String::from_utf8_lossy(&result.stderr).trim()));
        }
        if on {
            fs::write(KILL_SWITCH_FLAG, b"on\n").map_err(|e| format!("Kill switch: {e}"))
        } else {
            match fs::remove_file(KILL_SWITCH_FLAG) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("Kill switch: {e}")),
                _ => Ok(()),
            }
        }
    }

    /// Tells the app when a core stops by itself. The app decides what happens next.
    fn watch(&self) {
        loop {
            thread::sleep(Duration::from_millis(500));
            let mut exited = Vec::new();
            {
                let mut running = self.running.lock().unwrap();
                let Running { xray, tun, .. } = &mut *running;
                for (core, slot) in [(Core::Xray, xray), (Core::Tun, tun)] {
                    if let Some(Ok(Some(status))) = slot.as_mut().map(Child::try_wait) {
                        *slot = None;
                        exited.push((core, status.to_string()));
                    }
                }
            }
            for (core, status) in exited {
                self.send(&Message::Exited { core, status });
            }
        }
    }

    /// The adapter goes first, so traffic is never routed to a dead proxy. The kill switch stays.
    fn stop_everything(&self) {
        let mut running = self.running.lock().unwrap();
        stop(running.tun.take());
        stop(running.xray.take());
        for (_, child) in running.tests.drain() {
            stop(Some(child));
        }
    }
}

fn stop(child: Option<Child>) {
    if let Some(mut child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Turns the new process into the cores' account, holding `caps` and nothing else. Runs between
/// fork and exec, so it only makes system calls.
fn become_core(account: Account, caps: &[u32]) -> std::io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    let check = |result: libc::c_int| if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) };
    let mask = caps.iter().fold(0u32, |mask, cap| mask | 1 << cap);
    unsafe {
        // No way back to anything else, even for a program it starts. Needs root, so it's first.
        for cap in 0..64u32 {
            if !caps.contains(&cap) && libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) != 0 {
                // Numbers past the last capability this kernel knows.
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINVAL) {
                    return Err(error);
                }
            }
        }
        check(libc::setgroups(0, std::ptr::null()))?;
        check(libc::setresgid(account.gid, account.gid, account.gid))?;
        check(libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0))?;
        check(libc::setresuid(account.uid, account.uid, account.uid))?;

        let header = Header { version: CAPABILITY_VERSION_3, pid: 0 };
        let data = [Data { effective: mask, permitted: mask, inheritable: mask }, Data::default()];
        check(libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) as libc::c_int)?;
        // Ambient capabilities are what survive into the core, which has none on its file.
        for &cap in caps {
            check(libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, cap as libc::c_ulong, 0, 0))?;
        }
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
        // Changing accounts clears this one, so it comes last: the core dies with the helper.
        check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0))?;
    }
    Ok(())
}
