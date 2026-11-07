//! Linux side of `platform.rs`. The app runs as the user here: everything that needs root goes
//! through the helper (see `helper.rs`).

use std::io;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, OnceLock};
use std::thread;

/// Folders of system components, left out of the list of running apps.
const SYSTEM_FOLDERS: [&str; 5] = ["/usr/libexec/", "/usr/lib/systemd/", "/lib/systemd/", "/usr/lib/polkit-1/", "/usr/lib/xorg/"];
/// Variables an AppImage sets for its bundled libraries, which would break the system's programs.
const APPIMAGE_VARIABLES: [&str; 8] = [
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "GSETTINGS_SCHEMA_DIR",
    "GIO_MODULE_DIR",
    "GTK_PATH",
    "GTK_EXE_PREFIX",
    "GDK_PIXBUF_MODULE_FILE",
    "PYTHONHOME",
];

/// Whether root's part is ready. On Linux the app itself never runs as root.
pub fn is_elevated() -> bool {
    crate::helper::running()
}

/// Gets root's part going, which asks for the password the first time.
pub fn elevate() -> Result<(), String> {
    crate::helper::ensure()
}

pub fn relaunch_as_admin() -> Result<(), String> {
    elevate()
}

/// The account the cores run as, for keeping them outside the tunnel.
pub fn core_uid() -> Option<u32> {
    crate::helper::core_uid()
}

/// The network's own DNS server. `/etc/resolv.conf` usually names a local stub (systemd-resolved)
/// whose questions would come back through the tunnel, so its real servers are read instead.
pub fn system_dns() -> Option<IpAddr> {
    ["/run/systemd/resolve/resolv.conf", "/run/NetworkManager/no-stub-resolv.conf", "/etc/resolv.conf"]
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .find_map(|text| crate::tun::first_nameserver(&text))
}

/// A system program, without what an AppImage changed in the environment.
pub fn host_command(program: &str) -> Command {
    let mut command = Command::new(program);
    if std::env::var_os("APPIMAGE").is_some() {
        for name in APPIMAGE_VARIABLES {
            command.env_remove(name);
        }
    }
    command
}

pub fn open_url(url: &str) -> Result<(), String> {
    host_command("xdg-open").arg(url).spawn().map(drop).map_err(|e| e.to_string())
}

pub fn listener_pids(ports: &[u16]) -> Option<Vec<Vec<u32>>> {
    crate::helper_protocol::listener_pids(ports)
}

/// Not used here: data lives in the user's own folder.
pub fn current_user_sid() -> Option<String> {
    None
}

/// Programs running under this account, one entry per executable, without system components.
pub fn running_apps() -> Vec<super::RunningApp> {
    let Ok(me) = std::fs::metadata("/proc/self").map(|m| m.uid()) else { return Vec::new() };
    let Ok(processes) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut apps = Vec::new();
    for process in processes.flatten() {
        if !process.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if !process.metadata().is_ok_and(|m| m.uid() == me) {
            continue;
        }
        let Ok(exe) = std::fs::read_link(process.path().join("exe")) else { continue };
        let path = exe.to_string_lossy();
        // An updated program still running from its old file.
        let path = path.strip_suffix(" (deleted)").unwrap_or(&path).to_string();
        if SYSTEM_FOLDERS.iter().any(|folder| path.starts_with(folder)) {
            continue;
        }
        let name = path.rsplit('/').next().unwrap_or(&path).to_string();
        apps.push(super::RunningApp { name, path });
    }
    apps.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()).then(a.path.cmp(&b.path)));
    apps.dedup_by(|a, b| a.path == b.path);
    apps
}

type SpawnRequest = (Command, Sender<io::Result<Child>>);

/// Starts a program that dies with the app, even after a crash. The kernel ties that to the
/// thread that started it, and worker threads come and go, so one thread that lives as long as
/// the app does the starting.
pub fn spawn_bound(mut command: Command) -> io::Result<Child> {
    static SPAWNER: OnceLock<Mutex<Sender<SpawnRequest>>> = OnceLock::new();
    let spawner = SPAWNER.get_or_init(|| {
        let (send, requests) = mpsc::channel::<SpawnRequest>();
        thread::spawn(move || {
            for (mut command, answer) in requests {
                let _ = answer.send(command.spawn());
            }
        });
        Mutex::new(send)
    });
    unsafe { command.pre_exec(die_with_parent) };
    let (answer, result) = mpsc::channel();
    let closed = || io::Error::other("the process starter stopped");
    spawner.lock().unwrap().send((command, answer)).map_err(|_| closed())?;
    result.recv().map_err(|_| closed())?
}

/// For `pre_exec`: the kernel kills this process when its parent thread ends.
pub fn die_with_parent() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
