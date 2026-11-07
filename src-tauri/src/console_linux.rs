//! Linux side of console control: a Unix socket in `$XDG_RUNTIME_DIR/phi2ray`. That folder belongs
//! to the user and only they can enter it, and the app also checks who connected. Unlike on
//! Windows the app runs as the user here, so programs running as the user could pose as it; the
//! command has nothing more to give them than they could read by themselves.

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::ipc::{socket_path, Reply, MAX_REQUEST};

/// Answers one request through the given sender; true if the app should then quit.
pub type Handler = Box<dyn Fn(&[u8], &mut dyn FnMut(&Reply)) -> bool + Send + Sync>;

/// What the socket does with requests, kept apart from the app so it can be tested alone.
pub struct Hooks {
    pub handle: Handler,
    pub quit: Box<dyn Fn() + Send + Sync>,
    pub log: Box<dyn Fn(String) + Send + Sync>,
}

/// Requests handled at once; more get a "busy" answer instead of a thread each.
const MAX_CLIENTS: usize = 4;
/// A tool that connects but doesn't send its request in time is dropped.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

struct Listening {
    path: PathBuf,
    stop: Arc<AtomicBool>,
}

static LISTENING: Mutex<Option<Listening>> = Mutex::new(None);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

fn own_uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn start(hooks: Hooks) -> Result<(), String> {
    let path = socket_path().ok_or("cannot listen for console commands: XDG_RUNTIME_DIR isn't set")?;
    start_at(hooks, path)
}

fn start_at(hooks: Hooks, path: PathBuf) -> Result<(), String> {
    let mut listening = LISTENING.lock().unwrap();
    if listening.is_some() {
        return Ok(());
    }
    let error = |e: std::io::Error| format!("cannot listen for console commands: {e}");
    let dir = path.parent().ok_or("no folder for the console socket")?;
    fs::create_dir_all(dir).map_err(error)?;
    let meta = fs::symlink_metadata(dir).map_err(error)?;
    if !meta.is_dir() || meta.uid() != own_uid() {
        return Err(format!("{} doesn't belong to this account.", dir.display()));
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(error)?;
    // A socket left by a crash. Only one copy of the app runs, so nothing is listening on it.
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(error)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(error)?;

    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    thread::spawn(move || accept(Arc::new(hooks), listener, flag));
    *listening = Some(Listening { path, stop });
    Ok(())
}

pub fn stop() {
    let Some(listening) = LISTENING.lock().unwrap().take() else { return };
    listening.stop.store(true, Ordering::SeqCst);
    // Wake the waiting thread by connecting once; it sees the flag and closes the socket.
    let _ = UnixStream::connect(&listening.path);
    let _ = fs::remove_file(&listening.path);
}

fn accept(hooks: Arc<Hooks>, listener: UnixListener, stop: Arc<AtomicBool>) {
    for client in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok(mut client) = client else { continue };
        if peer_uid(&client) != Some(own_uid()) {
            (hooks.log)("[app] Console control: refused a connection from another account".into());
            continue;
        }
        if ACTIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
            let _ = reply(&mut client, &Reply::Failed { error: "Phi2ray is busy with other commands. Try again.".into() });
            continue;
        }
        let hooks = hooks.clone();
        thread::spawn(move || {
            serve(&hooks, client);
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Who is at the other end, from the kernel.
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut credentials as *mut _ as *mut libc::c_void, &mut size)
    };
    (result == 0).then_some(credentials.uid)
}

fn serve(hooks: &Hooks, mut client: UnixStream) {
    let Some(request) = read_request(&mut client) else { return };
    let mut gone = false;
    let quit = (hooks.handle)(&request, &mut |r| {
        // Once the tool is gone (Ctrl+C), the rest of the answer has nowhere to go.
        if !gone && reply(&mut client, r).is_err() {
            gone = true;
        }
    });
    drop(client);
    if quit {
        (hooks.quit)();
    }
}

/// One line, with a time limit so a client that never sends can't hold a thread.
fn read_request(client: &mut UnixStream) -> Option<Vec<u8>> {
    client.set_read_timeout(Some(REQUEST_TIMEOUT)).ok()?;
    let mut data = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = client.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(end) = data.iter().position(|&b| b == b'\n') {
            data.truncate(end);
            return Some(data);
        }
        if data.len() > MAX_REQUEST {
            return None;
        }
    }
}

fn reply(client: &mut UnixStream, reply: &Reply) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(reply).unwrap_or_default();
    line.push(b'\n');
    client.write_all(&line)
}

/// Packages put the command in `/usr/bin`. An AppImage has it inside, so while the setting is on
/// it's copied to `~/.local/bin`, with a note of where the AppImage is for `phi2ray start`.
pub fn publish_tool(enabled: bool) -> Result<(), String> {
    let (Some(app_dir), Some(image)) = (std::env::var_os("APPDIR"), std::env::var_os("APPIMAGE")) else { return Ok(()) };
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or("HOME isn't set")?;
    let tool = home.join(".local/bin/phi2ray");
    let record = crate::ipc::app_record(&home);
    if !enabled {
        let _ = fs::remove_file(&tool);
        let _ = fs::remove_file(&record);
        return Ok(());
    }
    let error = |e: std::io::Error| format!("cannot install the phi2ray command: {e}");
    for parent in [tool.parent(), record.parent()].into_iter().flatten() {
        fs::create_dir_all(parent).map_err(error)?;
    }
    replace(&Path::new(&app_dir).join("usr/bin/phi2ray"), &tool).map_err(error)?;
    fs::write(&record, image.as_encoded_bytes()).map_err(error)
}

/// Through a temporary file, since a running program's file can't be overwritten.
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    let tmp = to.with_extension("tmp");
    fs::copy(from, &tmp)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&tmp, to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    #[test]
    fn the_console_socket_answers_and_stops() {
        let folder = std::env::temp_dir().join(format!("phi2ray-console-{}", std::process::id()));
        let path = folder.join("console.sock");
        let hooks = Hooks {
            handle: Box::new(|request, send| {
                assert_eq!(request, b"hello");
                send(&Reply::Done { data: serde_json::json!("hi") });
                false
            }),
            quit: Box::new(|| {}),
            log: Box::new(|_| {}),
        };
        start_at(hooks, path.clone()).unwrap();
        let mode = fs::metadata(&folder).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        let mut client = UnixStream::connect(&path).unwrap();
        client.write_all(b"hello\n").unwrap();
        let mut line = String::new();
        BufReader::new(&client).read_line(&mut line).unwrap();
        assert!(line.contains("hi"));

        stop();
        assert!(UnixStream::connect(&path).is_err());
        let _ = fs::remove_dir_all(folder);
    }
}
