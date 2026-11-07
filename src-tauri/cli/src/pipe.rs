//! The tool's end of the pipe to the app.
//!
//! On Windows, before anything is sent, the pipe must belong to Administrators. Phi2ray runs elevated and
//! creates it that way; a program posing as Phi2ray (one that took the pipe name while the app
//! wasn't running) can't, since it isn't elevated, and is refused. The app also never lets
//! the user's programs open server ends of its pipe (see the app's `console.rs`).

use std::io::{BufRead, BufReader, Write};

use serde_json::Value;

use crate::ipc::{Reply, Request};
use crate::Failure;

/// Exit code (and failure code) when the app isn't reachable.
pub const NOT_RUNNING: u8 = 3;

pub fn request(request: &Request, mut progress: impl FnMut(Value)) -> Result<Value, Failure> {
    let pipe = imp::open()?;
    let mut line = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    line.push(b'\n');
    (&pipe).write_all(&line).map_err(|e| format!("cannot talk to Phi2ray: {e}"))?;
    for line in BufReader::new(&pipe).lines() {
        let line = line.map_err(|e| format!("Phi2ray stopped answering: {e}"))?;
        match serde_json::from_str::<Reply>(&line).map_err(|e| format!("unexpected answer from Phi2ray: {e}"))? {
            Reply::Progress { data } => progress(data),
            Reply::Done { data } => return Ok(data),
            Reply::Failed { error } => return Err(error.into()),
        }
    }
    Err("Phi2ray closed the connection without answering.".into())
}

fn not_running() -> Failure {
    Failure {
        message: "Phi2ray isn't running, or console control is off (Settings → Console). \
                  Start it with `phi2ray start`."
            .into(),
        code: NOT_RUNNING,
    }
}

#[cfg(windows)]
mod imp {
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::not_running;
    use crate::Failure;

    /// Read and write data, read attributes and the owner: exactly what the app grants.
    const ACCESS: u32 = 0x120083;

    pub fn open() -> Result<File, Failure> {
        let sid = current_user_sid().ok_or("cannot tell which Windows account this is")?;
        let name: Vec<u16> = crate::ipc::pipe_name(&sid).encode_utf16().chain(Some(0)).collect();
        for _ in 0..5 {
            // Identification only: the other end may learn who we are, never act as us.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    ACCESS,
                    0,
                    null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                if let Err(e) = check_owner(handle) {
                    unsafe { CloseHandle(handle) };
                    return Err(e);
                }
                return Ok(unsafe { File::from_raw_handle(handle) });
            }
            match unsafe { GetLastError() } {
                ERROR_FILE_NOT_FOUND => return Err(not_running()),
                ERROR_PIPE_BUSY => {
                    unsafe { WaitNamedPipeW(name.as_ptr(), 3000) };
                }
                ERROR_ACCESS_DENIED => {
                    return Err("Phi2ray refused the connection: it seems to run under another Windows account.".into())
                }
                code => return Err(format!("cannot reach Phi2ray (error {code})").into()),
            }
        }
        Err("Phi2ray is busy. Try again.".into())
    }

    /// The pipe must be owned by Administrators (see the module comment). Development builds
    /// of the tool also accept a pipe from an unelevated development build of the app.
    fn check_owner(handle: HANDLE) -> Result<(), Failure> {
        let mut owner: PSID = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let code = unsafe {
            GetSecurityInfo(handle, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, null_mut(), null_mut(), null_mut(), &mut sd)
        };
        let admin = code == 0 && !owner.is_null() && unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) } != 0;
        if !sd.is_null() {
            unsafe { LocalFree(sd as _) };
        }
        if admin || cfg!(debug_assertions) {
            Ok(())
        } else {
            Err("Something other than Phi2ray answered on its pipe, so nothing was sent. \
                 Restart Phi2ray, and check this computer for unwanted programs."
                .into())
        }
    }

    fn current_user_sid() -> Option<String> {
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            // u64 elements keep the buffer aligned for the pointer inside TOKEN_USER.
            let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len);
            CloseHandle(token);
            if ok == 0 {
                return None;
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut text = null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 || text.is_null() {
                return None;
            }
            let n = (0..).take_while(|&i| *text.add(i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
            LocalFree(text as _);
            sid.starts_with("S-1-").then_some(sid)
        }
    }
}

/// A Unix socket in the user's own runtime folder. The app runs as the user on Linux, so there's
/// no owner to check it against; the folder itself must be ours, though.
#[cfg(not(windows))]
mod imp {
    use std::io::ErrorKind;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;

    use super::not_running;
    use crate::Failure;

    pub fn open() -> Result<UnixStream, Failure> {
        let path = crate::ipc::socket_path().ok_or("XDG_RUNTIME_DIR isn't set, so Phi2ray can't be found")?;
        let me = std::fs::metadata("/proc/self").map_err(|e| e.to_string())?.uid();
        match path.parent().map(std::fs::symlink_metadata) {
            Some(Ok(dir)) if dir.is_dir() && dir.uid() == me => {}
            Some(Ok(_)) => return Err("The console folder doesn't belong to this account, so nothing was sent.".into()),
            _ => return Err(not_running()),
        }
        UnixStream::connect(&path).map_err(|e| match e.kind() {
            ErrorKind::NotFound | ErrorKind::ConnectionRefused => not_running(),
            _ => format!("cannot reach Phi2ray: {e}").into(),
        })
    }
}
