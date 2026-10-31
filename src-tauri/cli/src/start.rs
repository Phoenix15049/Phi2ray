//! `phi2ray start`: launches the app into the tray, then waits until it takes commands.
//!
//! The app is started from where it recorded itself (`Program Files\Phi2ray\bin\app.json`,
//! which only administrators can write), and only if the file there is still the exact one it
//! recorded. The exe often sits in a folder the user's programs can write to, and Windows asks
//! to run it as administrator, so a swapped file must never be started. The file is held open
//! with writing blocked from the check until Windows has started it, so it can't be swapped
//! in between.

use std::time::{Duration, Instant};

use crate::{pipe, Failure};

pub fn launch() -> Result<(), Failure> {
    let process = imp::start()?;
    eprintln!("Starting Phi2ray...");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let request = crate::ipc::Request { version: crate::ipc::VERSION, command: crate::ipc::Command::Status };
        match pipe::request(&request, |_| {}) {
            Ok(_) => return Ok(()),
            Err(f) if f.code != pipe::NOT_RUNNING => return Err(f),
            Err(_) => {}
        }
        if process.exited() {
            // Another copy was already running: the new one just brought its window forward.
            return Err("Phi2ray is already running, but console control is off. Turn it on in Settings → Console.".into());
        }
        if Instant::now() > deadline {
            return Err("Phi2ray didn't start in time.".into());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[cfg(windows)]
mod imp {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::ptr::null_mut;

    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramFiles, SHGetKnownFolderPath, ShellExecuteExW, KF_FLAG_DEFAULT, SEE_MASK_NOASYNC,
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    use crate::Failure;

    /// Others may read (and run) the file, but not change, rename or delete it.
    const FILE_SHARE_READ: u32 = 0x1;

    #[derive(serde::Deserialize)]
    struct Record {
        path: PathBuf,
        sha256: String,
    }

    pub struct Process(HANDLE);

    impl Process {
        pub fn exited(&self) -> bool {
            !self.0.is_null() && unsafe { WaitForSingleObject(self.0, 0) } == WAIT_OBJECT_0
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    pub fn start() -> Result<Process, Failure> {
        let unknown = || -> Failure {
            "Phi2ray's location isn't known yet. Open Phi2ray yourself once, with console control on.".into()
        };
        let record_path = program_files().ok_or_else(unknown)?.join("Phi2ray").join("bin").join("app.json");
        let record: Record =
            serde_json::from_slice(&std::fs::read(&record_path).map_err(|_| unknown())?).map_err(|_| unknown())?;

        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&record.path)
            .map_err(|e| format!("cannot open {}: {e}. Open Phi2ray yourself once.", record.path.display()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| format!("cannot read {}: {e}", record.path.display()))?;
        let hash: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        if !hash.eq_ignore_ascii_case(&record.sha256) {
            return Err(format!(
                "{} changed since Phi2ray last ran, so it wasn't started. Open it yourself if you replaced it.",
                record.path.display()
            )
            .into());
        }

        let wide = |s: &std::ffi::OsStr| s.encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let verb = wide("open".as_ref());
        let exe = wide(record.path.as_os_str());
        let args = wide("--hidden".as_ref());
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = exe.as_ptr();
        info.lpParameters = args.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        // Windows asks for administrator permission here, since Phi2ray needs it.
        let ok = unsafe { ShellExecuteExW(&mut info) } != 0;
        drop(file);
        if !ok {
            return Err(match unsafe { GetLastError() } {
                ERROR_CANCELLED => "Starting Phi2ray was cancelled.".to_string().into(),
                code => format!("cannot start Phi2ray (error {code})").into(),
            });
        }
        Ok(Process(info.hProcess))
    }

    /// `C:\Program Files`, as registered with the system (not from environment variables).
    fn program_files() -> Option<PathBuf> {
        let mut raw = null_mut();
        let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT as _, null_mut(), &mut raw) };
        let path = (hr >= 0 && !raw.is_null()).then(|| {
            let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
            PathBuf::from(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) }))
        });
        unsafe { CoTaskMemFree(raw as _) };
        path.filter(|p| p.is_absolute())
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::Failure;

    pub struct Process;

    impl Process {
        pub fn exited(&self) -> bool {
            true
        }
    }

    pub fn start() -> Result<Process, Failure> {
        Err("Starting Phi2ray from the console is only supported on Windows for now.".into())
    }
}
