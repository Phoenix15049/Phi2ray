//! Windows helpers: tie child processes to the app's lifetime, administrator elevation,
//! and the list of running apps for split tunnelling.

/// A running program, offered when adding apps to the split tunnel.
#[derive(serde::Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RunningApp {
    pub name: String,
    pub path: String,
}

#[cfg(windows)]
mod imp {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    /// The job handle, stored as usize because raw handles are not Send/Sync.
    static JOB: OnceLock<usize> = OnceLock::new();

    /// The job, or null if it couldn't be created with "kill on close".
    fn job() -> HANDLE {
        *JOB.get_or_init(|| unsafe {
            let job = CreateJobObjectW(null(), null());
            if job.is_null() {
                return 0;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let set = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                std::mem::size_of_val(&info) as u32,
            );
            if set == 0 {
                CloseHandle(job);
                return 0;
            }
            job as usize
        }) as HANDLE
    }

    /// Windows kills every process in our job when Phi2ray exits, even after a crash,
    /// so no orphaned core keeps tunnelling traffic. A core that can't be tied to the job
    /// must not run.
    pub fn bind_to_app(process: *mut c_void) -> Result<(), String> {
        let job = job();
        if job.is_null() || unsafe { AssignProcessToJobObject(job, process) } == 0 {
            return Err("Couldn't tie the core to Phi2ray's lifetime.".into());
        }
        Ok(())
    }

    /// For each of `ports`, the processes listening on it on 127.0.0.1 or all addresses.
    /// None when the table can't be read.
    pub fn listener_pids(ports: &[u16]) -> Option<Vec<Vec<u32>>> {
        let mut size = 0u32;
        unsafe { GetExtendedTcpTable(null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_LISTENER, 0) };
        for _ in 0..4 {
            // u32 elements keep the buffer aligned for the table's fields.
            let mut buf = vec![0u32; size as usize / 4 + 256];
            let mut len = (buf.len() * 4) as u32;
            let code = unsafe {
                GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut len, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_LISTENER, 0)
            };
            if code == ERROR_INSUFFICIENT_BUFFER {
                size = len;
                continue;
            }
            if code != 0 {
                return None;
            }
            let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize) };
            let loopback = u32::from_ne_bytes([127, 0, 0, 1]);
            return Some(
                ports
                    .iter()
                    .map(|&port| {
                        rows.iter()
                            .filter(|r| u16::from_be(r.dwLocalPort as u16) == port)
                            .filter(|r| r.dwLocalAddr == loopback || r.dwLocalAddr == 0)
                            .map(|r| r.dwOwningPid)
                            .collect()
                    })
                    .collect(),
            );
        }
        None
    }

    pub fn is_elevated() -> bool {
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    /// Programs currently running, one entry per executable, without Windows' own components.
    pub fn running_apps() -> Vec<super::RunningApp> {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};

        let mut apps = Vec::new();
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot.is_null() || snapshot as isize == -1 {
                return apps;
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut more = Process32FirstW(snapshot, &mut entry) != 0;
            while more {
                let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
                if !process.is_null() {
                    let mut buf = [0u16; 1024];
                    let mut len = buf.len() as u32;
                    if QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut len) != 0 {
                        let path = String::from_utf16_lossy(&buf[..len as usize]);
                        let name = path.rsplit('\\').next().unwrap_or(&path).to_string();
                        apps.push(super::RunningApp { name, path });
                    }
                    CloseHandle(process);
                }
                more = Process32NextW(snapshot, &mut entry) != 0;
            }
            CloseHandle(snapshot);
        }
        let windows_dir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()).to_ascii_lowercase();
        apps.retain(|a| !a.path.to_ascii_lowercase().starts_with(&windows_dir));
        apps.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()).then(a.path.cmp(&b.path)));
        apps.dedup_by(|a, b| a.path.eq_ignore_ascii_case(&b.path));
        apps
    }

    /// The real Windows folder, from the system rather than the (user-editable) environment.
    fn windows_dir() -> Option<std::path::PathBuf> {
        let mut buf = [0u16; 260];
        let len = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        (len > 0 && len < buf.len()).then(|| std::path::PathBuf::from(String::from_utf16_lossy(&buf[..len])))
    }

    /// Opens a web page in the default browser. Phi2ray runs as administrator, so the page is
    /// handed to Explorer, which opens it as the signed-in user instead of elevated.
    pub fn open_url(url: &str) -> Result<(), String> {
        let explorer = windows_dir().ok_or("Windows folder not found.")?.join("explorer.exe");
        std::process::Command::new(explorer).arg(url).spawn().map(drop).map_err(|e| e.to_string())
    }

    /// Starts a new elevated instance (UAC prompt). The caller should then exit.
    pub fn relaunch_as_admin() -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let wide = |s: &OsStr| s.encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let verb = wide(OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let result = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), file.as_ptr(), null(), null(), SW_SHOWNORMAL) };
        // ShellExecute returns a value greater than 32 on success.
        if result as isize > 32 {
            Ok(())
        } else {
            Err("Administrator permission was not granted.".into())
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn is_elevated() -> bool {
        true
    }

    pub fn relaunch_as_admin() -> Result<(), String> {
        Err("Run Phi2ray with sudo to use VPN mode.".into())
    }

    pub fn open_url(_url: &str) -> Result<(), String> {
        Err("Not supported on this system.".into())
    }

    pub fn listener_pids(_ports: &[u16]) -> Option<Vec<Vec<u32>>> {
        None
    }

    pub fn running_apps() -> Vec<super::RunningApp> {
        Vec::new()
    }
}

pub use imp::*;

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn finds_the_process_listening_on_a_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let owners = super::listener_pids(&[port, 1]).unwrap();
        assert_eq!(owners[0], vec![std::process::id()]);
        assert!(owners[1].is_empty());
    }
}
