//! Single-exe releases (`--features embed-cores`) carry xray, sing-box and their data files
//! inside Phi2ray.exe. On start they're unpacked to `Program Files\Phi2ray`, checked against
//! the hashes recorded at build time, and kept open with writing blocked until Phi2ray exits.
//!
//! Why this matters: Phi2ray runs elevated and starts these programs elevated too, so anyone
//! able to swap one of them would gain admin rights.
//! - Program Files only lets administrators create or change folders, so nobody else can
//!   create the folder first, plant a link in its place, or keep write access to it.
//! - Its location comes from the system (a known folder), not from environment variables,
//!   which any user can redefine for their own programs.
//! - Holding the files open without write or delete sharing means the bytes that passed the
//!   hash check are the bytes that run, every time, with no re-check race.

use std::path::{Path, PathBuf};

pub use imp::EMBEDDED;

/// Where single-exe builds keep their cores, or None for builds that use a core folder.
pub fn target_dir() -> Option<Result<PathBuf, String>> {
    imp::target_dir()
}

/// Unpacks (when needed), verifies and locks every embedded file in `dir`.
pub fn install(dir: &Path) -> Result<(), String> {
    imp::install(dir)
}

/// Whether `exe` is one of the verified, locked files. Single-exe builds run nothing else.
pub fn trusted(exe: &Path) -> bool {
    imp::trusted(exe)
}

#[cfg(feature = "embed-cores")]
mod imp {
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use std::ptr::null_mut;
    use std::sync::Mutex;

    use sha2::{Digest, Sha256};
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

    pub const EMBEDDED: bool = true;

    /// Others may read (and run) the file, but not write, rename or delete it.
    const FILE_SHARE_READ: u32 = 0x1;

    pub struct EmbeddedFile {
        pub name: &'static str,
        pub sha256: &'static str,
        pub data: &'static [u8],
    }

    include!(concat!(env!("OUT_DIR"), "/embedded_cores.rs"));

    /// Verified files and their open handles, held for the app's lifetime.
    static LOCKED: Mutex<Vec<(PathBuf, File)>> = Mutex::new(Vec::new());

    pub fn target_dir() -> Option<Result<PathBuf, String>> {
        let dir = program_files()
            .map(|p| p.join("Phi2ray").join(format!("core-{}", env!("CARGO_PKG_VERSION"))))
            .ok_or_else(|| "Cannot find the Program Files folder.".to_string());
        Some(dir)
    }

    pub fn install(dir: &Path) -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
        let mut locked = LOCKED.lock().unwrap();
        locked.clear();
        for file in FILES {
            let path = dir.join(file.name);
            let handle = match lock_verified(&path, file) {
                Ok(handle) => handle,
                Err(_) => {
                    unpack(dir, file)?;
                    lock_verified(&path, file)?
                }
            };
            locked.push((path, handle));
        }
        drop(locked);
        remove_old_versions(dir);
        Ok(())
    }

    /// Cores unpacked by earlier versions of Phi2ray are never used again: they are removed
    /// (best effort, so a folder still in use by another copy simply stays).
    fn remove_old_versions(current: &Path) {
        let (Some(parent), Some(name)) = (current.parent(), current.file_name()) else { return };
        let Ok(entries) = fs::read_dir(parent) else { return };
        for entry in entries.flatten() {
            let old = entry.file_name();
            let is_core = old.to_string_lossy().starts_with("core-");
            // Real folders only: a link is never followed into, just left alone.
            if is_core && old != name && entry.file_type().is_ok_and(|t| t.is_dir()) {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }

    pub fn trusted(exe: &Path) -> bool {
        LOCKED.lock().unwrap().iter().any(|(path, _)| path == exe)
    }

    /// Opens `path` with writing blocked, then checks the content through that same handle.
    fn lock_verified(path: &Path, file: &EmbeddedFile) -> Result<File, String> {
        let mut handle = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
        let mut bytes = Vec::new();
        handle.read_to_end(&mut bytes).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if hex::encode(Sha256::digest(&bytes)) != file.sha256 {
            return Err(format!("{} failed its integrity check", file.name));
        }
        Ok(handle)
    }

    fn unpack(dir: &Path, file: &EmbeddedFile) -> Result<(), String> {
        let data = zstd::decode_all(file.data).map_err(|e| format!("Cannot unpack {}: {e}", file.name))?;
        let tmp = dir.join(format!("{}.tmp", file.name));
        let _ = fs::remove_file(&tmp);
        fs::write(&tmp, &data).map_err(|e| format!("Cannot write {}: {e}", tmp.display()))?;
        let path = dir.join(file.name);
        fs::rename(&tmp, &path).map_err(|e| format!("Cannot replace {}: {e}", path.display()))
    }

    /// `C:\Program Files`, as registered with the system.
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

#[cfg(not(feature = "embed-cores"))]
mod imp {
    use std::path::{Path, PathBuf};

    pub const EMBEDDED: bool = false;

    pub fn target_dir() -> Option<Result<PathBuf, String>> {
        None
    }

    pub fn install(_dir: &Path) -> Result<(), String> {
        Ok(())
    }

    /// Builds without embedded cores check them with the `.sha256` pins instead (see `xray::verify`).
    pub fn trusted(_exe: &Path) -> bool {
        true
    }
}
