//! Single-exe releases (`--features embed-cores`) carry xray, sing-box and their data files
//! inside Phi2ray.exe. On start they're unpacked to a folder only administrators can write to,
//! and every file is checked against the hash recorded at build time.
//!
//! Why that folder matters: Phi2ray runs elevated and starts these programs elevated too, so a
//! user-writable location would let any unprivileged program swap xray.exe and gain admin rights.

use std::path::PathBuf;

/// Where the cores were unpacked, or None for builds that don't embed them.
pub fn install() -> Result<Option<PathBuf>, String> {
    imp::install()
}

#[cfg(feature = "embed-cores")]
mod imp {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use sha2::{Digest, Sha256};

    pub struct EmbeddedFile {
        pub name: &'static str,
        pub sha256: &'static str,
        pub data: &'static [u8],
    }

    include!(concat!(env!("OUT_DIR"), "/embedded_cores.rs"));

    pub fn install() -> Result<Option<PathBuf>, String> {
        let program_data = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        let dir = Path::new(&program_data).join("Phi2ray").join(format!("core-{}", env!("CARGO_PKG_VERSION")));
        fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
        lock_down(&dir)?;

        for file in FILES {
            let path = dir.join(file.name);
            let intact = fs::read(&path).map(|bytes| hex::encode(Sha256::digest(&bytes)) == file.sha256).unwrap_or(false);
            if !intact {
                let data = zstd::decode_all(file.data).map_err(|e| format!("Cannot unpack {}: {e}", file.name))?;
                let tmp = dir.join(format!("{}.tmp", file.name));
                // Remove anything planted under this name first (a link would redirect the write).
                let _ = fs::remove_file(&tmp);
                fs::write(&tmp, &data).map_err(|e| format!("Cannot write {}: {e}", tmp.display()))?;
                fs::rename(&tmp, &path).map_err(|e| format!("Cannot replace {}: {e}", path.display()))?;
            }
            // The hash pin makes every later start of this core re-check it (see xray::verify).
            let pin = dir.join(format!("{}.sha256", file.name));
            let _ = fs::remove_file(&pin);
            fs::write(&pin, file.sha256).map_err(|e| format!("Cannot write {}: {e}", pin.display()))?;
        }
        Ok(Some(dir))
    }

    /// Owner: Administrators. Write: Administrators and SYSTEM only. Everyone else: read/run.
    /// Inheritance from ProgramData (where any user may create files) is removed.
    fn lock_down(dir: &Path) -> Result<(), String> {
        let icacls = |target: &Path, args: &[&str]| -> Result<(), String> {
            let mut cmd = Command::new("icacls");
            cmd.arg(target).args(args);
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(crate::xray::CREATE_NO_WINDOW);
            }
            let out = cmd.output().map_err(|e| format!("icacls failed: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(format!("Cannot secure {}: {}", dir.display(), String::from_utf8_lossy(&out.stdout).trim()))
            }
        };
        // Take ownership of the folder and anything already in it (someone else may have planted files).
        icacls(dir, &["/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"])?;
        // The rules go on the folder only. Its (OI)(CI) flags make files inherit them; applied to
        // files directly they don't work and leave the files unreadable even for administrators.
        icacls(
            dir,
            &["/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/Q"],
        )?;
        // Existing files go back to inheriting from the folder (this also repairs files left
        // unreadable by earlier versions). Fails harmlessly when the folder is still empty.
        let _ = icacls(&dir.join("*"), &["/reset", "/C", "/Q"]);
        Ok(())
    }
}

#[cfg(not(feature = "embed-cores"))]
mod imp {
    use std::path::PathBuf;

    pub fn install() -> Result<Option<PathBuf>, String> {
        Ok(None)
    }
}
