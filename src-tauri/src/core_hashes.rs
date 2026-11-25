use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::{self, Read}, path::Path};

#[cfg(windows)]
const MANIFEST: &str = include_str!("../core/SHA256SUMS");
#[cfg(not(windows))]
const MANIFEST: &str = include_str!("../core/SHA256SUMS.linux");

pub fn verify(path: &Path) -> Result<(), String> {
    let name = path.file_name().and_then(|n| n.to_str()).ok_or("Invalid core file name.")?;
    let expected = MANIFEST.lines().find_map(|line| {
        let (hash, file) = line.split_once(char::is_whitespace)?;
        (file.trim().trim_start_matches('*') == name).then_some(hash)
    }).ok_or_else(|| format!("{name} has no trusted hash in this version of Phi2ray."))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| format!("Cannot read {name}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("Cannot inspect {name}: {e}"))?;
    if !meta.is_file() || meta.len() > 512 * 1024 * 1024 {
        return Err(format!("Cannot verify {name}: expected a regular core file."));
    }
    let mut file = file.take(meta.len() + 1);
    let mut sha = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("Cannot read {name}: {e}")),
        };
        sha.update(&buffer[..read]);
    }
    if file.limit() != 1 || format!("{:x}", sha.finalize()) != expected {
        return Err(format!("{name} does not match the trusted hash for this version of Phi2ray."));
    }
    Ok(())
}

pub fn verify_launch(path: &Path) -> Result<(), String> {
    verify(path)?;
    if matches!(path.file_name().and_then(|n| n.to_str()), Some("xray" | "xray.exe")) {
        let runtime = if cfg!(windows) { "libcronet.dll" } else { "libcronet.so" };
        for name in [runtime, "geoip.dat", "geosite.dat"] {
            let companion = path.with_file_name(name);
            match std::fs::symlink_metadata(&companion) {
                Ok(_) => verify(&companion)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("Cannot verify {name}: {e}")),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_hash_cannot_authorize_an_untrusted_binary() {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("phi2ray-core-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let name = if cfg!(windows) { "xray.exe" } else { "xray" };
        let bytes = b"not an executable";
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        let sidecar = dir.join(format!("{name}.sha256"));
        std::fs::write(&sidecar, format!("{:x}", Sha256::digest(bytes))).unwrap();
        assert!(verify(&path).unwrap_err().contains("trusted hash"));
        assert!(verify(&dir.join("unknown")).unwrap_err().contains("no trusted hash"));
        std::fs::remove_file(sidecar).unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
