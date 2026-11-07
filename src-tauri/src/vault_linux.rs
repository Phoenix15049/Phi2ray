//! Encrypts the store on Linux, with a key kept in the desktop's keyring (GNOME Keyring, KWallet)
//! through the Secret Service. As with DPAPI on Windows, the file alone is useless on another
//! computer, while programs running as this user can still ask for the key.
//!
//! Some systems have no keyring at all. There the key goes into a file only this user can read,
//! which protects less: it stays with the data if the whole folder is copied.
//!
//! The file says which kind of key it needs. A keyring that exists but can't be reached right now
//! must not look like a damaged store, so that case has its own error (`KEY_UNAVAILABLE`).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use secret_service::blocking::SecretService;
use secret_service::EncryptionType;

use super::KEY_UNAVAILABLE;

const MAGIC: &[u8; 4] = b"P2V1";
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
/// Long enough to type a keyring password, should the system ask for it.
const KEYRING_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum Kind {
    Keyring = 1,
    File = 2,
}

type Secret = [u8; KEY_LEN];

/// The folder for the key file, set once at startup.
static FOLDER: OnceLock<PathBuf> = OnceLock::new();
/// Keys already fetched, so saving never talks to the keyring again.
static KEYS: Mutex<Vec<(u8, Secret)>> = Mutex::new(Vec::new());

pub fn set_folder(folder: PathBuf) {
    let _ = FOLDER.set(folder);
}

fn key_file() -> Result<PathBuf, String> {
    FOLDER.get().map(|f| f.join("store.key")).ok_or_else(|| "no folder for the key".to_string())
}

fn cached(kind: Kind) -> Option<Secret> {
    KEYS.lock().unwrap().iter().find(|(k, _)| *k == kind as u8).map(|(_, key)| *key)
}

fn remember(kind: Kind, key: Secret) -> Secret {
    KEYS.lock().unwrap().push((kind as u8, key));
    key
}

fn attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([("application", "phi2ray"), ("purpose", "store")])
}

/// Looks the key up in the keyring, or adds a new one when `create` is set.
fn keyring_query(create: bool) -> Result<Option<Secret>, String> {
    let text = |e: secret_service::Error| e.to_string();
    let service = SecretService::connect(EncryptionType::Dh).map_err(text)?;
    let collection = service.get_default_collection().map_err(text)?;
    if collection.is_locked().map_err(text)? {
        collection.unlock().map_err(text)?;
    }
    if let Some(item) = collection.search_items(attributes()).map_err(text)?.first() {
        let secret = item.get_secret().map_err(text)?;
        return Secret::try_from(secret.as_slice()).map(Some).map_err(|_| "the key in the keyring isn't valid".to_string());
    }
    if !create {
        return Ok(None);
    }
    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    collection.create_item("Phi2ray store key", attributes(), &key, false, "application/octet-stream").map_err(text)?;
    Ok(Some(key))
}

/// The keyring can hang when its daemon is stuck, and this runs while the app starts.
fn keyring(create: bool) -> Result<Option<Secret>, String> {
    let (answer, wait) = mpsc::channel();
    thread::spawn(move || {
        let _ = answer.send(keyring_query(create));
    });
    wait.recv_timeout(KEYRING_TIMEOUT).map_err(|_| "the keyring didn't answer".to_string())?
}

fn file_key(create: bool) -> Result<Option<Secret>, String> {
    let path = key_file()?;
    match fs::read(&path) {
        Ok(bytes) => Secret::try_from(bytes.as_slice()).map(Some).map_err(|_| "the key file isn't valid".to_string()),
        Err(_) if !create => Ok(None),
        Err(_) => {
            crate::platform::check_write_target(&path)?;
            let mut key = [0u8; KEY_LEN];
            rand::thread_rng().fill_bytes(&mut key);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
            file.write_all(&key).map_err(|e| e.to_string())?;
            Ok(Some(key))
        }
    }
}

/// The key for writing: the one already in use, else the keyring, else a key file.
fn current_key() -> Result<(Kind, Secret), String> {
    for kind in [Kind::Keyring, Kind::File] {
        if let Some(key) = cached(kind) {
            return Ok((kind, key));
        }
    }
    // A key file means this system has no keyring; keep using it.
    if let Ok(Some(key)) = file_key(false) {
        return Ok((Kind::File, remember(Kind::File, key)));
    }
    match keyring(true) {
        Ok(Some(key)) => Ok((Kind::Keyring, remember(Kind::Keyring, key))),
        _ => {
            let key = file_key(true)?.ok_or("no key")?;
            Ok((Kind::File, remember(Kind::File, key)))
        }
    }
}

fn key_for(kind: Kind) -> Result<Secret, String> {
    if let Some(key) = cached(kind) {
        return Ok(key);
    }
    let found = match kind {
        Kind::Keyring => keyring(false).map_err(|_| KEY_UNAVAILABLE.to_string())?,
        Kind::File => file_key(false)?,
    };
    found.map(|key| remember(kind, key)).ok_or_else(|| KEY_UNAVAILABLE.to_string())
}

fn aad(kind: Kind) -> [u8; 5] {
    let [a, b, c, d] = *MAGIC;
    [a, b, c, d, kind as u8]
}

pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
    let (kind, key) = current_key()?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let header = aad(kind);
    let sealed = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: data, aad: &header })
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = Vec::with_capacity(header.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    let damaged = || "the store is damaged".to_string();
    if data.len() < 5 + NONCE_LEN || &data[..4] != MAGIC {
        return Err(damaged());
    }
    let kind = match data[4] {
        1 => Kind::Keyring,
        2 => Kind::File,
        _ => return Err(damaged()),
    };
    let key = key_for(kind)?;
    let (nonce, sealed) = data[5..].split_at(NONCE_LEN);
    let header = aad(kind);
    XChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(XNonce::from_slice(nonce), Payload { msg: sealed, aad: &header })
        .map_err(|_| damaged())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_file_key() {
        let folder = std::env::temp_dir().join(format!("phi2ray-vault-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        set_folder(folder);
        let mut keys = KEYS.lock().unwrap();
        if keys.is_empty() {
            keys.push((Kind::File as u8, [7; KEY_LEN]));
        }
    }

    #[test]
    fn what_is_sealed_opens_again_and_only_unchanged() {
        with_file_key();
        let sealed = protect(b"secret").unwrap();
        assert_eq!(unprotect(&sealed).unwrap(), b"secret");
        assert!(!sealed.windows(6).any(|w| w == b"secret"));

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(unprotect(&tampered).is_err());
        assert!(unprotect(b"plain text that was never sealed by anyone").is_err());
    }
}
