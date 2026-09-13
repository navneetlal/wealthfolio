use std::{
    collections::HashMap,
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use wealthfolio_core::{
    errors::Error,
    secrets::{format_service_id, SecretStore},
    Result,
};

#[cfg(windows)]
mod windows;

const CURRENT_VERSION: u32 = 1;

/// One server process owns a vault. The mutex serializes operations through this instance;
/// independent instances/processes must not share the same file.
pub struct FileSecretStore {
    path: PathBuf,
    encryption_key: [u8; 32],
    lock: Mutex<()>,
}

impl fmt::Debug for FileSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSecretStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlainSecrets {
    version: u32,
    secrets: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedSecrets {
    version: u32,
    nonce: String,
    ciphertext: String,
}

fn invalid_store() -> Error {
    Error::Secret(
        "Invalid or unsupported secrets file; preserve the file and restore a valid backup".into(),
    )
}

fn read_vault(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn decode_plain(raw: &[u8]) -> Result<HashMap<String, String>> {
    let plain: PlainSecrets = serde_json::from_slice(raw).map_err(|_| invalid_store())?;
    if plain.version != CURRENT_VERSION {
        return Err(invalid_store());
    }
    Ok(plain.secrets)
}

fn decrypt_store(raw: &[u8], key: &[u8; 32]) -> Result<HashMap<String, String>> {
    let enc: EncryptedSecrets = serde_json::from_slice(raw).map_err(|_| invalid_store())?;
    if enc.version != CURRENT_VERSION {
        return Err(invalid_store());
    }
    let nonce: [u8; 12] = BASE64
        .decode(enc.nonce)
        .map_err(|_| invalid_store())?
        .try_into()
        .map_err(|_| invalid_store())?;
    let ciphertext = BASE64.decode(enc.ciphertext).map_err(|_| invalid_store())?;
    let plaintext = ChaCha20Poly1305::new(key.into())
        .decrypt(&Nonce::from(nonce), ciphertext.as_ref())
        .map_err(|_| {
            Error::Secret(
                "Cannot decrypt secrets file; verify WF_SECRET_KEY or restore a matching backup"
                    .into(),
            )
        })?;
    decode_plain(&plaintext)
}

impl FileSecretStore {
    pub fn new_from_bytes(path: PathBuf, encryption_key: [u8; 32]) -> Self {
        Self {
            path,
            encryption_key,
            lock: Mutex::new(()),
        }
    }

    fn persist_migrated(&self, secrets: &HashMap<String, String>) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::Secret("Secret store lock poisoned".into()))?;
        self.persist_store_locked(secrets)
    }

    fn with_store<F>(&self, mut op: F) -> Result<()>
    where
        F: FnMut(&mut HashMap<String, String>) -> Result<()>,
    {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::Secret("Secret store lock poisoned".into()))?;
        let mut store = self.load_store_locked()?;
        op(&mut store)?;
        self.persist_store_locked(&store)
    }

    fn read_store(&self) -> Result<HashMap<String, String>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::Secret("Secret store lock poisoned".into()))?;
        self.load_store_locked()
    }

    fn load_store_locked(&self) -> Result<HashMap<String, String>> {
        match read_vault(&self.path)? {
            Some(raw) => decrypt_store(&raw, &self.encryption_key),
            None => Ok(HashMap::new()),
        }
    }

    fn persist_store_locked(&self, store: &HashMap<String, String>) -> Result<()> {
        let plain = PlainSecrets {
            version: CURRENT_VERSION,
            secrets: store.clone(),
        };
        let serialized = serde_json::to_vec(&plain)?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = ChaCha20Poly1305::new((&self.encryption_key).into())
            .encrypt(&Nonce::from(nonce), serialized.as_ref())
            .map_err(|_| Error::Secret("Failed to encrypt secrets".into()))?;
        let enc = EncryptedSecrets {
            version: CURRENT_VERSION,
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };
        atomic_write(&self.path, &serde_json::to_vec_pretty(&enc)?)
    }
}

fn restrict_file(file: &fs::File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    windows::restrict_file(file)?;
    Ok(())
}

/// The tempfile lives beside the vault so replacement stays on the same filesystem.
/// Before replacement an error leaves the old file untouched. A directory-sync error
/// after replacement means the new file is installed but its durability is uncertain.
fn atomic_write(path: &Path, ciphertext: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    // tempfile creates Unix files with mode 0600; existing directories are untouched.
    let mut temp_builder = tempfile::Builder::new();
    temp_builder.prefix(".wealthfolio-secrets-");
    #[cfg(not(windows))]
    let mut temp = temp_builder.tempfile_in(parent)?;
    #[cfg(windows)]
    let mut temp = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::WRITE_DAC,
        };
        // Request ACL rights on the original handle, before any ciphertext is written.
        temp_builder.make_in(parent, |path| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC)
                .create_new(true)
                .open(path)
        })?
    };
    restrict_file(temp.as_file())?;
    temp.write_all(ciphertext)?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| Error::from(error.error))?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all().map_err(|_| {
        Error::Secret(
            "Secrets file replaced, but directory sync failed; durability is uncertain".into(),
        )
    })?;
    Ok(())
}

impl SecretStore for FileSecretStore {
    fn set_secret(&self, service: &str, secret: &str) -> Result<()> {
        let key = format_service_id(service);
        self.with_store(|store| {
            store.insert(key.clone(), secret.to_string());
            Ok(())
        })
    }

    fn get_secret(&self, service: &str) -> Result<Option<String>> {
        let key = format_service_id(service);
        let store = self.read_store()?;
        Ok(store.get(&key).cloned())
    }

    fn delete_secret(&self, service: &str) -> Result<()> {
        let key = format_service_id(service);
        self.with_store(|store| {
            store.remove(&key);
            Ok(())
        })
    }
}

/// Validate at startup and migrate supported legacy formats using the atomic writer.
/// Plaintext v1 is accepted only here for compatibility with early custom builds.
pub fn build_secret_store(
    path: PathBuf,
    derived_key: [u8; 32],
    raw_key_for_migration: Option<&[u8]>,
) -> Result<FileSecretStore> {
    let store = FileSecretStore::new_from_bytes(path, derived_key);
    let Some(raw) = read_vault(&store.path)? else {
        return Ok(store);
    };
    match decrypt_store(&raw, &derived_key) {
        Ok(_) => {
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                use windows_sys::Win32::{
                    Foundation::GENERIC_READ, Storage::FileSystem::WRITE_DAC,
                };
                options.access_mode(GENERIC_READ | WRITE_DAC);
            }
            restrict_file(&options.open(&store.path)?)?;
            Ok(store)
        }
        Err(original_error) => {
            let legacy = raw_key_for_migration
                .and_then(|key| <&[u8; 32]>::try_from(key).ok())
                .and_then(|key| decrypt_store(&raw, key).ok())
                .or_else(|| decode_plain(&raw).ok());
            let Some(secrets) = legacy else {
                return Err(original_error);
            };
            store.persist_migrated(&secrets)?;
            tracing::info!("Migrated legacy secrets file to derived-key encryption");
            Ok(store)
        }
    }
}

#[cfg(test)]
mod tests;
