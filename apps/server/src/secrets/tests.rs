use super::*;
use tempfile::tempdir;

const KEY: [u8; 32] = [7; 32];

// Construct legacy-format input independently of the production serializer/writer.
fn encrypted_fixture(key: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let ciphertext = ChaCha20Poly1305::new(key.into())
        .encrypt(&Nonce::from([3; 12]), payload)
        .unwrap();
    serde_json::to_vec(&serde_json::json!({
        "version": 1, "nonce": BASE64.encode([3; 12]), "ciphertext": BASE64.encode(ciphertext)
    }))
    .unwrap()
}

fn legacy_payload() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1, "secrets": { format_service_id("fixture"): "fixture-token" }
    }))
    .unwrap()
}

#[test]
fn encrypted_crud_survives_reopen_and_uses_fresh_nonces() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("secrets.json");
    let store = build_secret_store(path.clone(), KEY, None).unwrap();
    assert!(!path.exists());
    assert_eq!(store.get_secret("absent").unwrap(), None);
    store.set_secret("alpha", "秘密 🔑").unwrap();
    let first: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    store.set_secret("alpha", "秘密 🔑").unwrap();
    let second: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_ne!(first["nonce"], second["nonce"]);
    assert!(!fs::read_to_string(&path).unwrap().contains("秘密"));
    drop(store);
    let store = build_secret_store(path, KEY, None).unwrap();
    assert_eq!(
        store.get_secret("alpha").unwrap().as_deref(),
        Some("秘密 🔑")
    );
    store.set_secret("other", "preserved").unwrap();
    store.set_secret("alpha", "updated").unwrap();
    assert_eq!(
        store.get_secret("alpha").unwrap().as_deref(),
        Some("updated")
    );
    store.delete_secret("alpha").unwrap();
    store.delete_secret("alpha").unwrap();
    assert_eq!(store.get_secret("alpha").unwrap(), None);
    assert_eq!(
        store.get_secret("other").unwrap().as_deref(),
        Some("preserved")
    );
}

#[test]
fn current_encrypted_v1_loads_without_rewriting() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("secrets.json");
    let fixture = encrypted_fixture(&KEY, &legacy_payload());
    fs::write(&path, &fixture).unwrap();
    let store = build_secret_store(path.clone(), KEY, Some(&[8; 32])).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        store.get_secret("fixture").unwrap().as_deref(),
        Some("fixture-token")
    );
    assert_eq!(fs::read(path).unwrap(), fixture);
}

#[test]
fn legacy_raw_key_and_plaintext_migrate_once_without_losing_entries() {
    for raw in [
        encrypted_fixture(&[8; 32], &legacy_payload()),
        legacy_payload(),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        fs::write(&path, raw).unwrap();
        let store = build_secret_store(path.clone(), KEY, Some(&[8; 32])).unwrap();
        assert_eq!(
            store.get_secret("fixture").unwrap().as_deref(),
            Some("fixture-token")
        );
        let migrated = fs::read(&path).unwrap();
        assert!(decrypt_store(&migrated, &KEY).is_ok());
        assert!(decrypt_store(&migrated, &[8; 32]).is_err());
        drop(store);
        let store = build_secret_store(path.clone(), KEY, None).unwrap();
        assert_eq!(fs::read(&path).unwrap(), migrated);
        store.set_secret("new", "value").unwrap();
        store.delete_secret("new").unwrap();
        assert_eq!(
            store.get_secret("fixture").unwrap().as_deref(),
            Some("fixture-token")
        );
    }
}

#[test]
fn malformed_or_wrong_key_files_fail_without_panics_or_replacement() {
    let valid = encrypted_fixture(&KEY, &legacy_payload());
    let mut cases = vec![
        vec![],
        b"{".to_vec(),
        b"null".to_vec(),
        b"{}".to_vec(),
        encrypted_fixture(&[99; 32], &legacy_payload()),
        br#"{"version":2,"secrets":{}}"#.to_vec(),
        encrypted_fixture(&KEY, br#"{"version":2,"secrets":{}}"#),
        encrypted_fixture(&KEY, b"not json"),
    ];
    for size in [0, 1, 11, 13, 32] {
        let mut value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        value["nonce"] = BASE64.encode(vec![0; size]).into();
        cases.push(serde_json::to_vec(&value).unwrap());
    }
    for (field, value) in [
        ("nonce", serde_json::json!("!invalid!")),
        ("ciphertext", serde_json::json!("!invalid!")),
        ("ciphertext", serde_json::json!("")),
        ("version", serde_json::json!(2)),
    ] {
        let mut envelope: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        envelope[field] = value;
        cases.push(serde_json::to_vec(&envelope).unwrap());
    }
    // A malformed envelope cannot downgrade to the plaintext migration path.
    cases.push(br#"{"version":1,"secrets":{},"ciphertext":"invalid"}"#.to_vec());
    for raw in cases {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        fs::write(&path, &raw).unwrap();
        assert!(build_secret_store(path.clone(), KEY, Some(&[8; 32])).is_err());
        let store = FileSecretStore::new_from_bytes(path.clone(), KEY);
        assert!(store.get_secret("fixture").is_err());
        assert!(store.set_secret("new", "value").is_err());
        assert!(store.delete_secret("fixture").is_err());
        assert_eq!(fs::read(path).unwrap(), raw);
    }
}

#[test]
fn unreadable_path_is_not_a_new_vault() {
    let dir = tempdir().unwrap();
    assert!(build_secret_store(dir.path().to_path_buf(), KEY, None).is_err());
}

#[test]
fn replacement_failure_cleans_temporary_ciphertext() {
    let dir = tempdir().unwrap();
    let destination = dir.path().join("existing-directory");
    fs::create_dir(&destination).unwrap();
    let marker = destination.join("keep");
    fs::write(&marker, "unchanged").unwrap();
    assert!(atomic_write(&destination, b"ciphertext fixture").is_err());
    assert_eq!(fs::read_to_string(marker).unwrap(), "unchanged");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn concurrent_calls_on_one_store_do_not_lose_updates() {
    let dir = tempdir().unwrap();
    let store = std::sync::Arc::new(FileSecretStore::new_from_bytes(
        dir.path().join("vault"),
        KEY,
    ));
    let threads: Vec<_> = (0..12)
        .map(|i| {
            let store = store.clone();
            std::thread::spawn(move || store.set_secret(&format!("entry-{i}"), "fixture").unwrap())
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    for i in 0..12 {
        assert_eq!(
            store.get_secret(&format!("entry-{i}")).unwrap().as_deref(),
            Some("fixture")
        );
    }
}

#[test]
fn debug_does_not_include_key() {
    let store = FileSecretStore::new_from_bytes(PathBuf::from("vault"), KEY);
    let output = format!("{store:?}");
    assert!(!output.contains("encryption_key"));
    assert!(!output.contains(&format!("{KEY:?}")));
}

#[cfg(unix)]
#[test]
fn owner_only_files_and_new_directories_preserve_existing_directory_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("private/vault");
    let store = FileSecretStore::new_from_bytes(path.clone(), KEY);
    store.set_secret("a", "fixture").unwrap();
    assert_eq!(
        fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    store.set_secret("b", "fixture").unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn failed_write_preserves_existing_vault() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault");
    let store = FileSecretStore::new_from_bytes(path.clone(), KEY);
    store.set_secret("original", "fixture").unwrap();
    let original = fs::read(&path).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let result = store.set_secret("new", "fixture");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        result.is_err(),
        "Run permission tests as an unprivileged user"
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    assert_eq!(
        store.get_secret("original").unwrap().as_deref(),
        Some("fixture")
    );
}

#[test]
fn subprocess_fixture_worker() {
    let Ok(path) = std::env::var("WF_VAULT_TEST_CHILD_PATH") else {
        return;
    };
    let store = build_secret_store(PathBuf::from(path), KEY, None).unwrap();
    match std::env::var("WF_VAULT_TEST_CHILD_ACTION")
        .unwrap()
        .as_str()
    {
        "write" => store.set_secret("restart", "fixture-token").unwrap(),
        "read" => assert_eq!(
            store.get_secret("restart").unwrap().as_deref(),
            Some("fixture-token")
        ),
        _ => panic!("Invalid fixture action"),
    }
}

#[test]
fn encrypted_credentials_survive_process_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault");
    for action in ["write", "read"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "secrets::tests::subprocess_fixture_worker"])
            .env("WF_VAULT_TEST_CHILD_PATH", &path)
            .env("WF_VAULT_TEST_CHILD_ACTION", action)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Fixture process failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
