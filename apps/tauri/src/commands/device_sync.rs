//! Commands for device sync and E2EE pairing.
//!
//! This module provides Tauri commands that wrap the shared device sync client,
//! handling token/device ID storage via the keyring.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use chrono::Utc;
use log::{debug, info};
use sha2::{Digest, Sha256};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use crate::context::ServiceContext;
use crate::events::{emit_portfolio_trigger_recalculate, PortfolioRequestPayload};
use crate::secret_store::KeyringSecretStore;
use wealthfolio_connect::DEFAULT_CLOUD_API_URL;
use wealthfolio_core::quotes::MarketSyncMode;
use wealthfolio_core::secrets::SecretStore;
use wealthfolio_core::sync::{
    backoff_seconds as core_sync_backoff_seconds,
    SyncEntity as LocalSyncEntity, SyncOperation as LocalSyncOperation,
    DEVICE_SYNC_FOREGROUND_INTERVAL_SECS, DEVICE_SYNC_INTERVAL_JITTER_SECS,
    DEVICE_SYNC_SNAPSHOT_EVENT_THRESHOLD, DEVICE_SYNC_SNAPSHOT_INTERVAL_SECS, APP_SYNC_TABLES,
};
use wealthfolio_device_sync::{
    ApiRetryClass, ClaimPairingRequest, ClaimPairingResponse, CommitInitializeKeysRequest,
    CommitInitializeKeysResponse, CommitRotateKeysRequest, CommitRotateKeysResponse,
    CompletePairingRequest, ConfirmPairingRequest, ConfirmPairingResponse, CreatePairingRequest,
    CreatePairingResponse, Device, DevicePlatform, DeviceSyncClient, EnrollDeviceResponse,
    GetPairingResponse, InitializeKeysResult, PairingMessagesResponse, RegisterDeviceRequest,
    ResetTeamSyncResponse, RotateKeysResponse, SnapshotRequestPayload, SuccessResponse, SyncEntity,
    SyncPushEventRequest, SyncPushRequest, SyncState, UpdateDeviceRequest,
};

// Storage keys (without prefix - the SecretStore adds "wealthfolio_" prefix)
const CLOUD_ACCESS_TOKEN_KEY: &str = "sync_access_token";

fn cloud_api_base_url() -> String {
    std::env::var("CONNECT_API_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CLOUD_API_URL.to_string())
}

/// Get the access token from keyring.
fn get_access_token() -> Result<String, String> {
    KeyringSecretStore
        .get_secret(CLOUD_ACCESS_TOKEN_KEY)
        .map_err(|e| format!("Failed to get access token: {}", e))?
        .ok_or_else(|| "No access token configured. Please sign in first.".to_string())
}

/// Sync identity stored in keychain as JSON (only device_id is needed here)
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncIdentity {
    device_id: Option<String>,
    root_key: Option<String>,
    key_version: Option<i32>,
}

fn get_sync_identity_from_store() -> Option<SyncIdentity> {
    const SYNC_IDENTITY_KEY: &str = "sync_identity";

    match KeyringSecretStore.get_secret(SYNC_IDENTITY_KEY) {
        Ok(Some(json)) => {
            match serde_json::from_str::<SyncIdentity>(&json) {
                Ok(identity) => {
                    if let Some(ref device_id) = identity.device_id {
                        debug!(
                            "[DeviceSync] Loaded sync_identity (device_id={}, has_root_key={}, key_version={})",
                            device_id,
                            identity.root_key.is_some(),
                            identity.key_version.unwrap_or_default()
                        );
                    } else {
                        debug!(
                            "[DeviceSync] sync_identity exists but deviceId is not set (has_root_key={}, key_version={})",
                            identity.root_key.is_some(),
                            identity.key_version.unwrap_or_default()
                        );
                    }
                    Some(identity)
                }
                Err(e) => {
                    log::warn!("[DeviceSync] Failed to parse sync_identity: {}", e);
                    None
                }
            }
        }
        Ok(None) => {
            debug!("[DeviceSync] No sync_identity in keyring");
            None
        }
        Err(e) => {
            log::warn!(
                "[DeviceSync] Failed to read sync_identity from keyring: {}",
                e
            );
            None
        }
    }
}

/// Get the device ID from sync_identity in keyring.
fn get_device_id_from_store() -> Option<String> {
    get_sync_identity_from_store().and_then(|identity| identity.device_id)
}

async fn persist_device_config_from_identity(
    context: &ServiceContext,
    identity: &SyncIdentity,
    trust_state: &str,
) {
    let Some(device_id) = identity.device_id.clone() else {
        return;
    };
    if let Err(err) = context
        .app_sync_repository()
        .upsert_device_config(device_id, identity.key_version, trust_state.to_string())
        .await
    {
        log::warn!("[DeviceSync] Failed to persist sync device config: {}", err);
    }
}

/// Create a device sync client with the stored credentials.
fn create_client() -> DeviceSyncClient {
    DeviceSyncClient::new(&cloud_api_base_url())
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncBootstrapResult {
    pub status: String,
    pub message: String,
    pub snapshot_id: Option<String>,
    pub cursor: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncEngineStatusResult {
    pub cursor: i64,
    pub last_push_at: Option<String>,
    pub last_pull_at: Option<String>,
    pub last_error: Option<String>,
    pub consecutive_failures: i32,
    pub next_retry_at: Option<String>,
    pub last_cycle_status: Option<String>,
    pub last_cycle_duration_ms: Option<i64>,
    pub background_running: bool,
    pub bootstrap_required: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncCycleResult {
    pub status: String,
    pub lock_version: i64,
    pub pushed_count: usize,
    pub pulled_count: usize,
    pub cursor: i64,
    pub needs_bootstrap: bool,
}

async fn request_snapshot_generation(
    client: &DeviceSyncClient,
    token: &str,
    device_id: &str,
    identity: &SyncIdentity,
    message: &str,
) -> Result<SyncBootstrapResult, String> {
    let payload_key_version = identity.key_version.unwrap_or(1).max(1);
    let request_response = client
        .request_snapshot(
            token,
            device_id,
            SnapshotRequestPayload {
                min_schema_version: Some(1),
                covers_tables: Some(APP_SYNC_TABLES.iter().map(|v| v.to_string()).collect()),
                payload: BASE64_STANDARD.encode("{}"),
                payload_key_version,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    debug!(
        "[DeviceSync] Snapshot request accepted: request_id={} status={} message={}",
        request_response.request_id, request_response.status, request_response.message
    );
    debug!(
        "[DeviceSync] Requested snapshot generation; no local upload performed in this path (device_id={} request_id={})",
        device_id, request_response.request_id
    );

    Ok(SyncBootstrapResult {
        status: "requested".to_string(),
        message: message.to_string(),
        snapshot_id: None,
        cursor: None,
    })
}

fn is_sqlite_image(bytes: &[u8]) -> bool {
    bytes.starts_with(b"SQLite format 3\0")
}

fn sha256_checksum(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{:x}", digest)
}

fn classify_snapshot_upload_error(err: &str) -> &'static str {
    let lower = err.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("tempor") {
        return "transient";
    }
    if lower.contains("401")
        || lower.contains("403")
        || lower.contains("unauthor")
        || lower.contains("forbidden")
    {
        return "auth";
    }
    if lower.contains("400")
        || lower.contains("404")
        || lower.contains("422")
        || lower.contains("zod")
        || lower.contains("invalid")
    {
        return "validation";
    }
    if lower.contains("500") || lower.contains("502") || lower.contains("503") {
        return "server";
    }
    "unknown"
}

fn decode_snapshot_sqlite_payload(
    blob: Vec<u8>,
    identity: &SyncIdentity,
) -> Result<Vec<u8>, String> {
    if is_sqlite_image(&blob) {
        return Ok(blob);
    }

    let blob_text = String::from_utf8(blob).map_err(|_| "Snapshot payload is not valid UTF-8")?;
    if let Ok(decoded) = BASE64_STANDARD.decode(blob_text.trim()) {
        if is_sqlite_image(&decoded) {
            return Ok(decoded);
        }
    }

    if let (Some(root_key), Some(key_version)) = (&identity.root_key, identity.key_version) {
        if key_version <= 0 {
            return Err("Invalid key version in sync identity".to_string());
        }

        let dek = wealthfolio_device_sync::crypto::derive_dek(root_key, key_version as u32)
            .map_err(|e| format!("Failed to derive snapshot DEK: {}", e))?;
        let decrypted = wealthfolio_device_sync::crypto::decrypt(&dek, blob_text.trim())
            .map_err(|e| format!("Failed to decrypt snapshot payload: {}", e))?;

        if let Ok(decoded) = BASE64_STANDARD.decode(decrypted.trim()) {
            if is_sqlite_image(&decoded) {
                return Ok(decoded);
            }
        }

        if is_sqlite_image(decrypted.as_bytes()) {
            return Ok(decrypted.into_bytes());
        }
    }

    Err("Snapshot payload is not a SQLite image after decode/decrypt".to_string())
}

fn remote_supports_entity(entity: &LocalSyncEntity) -> bool {
    matches!(
        entity,
        LocalSyncEntity::Account
            | LocalSyncEntity::Asset
            | LocalSyncEntity::Activity
            | LocalSyncEntity::ActivityImportProfile
            | LocalSyncEntity::Goal
            | LocalSyncEntity::ContributionLimit
    )
}

fn allow_unsupported_entity_sync() -> bool {
    let parse_flag = |value: String| value.eq_ignore_ascii_case("true") || value == "1";
    std::env::var("WF_DEVICE_SYNC_ENABLE_UNSUPPORTED_ENTITIES")
        .map(parse_flag)
        .or_else(|_| std::env::var("WF_SYNC_ENABLE_UNSUPPORTED_ENTITIES").map(parse_flag))
        .unwrap_or(false)
}

fn to_remote_entity(entity: &LocalSyncEntity) -> SyncEntity {
    match entity {
        LocalSyncEntity::Account => SyncEntity::Account,
        LocalSyncEntity::Asset => SyncEntity::Asset,
        LocalSyncEntity::AssetTaxonomyAssignment => SyncEntity::AssetTaxonomyAssignment,
        LocalSyncEntity::Activity => SyncEntity::Activity,
        LocalSyncEntity::ActivityImportProfile => SyncEntity::ActivityImportProfile,
        LocalSyncEntity::Goal => SyncEntity::Goal,
        LocalSyncEntity::GoalsAllocation => SyncEntity::GoalsAllocation,
        LocalSyncEntity::AiThread => SyncEntity::AiThread,
        LocalSyncEntity::AiMessage => SyncEntity::AiMessage,
        LocalSyncEntity::AiThreadTag => SyncEntity::AiThreadTag,
        LocalSyncEntity::ContributionLimit => SyncEntity::ContributionLimit,
        LocalSyncEntity::Platform => SyncEntity::Platform,
        LocalSyncEntity::Settings => SyncEntity::Settings,
        LocalSyncEntity::Snapshot => SyncEntity::Snapshot,
    }
}

fn from_remote_entity(entity: &SyncEntity) -> LocalSyncEntity {
    match entity {
        SyncEntity::Account => LocalSyncEntity::Account,
        SyncEntity::Asset => LocalSyncEntity::Asset,
        SyncEntity::AssetTaxonomyAssignment => LocalSyncEntity::AssetTaxonomyAssignment,
        SyncEntity::Activity => LocalSyncEntity::Activity,
        SyncEntity::ActivityImportProfile => LocalSyncEntity::ActivityImportProfile,
        SyncEntity::Goal => LocalSyncEntity::Goal,
        SyncEntity::GoalsAllocation => LocalSyncEntity::GoalsAllocation,
        SyncEntity::AiThread => LocalSyncEntity::AiThread,
        SyncEntity::AiMessage => LocalSyncEntity::AiMessage,
        SyncEntity::AiThreadTag => LocalSyncEntity::AiThreadTag,
        SyncEntity::ContributionLimit => LocalSyncEntity::ContributionLimit,
        SyncEntity::Platform => LocalSyncEntity::Platform,
        SyncEntity::Settings => LocalSyncEntity::Settings,
        SyncEntity::Snapshot => LocalSyncEntity::Snapshot,
    }
}

fn sync_entity_name(entity: &LocalSyncEntity) -> &'static str {
    match entity {
        LocalSyncEntity::Account => "account",
        LocalSyncEntity::Asset => "asset",
        LocalSyncEntity::AssetTaxonomyAssignment => "asset_taxonomy_assignment",
        LocalSyncEntity::Activity => "activity",
        LocalSyncEntity::ActivityImportProfile => "activity_import_profile",
        LocalSyncEntity::Goal => "goal",
        LocalSyncEntity::GoalsAllocation => "goals_allocation",
        LocalSyncEntity::AiThread => "ai_thread",
        LocalSyncEntity::AiMessage => "ai_message",
        LocalSyncEntity::AiThreadTag => "ai_thread_tag",
        LocalSyncEntity::ContributionLimit => "contribution_limit",
        LocalSyncEntity::Platform => "platform",
        LocalSyncEntity::Settings => "settings",
        LocalSyncEntity::Snapshot => "snapshot",
    }
}

fn sync_operation_name(op: &LocalSyncOperation) -> &'static str {
    match op {
        LocalSyncOperation::Create => "create",
        LocalSyncOperation::Update => "update",
        LocalSyncOperation::Delete => "delete",
        LocalSyncOperation::Request => "request",
    }
}

fn retry_class_code(class: ApiRetryClass) -> &'static str {
    match class {
        ApiRetryClass::Retryable => "retryable",
        ApiRetryClass::Permanent => "permanent",
        ApiRetryClass::ReauthRequired => "reauth_required",
    }
}

fn parse_event_operation(event_type: &str) -> Option<LocalSyncOperation> {
    let mut parts = event_type.split('.');
    let _entity = parts.next()?;
    match parts.next()? {
        "create" => Some(LocalSyncOperation::Create),
        "update" => Some(LocalSyncOperation::Update),
        "delete" => Some(LocalSyncOperation::Delete),
        "request" => Some(LocalSyncOperation::Request),
        _ => None,
    }
}

fn millis_until_rfc3339(target: &str) -> Option<u64> {
    let target = chrono::DateTime::parse_from_rfc3339(target).ok()?;
    let now = chrono::Utc::now();
    let diff = target.with_timezone(&chrono::Utc) - now;
    if diff <= chrono::Duration::zero() {
        return Some(0);
    }
    Some(diff.num_milliseconds() as u64)
}

fn encrypt_sync_payload(
    plaintext_payload: &str,
    identity: &SyncIdentity,
    payload_key_version: i32,
) -> Result<String, String> {
    let root_key = identity
        .root_key
        .as_ref()
        .ok_or_else(|| "Sync root key is not configured".to_string())?;
    let key_version = payload_key_version.max(1) as u32;
    let dek = wealthfolio_device_sync::crypto::derive_dek(root_key, key_version)
        .map_err(|e| format!("Failed to derive event DEK: {}", e))?;
    wealthfolio_device_sync::crypto::encrypt(&dek, plaintext_payload)
        .map_err(|e| format!("Failed to encrypt sync payload: {}", e))
}

fn decrypt_sync_payload(
    encrypted_payload: &str,
    identity: &SyncIdentity,
    payload_key_version: i32,
) -> Result<String, String> {
    let root_key = identity
        .root_key
        .as_ref()
        .ok_or_else(|| "Sync root key is not configured".to_string())?;
    let key_version = payload_key_version.max(1) as u32;
    let dek = wealthfolio_device_sync::crypto::derive_dek(root_key, key_version)
        .map_err(|e| format!("Failed to derive event DEK: {}", e))?;
    wealthfolio_device_sync::crypto::decrypt(&dek, encrypted_payload)
        .map_err(|e| format!("Failed to decrypt sync payload: {}", e))
}

/// Get the OS version string.
fn get_os_version() -> Option<String> {
    let version = get_os_version_impl();
    if version.is_none() {
        debug!("[DeviceSync] Could not detect OS version");
    }
    version
}

#[cfg(target_os = "macos")]
fn get_os_version_impl() -> Option<String> {
    // sw_vers -productVersion returns e.g., "15.2"
    Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "windows")]
fn get_os_version_impl() -> Option<String> {
    // Use PowerShell to get OS version reliably (works across locales)
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[System.Environment]::OSVersion.Version.ToString()",
        ])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn get_os_version_impl() -> Option<String> {
    // Try /etc/os-release first (standard on modern distros)
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            // Try VERSION_ID first (e.g., "22.04"), then VERSION (e.g., "22.04 LTS")
            content
                .lines()
                .find(|l| l.starts_with("VERSION_ID="))
                .map(|l| {
                    l.trim_start_matches("VERSION_ID=")
                        .trim_matches('"')
                        .to_string()
                })
        })
        .or_else(|| {
            // Fallback: try /etc/lsb-release
            std::fs::read_to_string("/etc/lsb-release")
                .ok()
                .and_then(|content| {
                    content
                        .lines()
                        .find(|l| l.starts_with("DISTRIB_RELEASE="))
                        .map(|l| {
                            l.trim_start_matches("DISTRIB_RELEASE=")
                                .trim_matches('"')
                                .to_string()
                        })
                })
        })
        .or_else(|| {
            // Last resort: kernel version via uname
            Command::new("uname")
                .arg("-r")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "ios")]
fn get_os_version_impl() -> Option<String> {
    // For iOS, we rely on Tauri's device info plugin or Swift interop
    // This is a placeholder - actual implementation would use UIDevice.current.systemVersion
    None
}

#[cfg(target_os = "android")]
fn get_os_version_impl() -> Option<String> {
    // For Android, we rely on Tauri's device info plugin or JNI
    // This is a placeholder - actual implementation would use Build.VERSION.RELEASE
    None
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "windows",
    target_os = "linux",
    target_os = "ios",
    target_os = "android"
)))]
fn get_os_version_impl() -> Option<String> {
    None
}

/// Get the app version from Cargo.toml
fn get_app_version() -> Option<String> {
    Some(env!("CARGO_PKG_VERSION").to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Device Management
// ─────────────────────────────────────────────────────────────────────────────

/// Enroll a device with the cloud API.
///
/// Returns the next step for the device:
/// - BOOTSTRAP: First device for this team - generate RK locally
/// - PAIR: E2EE already enabled - device must pair with existing trusted device
/// - READY: Device is already trusted and ready to sync
#[tauri::command(rename_all = "camelCase")]
pub async fn enroll_device(
    device_nonce: String,
    display_name: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<EnrollDeviceResponse, String> {
    info!("[DeviceSync] Enrolling device: {}", display_name);

    let token = get_access_token()?;
    let client = create_client();

    // Auto-detect platform, OS version, and app version
    let platform = DevicePlatform::detect().to_string();
    let os_version = get_os_version();
    let app_version = get_app_version();

    info!(
        "[DeviceSync] Platform: {}, OS version: {:?}, App version: {:?}",
        platform, os_version, app_version
    );

    let request = RegisterDeviceRequest {
        device_nonce,
        display_name,
        platform,
        os_version,
        app_version,
    };

    let result = client
        .enroll_device(&token, request)
        .await
        .map_err(|e| e.to_string())?;

    // Log the result - device ID storage is handled by TypeScript via sync_identity
    let device_id = match &result {
        EnrollDeviceResponse::Bootstrap { device_id, .. } => device_id,
        EnrollDeviceResponse::Pair { device_id, .. } => device_id,
        EnrollDeviceResponse::Ready { device_id, .. } => device_id,
    };

    info!(
        "[DeviceSync] Device enrolled: {} (mode: {:?})",
        device_id,
        match &result {
            EnrollDeviceResponse::Bootstrap { .. } => "BOOTSTRAP",
            EnrollDeviceResponse::Pair { .. } => "PAIR",
            EnrollDeviceResponse::Ready { .. } => "READY",
        }
    );
    Ok(result)
}

/// Get device info by ID.
#[tauri::command(rename_all = "camelCase")]
pub async fn get_device(
    device_id: Option<String>,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<Device, String> {
    let token = get_access_token()?;
    let device_id = device_id
        .or_else(get_device_id_from_store)
        .ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .get_device(&token, &device_id)
        .await
        .map_err(|e| e.to_string())
}

/// List all devices.
#[tauri::command]
pub async fn list_devices(
    scope: Option<String>,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<Vec<Device>, String> {
    info!("[DeviceSync] Listing devices (scope: {:?})...", scope);

    let token = get_access_token()?;

    let devices = create_client()
        .list_devices(&token, scope.as_deref())
        .await
        .map_err(|e| e.to_string())?;

    info!("[DeviceSync] Found {} devices", devices.len());
    Ok(devices)
}

/// Update a device (e.g., rename).
#[tauri::command(rename_all = "camelCase")]
pub async fn update_device(
    device_id: String,
    display_name: Option<String>,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<SuccessResponse, String> {
    info!("Updating device {}: name={:?}", device_id, display_name);

    let token = get_access_token()?;

    create_client()
        .update_device(
            &token,
            &device_id,
            UpdateDeviceRequest {
                display_name,
                metadata: None,
            },
        )
        .await
        .map_err(|e| e.to_string())
}

/// Delete a device.
#[tauri::command(rename_all = "camelCase")]
pub async fn delete_device(
    device_id: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<SuccessResponse, String> {
    info!("Deleting device: {}", device_id);

    let token = get_access_token()?;

    create_client()
        .delete_device(&token, &device_id)
        .await
        .map_err(|e| e.to_string())
}

/// Revoke a device's trust.
#[tauri::command(rename_all = "camelCase")]
pub async fn revoke_device(
    device_id: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<SuccessResponse, String> {
    info!("Revoking device: {}", device_id);

    let token = get_access_token()?;

    create_client()
        .revoke_device(&token, &device_id)
        .await
        .map_err(|e| e.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Team Keys (E2EE)
// ─────────────────────────────────────────────────────────────────────────────

/// Initialize team keys (Phase 1).
///
/// Returns next step for key initialization:
/// - BOOTSTRAP: Ready to initialize - challenge/nonce returned for key generation
/// - PAIRING_REQUIRED: Already initialized - device must pair with trusted device
/// - READY: Device already trusted at current key version
#[tauri::command]
pub async fn initialize_team_keys(
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<InitializeKeysResult, String> {
    info!("[DeviceSync] Initializing team keys...");

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    let result = create_client()
        .initialize_team_keys(&token, &device_id)
        .await
        .map_err(|e| e.to_string())?;

    info!(
        "[DeviceSync] Initialize team keys result: {:?}",
        match &result {
            InitializeKeysResult::Bootstrap { .. } => "BOOTSTRAP",
            InitializeKeysResult::PairingRequired { .. } => "PAIRING_REQUIRED",
            InitializeKeysResult::Ready { .. } => "READY",
        }
    );

    Ok(result)
}

/// Commit team key initialization (Phase 2).
#[tauri::command(rename_all = "camelCase")]
pub async fn commit_initialize_team_keys(
    key_version: i32,
    device_key_envelope: String,
    signature: String,
    challenge_response: Option<String>,
    recovery_envelope: Option<String>,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<CommitInitializeKeysResponse, String> {
    info!("[DeviceSync] Committing team key initialization...");

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    let request = CommitInitializeKeysRequest {
        device_id: device_id.clone(),
        key_version,
        device_key_envelope,
        signature,
        challenge_response,
        recovery_envelope,
    };

    create_client()
        .commit_initialize_team_keys(&token, request)
        .await
        .map_err(|e| e.to_string())
}

/// Start key rotation (Phase 1).
#[tauri::command]
pub async fn rotate_team_keys(
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<RotateKeysResponse, String> {
    info!("[DeviceSync] Starting key rotation...");

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .rotate_team_keys(&token, &device_id)
        .await
        .map_err(|e| e.to_string())
}

/// Commit key rotation (Phase 2).
#[tauri::command]
pub async fn commit_rotate_team_keys(
    request: CommitRotateKeysRequest,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<CommitRotateKeysResponse, String> {
    info!("[DeviceSync] Committing key rotation...");

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .commit_rotate_team_keys(&token, &device_id, request)
        .await
        .map_err(|e| e.to_string())
}

/// Reset team sync (destructive, owner only).
/// Revokes all devices and increments key version.
#[tauri::command]
pub async fn reset_team_sync(
    reason: Option<String>,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<ResetTeamSyncResponse, String> {
    info!("[DeviceSync] Resetting team sync...");

    let token = get_access_token()?;

    create_client()
        .reset_team_sync(&token, reason.as_deref())
        .await
        .map_err(|e| e.to_string())
}

/// Returns current app sync engine status.
#[tauri::command]
pub async fn sync_engine_status(
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncEngineStatusResult, String> {
    let sync_repo = state.app_sync_repository();
    let status = sync_repo.get_engine_status().map_err(|e| e.to_string())?;
    let bootstrap_required = match get_device_id_from_store() {
        Some(device_id) => sync_repo
            .needs_bootstrap(&device_id)
            .map_err(|e| e.to_string())?,
        None => true,
    };
    let runtime = state.inner().device_sync_runtime();
    let background_running = runtime.background_task.lock().await.is_some();

    Ok(SyncEngineStatusResult {
        cursor: status.cursor,
        last_push_at: status.last_push_at,
        last_pull_at: status.last_pull_at,
        last_error: status.last_error,
        consecutive_failures: status.consecutive_failures,
        next_retry_at: status.next_retry_at,
        last_cycle_status: status.last_cycle_status,
        last_cycle_duration_ms: status.last_cycle_duration_ms,
        background_running,
        bootstrap_required,
    })
}

/// Bootstraps local sync tables from the latest snapshot when required.
#[tauri::command]
pub async fn sync_bootstrap_snapshot_if_needed(
    handle: AppHandle,
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncBootstrapResult, String> {
    let identity = get_sync_identity_from_store()
        .ok_or_else(|| "No sync identity configured. Please enable sync first.".to_string())?;
    let device_id = identity
        .device_id
        .clone()
        .ok_or_else(|| "No device ID configured".to_string())?;
    let token = get_access_token()?;

    let sync_state = state
        .device_enroll_service()
        .get_sync_state()
        .await
        .map_err(|e| e.message)?;
    if sync_state.state != SyncState::Ready {
        return Ok(SyncBootstrapResult {
            status: "skipped".to_string(),
            message: "Device is not in READY state".to_string(),
            snapshot_id: None,
            cursor: None,
        });
    }
    persist_device_config_from_identity(state.inner().as_ref(), &identity, "trusted").await;

    let sync_repo = state.app_sync_repository();
    if !sync_repo
        .needs_bootstrap(&device_id)
        .map_err(|e| e.to_string())?
    {
        return Ok(SyncBootstrapResult {
            status: "skipped".to_string(),
            message: "Snapshot bootstrap already completed".to_string(),
            snapshot_id: None,
            cursor: Some(sync_repo.get_cursor().map_err(|e| e.to_string())?),
        });
    }

    let client = create_client();
    debug!(
        "[DeviceSync] Requesting latest snapshot metadata for device {}",
        device_id
    );
    let latest = match client
        .get_latest_snapshot_with_cursor_fallback(&token, &device_id)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            if err.status_code() == Some(404) {
                debug!(
                    "[DeviceSync] Latest snapshot not found (404); requested snapshot generation and no local upload performed in this path"
                );
                return request_snapshot_generation(
                    &client,
                    &token,
                    &device_id,
                    &identity,
                    "No snapshot available yet. Requested generation.",
                )
                .await;
            }
            return Err(err.to_string());
        }
    };

    let latest = match latest {
        Some(value) => value,
        None => {
            debug!(
                "[DeviceSync] Latest snapshot endpoint returned no snapshot; requested snapshot generation and no local upload performed in this path"
            );
            return request_snapshot_generation(
                &client,
                &token,
                &device_id,
                &identity,
                "No snapshot available yet. Requested generation.",
            )
            .await;
        }
    };

    debug!(
        "[DeviceSync] Latest snapshot metadata: id='{}' schema={} oplog_seq={} size={}",
        latest.snapshot_id, latest.schema_version, latest.oplog_seq, latest.size_bytes
    );

    let snapshot_id = latest.snapshot_id.trim().to_string();
    if snapshot_id.is_empty() {
        debug!(
            "[DeviceSync] Latest snapshot metadata had empty snapshot_id; requested snapshot generation and no local upload performed in this path"
        );
        return request_snapshot_generation(
            &client,
            &token,
            &device_id,
            &identity,
            "Latest snapshot metadata was invalid. Requested a fresh snapshot.",
        )
        .await;
    }
    let snapshot_oplog_seq = latest.oplog_seq;
    let latest_checksum = if latest.checksum.trim().is_empty() {
        None
    } else {
        Some(latest.checksum)
    };
    let latest_tables = if latest.covers_tables.is_empty() {
        APP_SYNC_TABLES.iter().map(|v| v.to_string()).collect()
    } else {
        latest.covers_tables
    };

    let (headers, blob) = client
        .download_snapshot(&token, &device_id, &snapshot_id)
        .await
        .map_err(|e| e.to_string())?;
    debug!(
        "[DeviceSync] Snapshot download response headers: schema_version={} tables={} checksum={} blob_size={}",
        headers.schema_version,
        headers.covers_tables.join(","),
        headers.checksum,
        blob.len()
    );

    let actual_checksum = sha256_checksum(&blob);
    if headers.checksum != actual_checksum {
        return Err(format!(
            "Snapshot checksum mismatch (download header): expected={}, got={}",
            headers.checksum, actual_checksum
        ));
    }
    if let Some(expected_checksum) = latest_checksum.as_ref() {
        if expected_checksum != &actual_checksum {
            return Err(format!(
                "Snapshot checksum mismatch (latest metadata): expected={}, got={}",
                expected_checksum, actual_checksum
            ));
        }
    }

    let sqlite_image = decode_snapshot_sqlite_payload(blob, &identity)?;
    let temp_snapshot_path =
        std::env::temp_dir().join(format!("wf_snapshot_{}.db", Uuid::new_v4()));
    std::fs::write(&temp_snapshot_path, sqlite_image)
        .map_err(|e| format!("Failed to persist snapshot image: {}", e))?;
    let snapshot_path_str = temp_snapshot_path.to_string_lossy().to_string();

    let mut tables_to_restore: Vec<String> = latest_tables
        .iter()
        .filter(|table| APP_SYNC_TABLES.contains(&table.as_str()))
        .map(|table| table.to_string())
        .collect();
    if tables_to_restore.is_empty() {
        tables_to_restore = APP_SYNC_TABLES
            .iter()
            .map(|table| table.to_string())
            .collect();
    }

    let restore_result = sync_repo
        .restore_snapshot_tables_from_file(
            snapshot_path_str,
            tables_to_restore,
            snapshot_oplog_seq,
            device_id,
            identity.key_version,
        )
        .await;
    let _ = std::fs::remove_file(&temp_snapshot_path);
    restore_result.map_err(|e| e.to_string())?;

    let payload = PortfolioRequestPayload::builder()
        .account_ids(None)
        .market_sync_mode(MarketSyncMode::Incremental { asset_ids: None })
        .build();
    emit_portfolio_trigger_recalculate(&handle, payload);

    Ok(SyncBootstrapResult {
        status: "applied".to_string(),
        message: "Snapshot bootstrap completed".to_string(),
        snapshot_id: Some(snapshot_id),
        cursor: Some(snapshot_oplog_seq),
    })
}

/// Runs one sync engine cycle (push + pull skeleton with backoff and stale cursor handling).
async fn run_sync_cycle(context: Arc<ServiceContext>) -> Result<SyncCycleResult, String> {
    let runtime = context.device_sync_runtime();
    let _cycle_guard = runtime.cycle_mutex.lock().await;
    let cycle_started_at = std::time::Instant::now();
    let sync_repo = context.app_sync_repository();

    let identity = match get_sync_identity_from_store() {
        Some(value) => value,
        None => {
            let message = "No sync identity configured. Please enable sync first.".to_string();
            sync_repo
                .mark_engine_error(message.clone())
                .await
                .map_err(|e| e.to_string())?;
            let _ = sync_repo
                .mark_cycle_outcome(
                    "config_error".to_string(),
                    cycle_started_at.elapsed().as_millis() as i64,
                    None,
                )
                .await;
            return Ok(SyncCycleResult {
                status: "config_error".to_string(),
                lock_version: 0,
                pushed_count: 0,
                pulled_count: 0,
                cursor: sync_repo.get_cursor().unwrap_or(0),
                needs_bootstrap: false,
            });
        }
    };
    let device_id = match identity.device_id.clone() {
        Some(value) => value,
        None => {
            let message = "No device ID configured".to_string();
            sync_repo
                .mark_engine_error(message.clone())
                .await
                .map_err(|e| e.to_string())?;
            let _ = sync_repo
                .mark_cycle_outcome(
                    "config_error".to_string(),
                    cycle_started_at.elapsed().as_millis() as i64,
                    None,
                )
                .await;
            return Ok(SyncCycleResult {
                status: "config_error".to_string(),
                lock_version: 0,
                pushed_count: 0,
                pulled_count: 0,
                cursor: sync_repo.get_cursor().unwrap_or(0),
                needs_bootstrap: false,
            });
        }
    };

    let runtime_state = match context.device_enroll_service().get_sync_state().await {
        Ok(value) => value,
        Err(err) => {
            sync_repo
                .mark_engine_error(format!("Failed to read sync state: {}", err.message))
                .await
                .map_err(|e| e.to_string())?;
            let _ = sync_repo
                .mark_cycle_outcome(
                    "state_error".to_string(),
                    cycle_started_at.elapsed().as_millis() as i64,
                    Some((Utc::now() + chrono::Duration::seconds(15)).to_rfc3339()),
                )
                .await;
            return Ok(SyncCycleResult {
                status: "state_error".to_string(),
                lock_version: 0,
                pushed_count: 0,
                pulled_count: 0,
                cursor: sync_repo.get_cursor().unwrap_or(0),
                needs_bootstrap: false,
            });
        }
    };
    if runtime_state.state != SyncState::Ready {
        persist_device_config_from_identity(context.as_ref(), &identity, "untrusted").await;
        let _ = sync_repo
            .mark_cycle_outcome(
                "not_ready".to_string(),
                cycle_started_at.elapsed().as_millis() as i64,
                None,
            )
            .await;
        return Ok(SyncCycleResult {
            status: "not_ready".to_string(),
            lock_version: 0,
            pushed_count: 0,
            pulled_count: 0,
            cursor: sync_repo.get_cursor().unwrap_or(0),
            needs_bootstrap: false,
        });
    }

    persist_device_config_from_identity(context.as_ref(), &identity, "trusted").await;
    let token = match get_access_token() {
        Ok(value) => value,
        Err(err) => {
            sync_repo
                .mark_engine_error(format!("Auth error: {}", err))
                .await
                .map_err(|e| e.to_string())?;
            let _ = sync_repo
                .mark_cycle_outcome(
                    "auth_error".to_string(),
                    cycle_started_at.elapsed().as_millis() as i64,
                    Some((Utc::now() + chrono::Duration::seconds(30)).to_rfc3339()),
                )
                .await;
            return Ok(SyncCycleResult {
                status: "auth_error".to_string(),
                lock_version: 0,
                pushed_count: 0,
                pulled_count: 0,
                cursor: sync_repo.get_cursor().unwrap_or(0),
                needs_bootstrap: false,
            });
        }
    };

    let lock_version = sync_repo
        .acquire_cycle_lock()
        .await
        .map_err(|e| e.to_string())?;
    let mut local_cursor = sync_repo.get_cursor().map_err(|e| e.to_string())?;
    let client = create_client();

    let cursor_response = match client.get_events_cursor(&token, &device_id).await {
        Ok(response) => response,
        Err(err) => {
            sync_repo
                .mark_engine_error(format!("Cursor check failed: {}", err))
                .await
                .map_err(|e| e.to_string())?;
            let _ = sync_repo
                .mark_cycle_outcome(
                    "cursor_error".to_string(),
                    cycle_started_at.elapsed().as_millis() as i64,
                    Some((Utc::now() + chrono::Duration::seconds(10)).to_rfc3339()),
                )
                .await;
            return Ok(SyncCycleResult {
                status: "cursor_error".to_string(),
                lock_version,
                pushed_count: 0,
                pulled_count: 0,
                cursor: local_cursor,
                needs_bootstrap: false,
            });
        }
    };
    if let Some(gc_watermark) = cursor_response.gc_watermark {
        if local_cursor < gc_watermark {
            let msg = format!(
                "Local cursor {} is older than GC watermark {}. Snapshot bootstrap required.",
                local_cursor, gc_watermark
            );
            sync_repo
                .mark_engine_error(msg.clone())
                .await
                .map_err(|e| e.to_string())?;
            let _ = sync_repo
                .mark_cycle_outcome(
                    "stale_cursor".to_string(),
                    cycle_started_at.elapsed().as_millis() as i64,
                    None,
                )
                .await;
            return Ok(SyncCycleResult {
                status: "stale_cursor".to_string(),
                lock_version,
                pushed_count: 0,
                pulled_count: 0,
                cursor: local_cursor,
                needs_bootstrap: true,
            });
        }
    }

    let pending = sync_repo
        .list_pending_outbox(500)
        .map_err(|e| e.to_string())?;
    let allow_unsupported = allow_unsupported_entity_sync();
    let mut push_events = Vec::new();
    let mut push_event_ids = Vec::new();
    let mut unsupported_event_ids = Vec::new();
    let mut max_retry_count = 0;

    for event in pending {
        if !allow_unsupported && !remote_supports_entity(&event.entity) {
            unsupported_event_ids.push(event.event_id.clone());
            continue;
        }

        max_retry_count = max_retry_count.max(event.retry_count);
        let event_type = format!(
            "{}.{}.v1",
            sync_entity_name(&event.entity),
            sync_operation_name(&event.op)
        );
        push_event_ids.push(event.event_id.clone());
        let payload_key_version = event.payload_key_version.max(1);
        let encrypted_payload =
            match encrypt_sync_payload(&event.payload, &identity, payload_key_version) {
                Ok(payload) => payload,
                Err(err) => {
                    sync_repo
                        .mark_engine_error(format!("Push payload encryption failed: {}", err))
                        .await
                        .map_err(|e| e.to_string())?;
                    let _ = sync_repo
                        .mark_cycle_outcome(
                            "push_prepare_error".to_string(),
                            cycle_started_at.elapsed().as_millis() as i64,
                            Some((Utc::now() + chrono::Duration::seconds(15)).to_rfc3339()),
                        )
                        .await;
                    return Ok(SyncCycleResult {
                        status: "push_prepare_error".to_string(),
                        lock_version,
                        pushed_count: 0,
                        pulled_count: 0,
                        cursor: local_cursor,
                        needs_bootstrap: false,
                    });
                }
            };
        push_events.push(SyncPushEventRequest {
            event_id: event.event_id,
            device_id: device_id.clone(),
            event_type,
            entity: to_remote_entity(&event.entity),
            entity_id: event.entity_id,
            client_timestamp: event.client_timestamp,
            payload: encrypted_payload,
            payload_key_version,
        });
    }

    if !unsupported_event_ids.is_empty() {
        sync_repo
            .schedule_outbox_retry(
                unsupported_event_ids,
                6 * 60 * 60,
                Some("Entity not yet supported by remote sync contract".to_string()),
                Some("unsupported_entity".to_string()),
            )
            .await
            .map_err(|e| e.to_string())?;
    }

    let mut pushed_count = 0usize;
    if !push_events.is_empty() {
        match client
            .push_events(
                &token,
                &device_id,
                SyncPushRequest {
                    events: push_events,
                },
            )
            .await
        {
            Ok(push_response) => {
                let mut sent_ids: Vec<String> = push_response
                    .accepted
                    .into_iter()
                    .map(|item| item.event_id)
                    .collect();
                sent_ids.extend(
                    push_response
                        .duplicate
                        .into_iter()
                        .map(|item| item.event_id),
                );
                pushed_count = sent_ids.len();
                sync_repo
                    .mark_outbox_sent(sent_ids)
                    .await
                    .map_err(|e| e.to_string())?;
                sync_repo
                    .mark_push_completed()
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Err(err) => {
                let backoff = core_sync_backoff_seconds(max_retry_count);
                let retry_at =
                    (chrono::Utc::now() + chrono::Duration::seconds(backoff)).to_rfc3339();
                let retry_class = err.retry_class();
                match retry_class {
                    ApiRetryClass::Retryable | ApiRetryClass::ReauthRequired => {
                        sync_repo
                            .schedule_outbox_retry(
                                push_event_ids,
                                backoff,
                                Some(err.to_string()),
                                Some(retry_class_code(retry_class).to_string()),
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    ApiRetryClass::Permanent => {
                        sync_repo
                            .mark_outbox_dead(
                                push_event_ids,
                                Some(err.to_string()),
                                Some(retry_class_code(retry_class).to_string()),
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                }
                sync_repo
                    .mark_engine_error(format!("Push failed: {}", err))
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = sync_repo
                    .mark_cycle_outcome(
                        "push_error".to_string(),
                        cycle_started_at.elapsed().as_millis() as i64,
                        Some(retry_at),
                    )
                    .await;
                return Ok(SyncCycleResult {
                    status: "push_error".to_string(),
                    lock_version,
                    pushed_count: 0,
                    pulled_count: 0,
                    cursor: local_cursor,
                    needs_bootstrap: false,
                });
            }
        }
    }

    let mut pulled_count = 0usize;
    if cursor_response.cursor > local_cursor {
        loop {
            let pull_response = match client
                .pull_events(&token, &device_id, Some(local_cursor), Some(500))
                .await
            {
                Ok(value) => value,
                Err(err) => {
                    sync_repo
                        .mark_engine_error(format!("Pull failed: {}", err))
                        .await
                        .map_err(|e| e.to_string())?;
                    let _ = sync_repo
                        .mark_cycle_outcome(
                            "pull_error".to_string(),
                            cycle_started_at.elapsed().as_millis() as i64,
                            Some((Utc::now() + chrono::Duration::seconds(10)).to_rfc3339()),
                        )
                        .await;
                    return Ok(SyncCycleResult {
                        status: "pull_error".to_string(),
                        lock_version,
                        pushed_count,
                        pulled_count: 0,
                        cursor: local_cursor,
                        needs_bootstrap: false,
                    });
                }
            };

            if let Some(gc_watermark) = pull_response.gc_watermark {
                if local_cursor < gc_watermark {
                    sync_repo
                        .mark_engine_error(format!(
                            "Cursor {} is older than pull GC watermark {}",
                            local_cursor, gc_watermark
                        ))
                        .await
                        .map_err(|e| e.to_string())?;
                    let _ = sync_repo
                        .mark_cycle_outcome(
                            "stale_cursor".to_string(),
                            cycle_started_at.elapsed().as_millis() as i64,
                            None,
                        )
                        .await;
                    return Ok(SyncCycleResult {
                        status: "stale_cursor".to_string(),
                        lock_version,
                        pushed_count,
                        pulled_count: 0,
                        cursor: local_cursor,
                        needs_bootstrap: true,
                    });
                }
            }

            let mut decoded_events: Vec<(
                LocalSyncEntity,
                String,
                LocalSyncOperation,
                String,
                String,
                i64,
                serde_json::Value,
            )> = Vec::with_capacity(pull_response.events.len());
            for remote_event in pull_response.events {
                let local_entity = from_remote_entity(&remote_event.entity);
                if local_entity == LocalSyncEntity::Snapshot {
                    debug!(
                        "[DeviceSync] Skipping snapshot control event during replay: event_id={} event_type={} seq={}",
                        remote_event.event_id, remote_event.event_type, remote_event.seq
                    );
                    continue;
                }
                if !allow_unsupported && !remote_supports_entity(&local_entity) {
                    let message = format!(
                        "Replay blocked: unsupported entity '{}' for event {}",
                        sync_entity_name(&local_entity),
                        remote_event.event_id
                    );
                    log::warn!("[DeviceSync] {}", message);
                    sync_repo
                        .mark_engine_error(message.clone())
                        .await
                        .map_err(|e| e.to_string())?;
                    let _ = sync_repo
                        .mark_cycle_outcome(
                            "replay_blocked".to_string(),
                            cycle_started_at.elapsed().as_millis() as i64,
                            Some((Utc::now() + chrono::Duration::hours(6)).to_rfc3339()),
                        )
                        .await;
                    return Ok(SyncCycleResult {
                        status: "replay_blocked".to_string(),
                        lock_version,
                        pushed_count,
                        pulled_count,
                        cursor: local_cursor,
                        needs_bootstrap: false,
                    });
                }
                let local_op = match parse_event_operation(&remote_event.event_type) {
                    Some(op) => op,
                    None => {
                        let message = format!(
                            "Replay blocked: unsupported event type '{}' for event {}",
                            remote_event.event_type, remote_event.event_id
                        );
                        log::warn!("[DeviceSync] {}", message);
                        sync_repo
                            .mark_engine_error(message.clone())
                            .await
                            .map_err(|e| e.to_string())?;
                        let _ = sync_repo
                            .mark_cycle_outcome(
                                "replay_blocked".to_string(),
                                cycle_started_at.elapsed().as_millis() as i64,
                                Some((Utc::now() + chrono::Duration::hours(6)).to_rfc3339()),
                            )
                            .await;
                        return Ok(SyncCycleResult {
                            status: "replay_blocked".to_string(),
                            lock_version,
                            pushed_count,
                            pulled_count,
                            cursor: local_cursor,
                            needs_bootstrap: false,
                        });
                    }
                };
                let decrypted_payload = match decrypt_sync_payload(
                    &remote_event.payload,
                    &identity,
                    remote_event.payload_key_version,
                ) {
                    Ok(payload) => payload,
                    Err(err) => {
                        let message = format!(
                            "Replay decrypt failed for event {}: {}",
                            remote_event.event_id, err
                        );
                        sync_repo
                            .mark_engine_error(message.clone())
                            .await
                            .map_err(|e| e.to_string())?;
                        let _ = sync_repo
                            .mark_cycle_outcome(
                                "replay_error".to_string(),
                                cycle_started_at.elapsed().as_millis() as i64,
                                Some((Utc::now() + chrono::Duration::seconds(10)).to_rfc3339()),
                            )
                            .await;
                        return Ok(SyncCycleResult {
                            status: "replay_error".to_string(),
                            lock_version,
                            pushed_count,
                            pulled_count,
                            cursor: local_cursor,
                            needs_bootstrap: false,
                        });
                    }
                };
                let payload_json: serde_json::Value = match serde_json::from_str(&decrypted_payload) {
                    Ok(payload) => payload,
                    Err(err) => {
                        let message = format!(
                            "Replay payload decode failed for event {}: {}",
                            remote_event.event_id, err
                        );
                        sync_repo
                            .mark_engine_error(message.clone())
                            .await
                            .map_err(|e| e.to_string())?;
                        let _ = sync_repo
                            .mark_cycle_outcome(
                                "replay_error".to_string(),
                                cycle_started_at.elapsed().as_millis() as i64,
                                Some((Utc::now() + chrono::Duration::seconds(10)).to_rfc3339()),
                            )
                            .await;
                        return Ok(SyncCycleResult {
                            status: "replay_error".to_string(),
                            lock_version,
                            pushed_count,
                            pulled_count,
                            cursor: local_cursor,
                            needs_bootstrap: false,
                        });
                    }
                };

                decoded_events.push((
                    local_entity,
                    remote_event.entity_id,
                    local_op,
                    remote_event.event_id,
                    remote_event.client_timestamp,
                    remote_event.seq,
                    payload_json,
                ));
            }

            let applied_count = match sync_repo.apply_remote_events_lww_batch(decoded_events).await {
                Ok(applied) => applied,
                Err(err) => {
                    let message = format!("Replay apply failed: {}", err);
                    sync_repo
                        .mark_engine_error(message.clone())
                        .await
                        .map_err(|e| e.to_string())?;
                    let _ = sync_repo
                        .mark_cycle_outcome(
                            "replay_error".to_string(),
                            cycle_started_at.elapsed().as_millis() as i64,
                            Some((Utc::now() + chrono::Duration::seconds(10)).to_rfc3339()),
                        )
                        .await;
                    return Ok(SyncCycleResult {
                        status: "replay_error".to_string(),
                        lock_version,
                        pushed_count,
                        pulled_count,
                        cursor: local_cursor,
                        needs_bootstrap: false,
                    });
                }
            };
            pulled_count += applied_count;

            local_cursor = pull_response.next_cursor;
            sync_repo
                .set_cursor(local_cursor)
                .await
                .map_err(|e| e.to_string())?;

            if !pull_response.has_more {
                break;
            }
        }
        sync_repo
            .mark_pull_completed()
            .await
            .map_err(|e| e.to_string())?;
    }

    if local_cursor > 20_000 {
        let prune_seq = local_cursor - 10_000;
        let _ = sync_repo.prune_applied_events_up_to_seq(prune_seq).await;
    }

    sync_repo
        .mark_cycle_outcome(
            "ok".to_string(),
            cycle_started_at.elapsed().as_millis() as i64,
            None,
        )
        .await
        .map_err(|e| e.to_string())?;

    Ok(SyncCycleResult {
        status: "ok".to_string(),
        lock_version,
        pushed_count,
        pulled_count,
        cursor: local_cursor,
        needs_bootstrap: false,
    })
}

/// Runs one sync engine cycle (push + pull + replay).
#[tauri::command]
pub async fn sync_trigger_cycle(
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncCycleResult, String> {
    run_sync_cycle(Arc::clone(state.inner())).await
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncBackgroundEngineResult {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncSnapshotUploadResult {
    pub status: String,
    pub snapshot_id: Option<String>,
    pub oplog_seq: Option<i64>,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotUploadProgressEvent {
    stage: String,
    progress: u8,
    message: String,
}

const DEVICE_SYNC_SNAPSHOT_UPLOAD_PROGRESS_EVENT: &str = "device-sync:snapshot-upload-progress";

fn emit_snapshot_upload_progress(
    handle: Option<&AppHandle>,
    stage: &str,
    progress: u8,
    message: &str,
) {
    if let Some(handle) = handle {
        let payload = SnapshotUploadProgressEvent {
            stage: stage.to_string(),
            progress,
            message: message.to_string(),
        };
        let _ = handle.emit(DEVICE_SYNC_SNAPSHOT_UPLOAD_PROGRESS_EVENT, payload);
    }
}

fn snapshot_upload_cancelled_result(message: &str) -> SyncSnapshotUploadResult {
    SyncSnapshotUploadResult {
        status: "cancelled".to_string(),
        snapshot_id: None,
        oplog_seq: None,
        message: message.to_string(),
    }
}

async fn generate_snapshot_now_internal(
    handle: Option<&AppHandle>,
    context: Arc<ServiceContext>,
) -> Result<SyncSnapshotUploadResult, String> {
    context
        .device_sync_runtime()
        .snapshot_upload_cancelled
        .store(false, Ordering::Relaxed);
    emit_snapshot_upload_progress(handle, "start", 5, "Preparing snapshot export");

    let identity = get_sync_identity_from_store()
        .ok_or_else(|| "No sync identity configured. Please enable sync first.".to_string())?;
    let device_id = identity
        .device_id
        .clone()
        .ok_or_else(|| "No device ID configured".to_string())?;
    let key_version = identity.key_version.unwrap_or(1).max(1);
    let token = get_access_token()?;

    let sync_state = create_client()
        .get_device(&token, &device_id)
        .await
        .map_err(|e| e.to_string())?;
    debug!(
        "[DeviceSync] Snapshot upload eligibility: device_id={} trust_state={:?}",
        device_id, sync_state.trust_state
    );
    if sync_state.trust_state != wealthfolio_device_sync::TrustState::Trusted {
        return Ok(SyncSnapshotUploadResult {
            status: "skipped".to_string(),
            snapshot_id: None,
            oplog_seq: None,
            message: "Current device is not trusted".to_string(),
        });
    }
    if context
        .device_sync_runtime()
        .snapshot_upload_cancelled
        .load(Ordering::Relaxed)
    {
        emit_snapshot_upload_progress(handle, "cancelled", 0, "Snapshot upload cancelled");
        return Ok(snapshot_upload_cancelled_result(
            "Snapshot upload cancelled before export",
        ));
    }

    let sqlite_bytes = context
        .app_sync_repository()
        .export_snapshot_sqlite_image(APP_SYNC_TABLES.iter().map(|v| v.to_string()).collect())
        .await
        .map_err(|e| format!("Failed to export snapshot SQLite image: {}", e))?;
    emit_snapshot_upload_progress(handle, "exported", 35, "Snapshot exported");
    if context
        .device_sync_runtime()
        .snapshot_upload_cancelled
        .load(Ordering::Relaxed)
    {
        emit_snapshot_upload_progress(handle, "cancelled", 0, "Snapshot upload cancelled");
        return Ok(snapshot_upload_cancelled_result(
            "Snapshot upload cancelled after export",
        ));
    }

    let encoded_snapshot = BASE64_STANDARD.encode(sqlite_bytes);
    let encrypted_snapshot_payload = encrypt_sync_payload(&encoded_snapshot, &identity, key_version)?;
    let payload = encrypted_snapshot_payload.into_bytes();
    let checksum = sha256_checksum(&payload);
    let metadata_payload = encrypt_sync_payload(
        &serde_json::json!({
            "schemaVersion": 1,
            "coversTables": APP_SYNC_TABLES,
            "generatedAt": Utc::now().to_rfc3339(),
        })
        .to_string(),
        &identity,
        key_version,
    )?;

    let upload_headers = wealthfolio_device_sync::SnapshotUploadHeaders {
        event_id: Some(Uuid::now_v7().to_string()),
        schema_version: 1,
        covers_tables: APP_SYNC_TABLES.iter().map(|v| v.to_string()).collect(),
        size_bytes: payload.len() as i64,
        checksum,
        metadata_payload,
        payload_key_version: key_version,
    };
    let checksum_prefix = upload_headers
        .checksum
        .strip_prefix("sha256:")
        .unwrap_or(upload_headers.checksum.as_str());
    let checksum_prefix = &checksum_prefix[..checksum_prefix.len().min(12)];
    emit_snapshot_upload_progress(handle, "uploading", 70, "Uploading snapshot");
    info!(
        "[DeviceSync] Snapshot upload start device_id={} size_bytes={} key_version={} checksum=sha256:{}",
        device_id,
        upload_headers.size_bytes,
        upload_headers.payload_key_version,
        checksum_prefix
    );

    let runtime = context.device_sync_runtime();
    let upload_result = create_client()
        .upload_snapshot_with_cancel_flag(
            &token,
            &device_id,
            upload_headers,
            payload,
            Some(&runtime.snapshot_upload_cancelled),
        )
        .await;
    let response = match upload_result {
        Ok(value) => value,
        Err(err) => {
            let message = err.to_string();
            if message.to_ascii_lowercase().contains("cancelled") {
                emit_snapshot_upload_progress(
                    handle,
                    "cancelled",
                    0,
                    "Snapshot upload cancelled during transfer",
                );
                return Ok(snapshot_upload_cancelled_result(
                    "Snapshot upload cancelled during transfer",
                ));
            }
            return Err(message);
        }
    };
    info!(
        "[DeviceSync] Snapshot upload success snapshot_id={} oplog_seq={} r2_key={}",
        response.snapshot_id, response.oplog_seq, response.r2_key
    );
    emit_snapshot_upload_progress(handle, "complete", 100, "Snapshot upload complete");

    Ok(SyncSnapshotUploadResult {
        status: "uploaded".to_string(),
        snapshot_id: Some(response.snapshot_id),
        oplog_seq: Some(response.oplog_seq),
        message: "Snapshot uploaded".to_string(),
    })
}

async fn maybe_generate_snapshot_for_policy(context: Arc<ServiceContext>) {
    let cursor = match context.app_sync_repository().get_cursor() {
        Ok(value) => value,
        Err(err) => {
            log::warn!("[DeviceSync] Failed reading cursor for snapshot policy: {}", err);
            return;
        }
    };

    let now = Utc::now();
    let runtime = context.device_sync_runtime();
    let (due_by_time, due_by_seq, last_uploaded_cursor) = {
        let state = runtime.snapshot_policy.lock().await;
        let due_by_time = state
            .last_uploaded_at
            .map(|at| (now - at).num_seconds() >= DEVICE_SYNC_SNAPSHOT_INTERVAL_SECS as i64)
            .unwrap_or(true);
        let last_uploaded_cursor = state.last_uploaded_cursor;
        let due_by_seq =
            cursor.saturating_sub(last_uploaded_cursor) >= DEVICE_SYNC_SNAPSHOT_EVENT_THRESHOLD;
        (due_by_time, due_by_seq, last_uploaded_cursor)
    };
    let delta_seq = cursor.saturating_sub(last_uploaded_cursor);
    debug!(
        "[DeviceSync] Snapshot policy eval cursor={} last_uploaded_cursor={} delta_seq={} due_by_time={} due_by_seq={} threshold_seq={} threshold_secs={}",
        cursor,
        last_uploaded_cursor,
        delta_seq,
        due_by_time,
        due_by_seq,
        DEVICE_SYNC_SNAPSHOT_EVENT_THRESHOLD,
        DEVICE_SYNC_SNAPSHOT_INTERVAL_SECS
    );

    if !due_by_time && !due_by_seq {
        debug!("[DeviceSync] Snapshot policy skipped: neither time nor seq threshold met");
        return;
    }

    match generate_snapshot_now_internal(None, Arc::clone(&context)).await {
        Ok(result) if result.status == "uploaded" => {
            let mut state = runtime.snapshot_policy.lock().await;
            state.last_uploaded_at = Some(now);
            state.last_uploaded_cursor = result.oplog_seq.unwrap_or(cursor);
        }
        Ok(_) => {}
        Err(err) => {
            let key_version = get_sync_identity_from_store()
                .and_then(|identity| identity.key_version)
                .unwrap_or(1)
                .max(1);
            log::warn!(
                "[DeviceSync] Snapshot policy upload failed cursor={} key_version={} error_class={} error={}",
                cursor,
                key_version,
                classify_snapshot_upload_error(&err),
                err
            );
        }
    }
}

pub async fn ensure_background_engine_started(context: Arc<ServiceContext>) -> Result<(), String> {
    let runtime = context.device_sync_runtime();
    let mut guard = runtime.background_task.lock().await;
    if guard.is_some() {
        return Ok(());
    }

    let handle = tokio::spawn(async move {
        loop {
            let cycle_result = run_sync_cycle(Arc::clone(&context)).await;
            if let Err(err) = &cycle_result {
                log::warn!("[DeviceSync] Background cycle failed: {}", err);
            }
            if let Ok(result) = &cycle_result {
                debug!(
                    "[DeviceSync] Cycle complete status={} needs_bootstrap={} cursor={} pushed={} pulled={}",
                    result.status,
                    result.needs_bootstrap,
                    result.cursor,
                    result.pushed_count,
                    result.pulled_count
                );
                if result.status == "ok" {
                    maybe_generate_snapshot_for_policy(Arc::clone(&context)).await;
                } else {
                    debug!(
                        "[DeviceSync] Snapshot policy skipped because cycle status is '{}' (requires 'ok')",
                        result.status
                    );
                }
            }

            let jitter_bound = DEVICE_SYNC_INTERVAL_JITTER_SECS.saturating_mul(1000);
            let jitter_ms = if jitter_bound > 0 {
                (Utc::now().timestamp_millis().unsigned_abs() % jitter_bound) as u64
            } else {
                0
            };
            let mut delay_ms = DEVICE_SYNC_FOREGROUND_INTERVAL_SECS.saturating_mul(1000) + jitter_ms;

            if let Ok(engine_status) = context.app_sync_repository().get_engine_status() {
                if let Some(next_retry_at) = engine_status.next_retry_at.as_deref() {
                    if let Some(wait_ms) = millis_until_rfc3339(next_retry_at) {
                        delay_ms = wait_ms.saturating_add(jitter_ms).max(1_000);
                    }
                }
            }

            if let Ok(pending) = context.app_sync_repository().list_pending_outbox(1) {
                if !pending.is_empty() {
                    delay_ms = delay_ms.min(2_000 + (jitter_ms % 500));
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    });
    *guard = Some(handle);
    Ok(())
}

pub async fn ensure_background_engine_stopped(context: Arc<ServiceContext>) -> Result<(), String> {
    let runtime = context.device_sync_runtime();
    let mut guard = runtime.background_task.lock().await;
    if let Some(handle) = guard.take() {
        handle.abort();
    }
    Ok(())
}

#[tauri::command]
pub async fn device_sync_start_background_engine(
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncBackgroundEngineResult, String> {
    ensure_background_engine_started(Arc::clone(state.inner())).await?;
    Ok(SyncBackgroundEngineResult {
        status: "started".to_string(),
        message: "Device sync background engine started".to_string(),
    })
}

#[tauri::command]
pub async fn device_sync_stop_background_engine(
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncBackgroundEngineResult, String> {
    ensure_background_engine_stopped(Arc::clone(state.inner())).await?;
    Ok(SyncBackgroundEngineResult {
        status: "stopped".to_string(),
        message: "Device sync background engine stopped".to_string(),
    })
}

#[tauri::command]
pub async fn device_sync_generate_snapshot_now(
    handle: AppHandle,
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncSnapshotUploadResult, String> {
    generate_snapshot_now_internal(Some(&handle), Arc::clone(state.inner())).await
}

#[tauri::command]
pub async fn device_sync_cancel_snapshot_upload(
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncBackgroundEngineResult, String> {
    state
        .inner()
        .device_sync_runtime()
        .snapshot_upload_cancelled
        .store(true, Ordering::Relaxed);
    Ok(SyncBackgroundEngineResult {
        status: "cancel_requested".to_string(),
        message: "Snapshot upload cancellation requested".to_string(),
    })
}

/// Explicitly-named alias for `sync_engine_status`.
#[tauri::command]
pub async fn device_sync_engine_status(
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncEngineStatusResult, String> {
    sync_engine_status(state).await
}

/// Explicitly-named alias for `sync_bootstrap_snapshot_if_needed`.
#[tauri::command]
pub async fn device_sync_bootstrap_snapshot_if_needed(
    handle: AppHandle,
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncBootstrapResult, String> {
    sync_bootstrap_snapshot_if_needed(handle, state).await
}

/// Explicitly-named alias for `sync_trigger_cycle`.
#[tauri::command]
pub async fn device_sync_trigger_cycle(
    state: State<'_, Arc<ServiceContext>>,
) -> Result<SyncCycleResult, String> {
    sync_trigger_cycle(state).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Pairing
// ─────────────────────────────────────────────────────────────────────────────

/// Create a pairing session (trusted device side).
#[tauri::command(rename_all = "camelCase")]
pub async fn create_pairing(
    code_hash: String,
    ephemeral_public_key: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<CreatePairingResponse, String> {
    debug!("Creating pairing session...");

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .create_pairing(
            &token,
            &device_id,
            CreatePairingRequest {
                code_hash,
                ephemeral_public_key,
            },
        )
        .await
        .map_err(|e| e.to_string())
}

/// Get pairing session details.
#[tauri::command(rename_all = "camelCase")]
pub async fn get_pairing(
    pairing_id: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<GetPairingResponse, String> {
    debug!("Getting pairing session: {}", pairing_id);

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .get_pairing(&token, &device_id, &pairing_id)
        .await
        .map_err(|e| e.to_string())
}

/// Approve a pairing session.
#[tauri::command(rename_all = "camelCase")]
pub async fn approve_pairing(
    pairing_id: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<SuccessResponse, String> {
    debug!("Approving pairing session: {}", pairing_id);

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .approve_pairing(&token, &device_id, &pairing_id)
        .await
        .map_err(|e| e.to_string())
}

/// Complete a pairing session with key bundle.
#[tauri::command(rename_all = "camelCase")]
pub async fn complete_pairing(
    pairing_id: String,
    encrypted_key_bundle: String,
    sas_proof: serde_json::Value,
    signature: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<SuccessResponse, String> {
    debug!("Completing pairing session: {}", pairing_id);

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .complete_pairing(
            &token,
            &device_id,
            &pairing_id,
            CompletePairingRequest {
                encrypted_key_bundle,
                sas_proof,
                signature,
            },
        )
        .await
        .map_err(|e| e.to_string())
}

/// Cancel a pairing session.
#[tauri::command(rename_all = "camelCase")]
pub async fn cancel_pairing(
    pairing_id: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<SuccessResponse, String> {
    debug!("Canceling pairing session: {}", pairing_id);

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .cancel_pairing(&token, &device_id, &pairing_id)
        .await
        .map_err(|e| e.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Claimer-Side Pairing (New Device)
// ─────────────────────────────────────────────────────────────────────────────

/// Claim a pairing session using the code from the issuer device.
///
/// This is called by the claimer (new device) to join a pairing session.
/// Returns the issuer's ephemeral public key for deriving the shared secret.
#[tauri::command(rename_all = "camelCase")]
pub async fn claim_pairing(
    code: String,
    ephemeral_public_key: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<ClaimPairingResponse, String> {
    info!("[DeviceSync] Claiming pairing session...");

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .claim_pairing(
            &token,
            &device_id,
            ClaimPairingRequest {
                code,
                ephemeral_public_key,
            },
        )
        .await
        .map_err(|e| e.to_string())
}

/// Poll for messages/key bundle from the issuer (claimer side).
///
/// The claimer polls this endpoint to receive the encrypted RK bundle
/// from the issuer after they complete the pairing.
#[tauri::command(rename_all = "camelCase")]
pub async fn get_pairing_messages(
    pairing_id: String,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<PairingMessagesResponse, String> {
    debug!("[DeviceSync] Polling for pairing messages: {}", pairing_id);

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .get_pairing_messages(&token, &device_id, &pairing_id)
        .await
        .map_err(|e| e.to_string())
}

/// Confirm pairing and become trusted (claimer side).
///
/// This is the final step in the pairing flow. After successfully
/// decrypting the RK bundle, the claimer calls this to confirm and
/// be marked as trusted.
#[tauri::command(rename_all = "camelCase")]
pub async fn confirm_pairing(
    pairing_id: String,
    proof: Option<String>,
    _state: State<'_, Arc<ServiceContext>>,
) -> Result<ConfirmPairingResponse, String> {
    info!("[DeviceSync] Confirming pairing: {}", pairing_id);

    let token = get_access_token()?;
    let device_id =
        get_device_id_from_store().ok_or_else(|| "No device ID configured".to_string())?;

    create_client()
        .confirm_pairing(
            &token,
            &device_id,
            &pairing_id,
            ConfirmPairingRequest { proof },
        )
        .await
        .map_err(|e| e.to_string())
}
