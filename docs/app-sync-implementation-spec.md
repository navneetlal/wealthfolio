# Wealthfolio App-Side Sync Implementation Specification

> **Audience**: App-side developer / AI agent implementing the client sync layer.
> **API Status**: All endpoints are fully implemented and deployed.
> **App Status**: Device enrollment, E2EE key bootstrap, and device pairing are implemented. Event sync, snapshots, and the sync engine are TODO.
> **Last verified against codebase**: 2026-02-10

---

## Table of Contents

- [Part I: Identity & Trust (Implemented)](#part-i-identity--trust-implemented)
  1. [Architecture Overview](#1-architecture-overview)
  2. [HTTP Conventions](#2-http-conventions)
  3. [Storage Architecture](#3-storage-architecture)
  4. [State Machine](#4-state-machine)
  5. [Device Enrollment](#5-device-enrollment)
  6. [E2EE Key Bootstrap](#6-e2ee-key-bootstrap)
  7. [Device Pairing](#7-device-pairing)
  8. [Key Rotation](#8-key-rotation)
- [Part II: Event Sync (TODO)](#part-ii-event-sync-todo)
  9. [Event Sync Overview](#9-event-sync-overview)
  10. [Outbox Write Path](#10-outbox-write-path)
  11. [Event Push](#11-event-push)
  12. [Event Pull & Replay](#12-event-pull--replay)
  13. [Event Cursor](#13-event-cursor)
  14. [Conflict Resolution (LWW)](#14-conflict-resolution-lww)
- [Part III: Snapshot Sync (TODO)](#part-iii-snapshot-sync-todo)
  15. [Snapshot Bootstrap](#15-snapshot-bootstrap)
  16. [Snapshot Generation](#16-snapshot-generation)
  17. [Snapshot Request](#17-snapshot-request)
- [Part IV: Client Architecture (TODO)](#part-iv-client-architecture-todo)
  18. [Client-Side Data Model](#18-client-side-data-model)
  19. [Sync Engine Scheduling](#19-sync-engine-scheduling)
- [Appendices](#appendices)
  - [A. Error Codes Reference](#a-error-codes-reference)
  - [B. GC Watermark](#b-gc-watermark)
  - [C. Event Encryption](#c-event-encryption)
  - [D. Complete API Endpoint Summary](#d-complete-api-endpoint-summary)
  - [E. Security Checklist](#e-security-checklist)
  - [F. Implementation Checklist](#f-implementation-checklist)

---

# Part I: Identity & Trust (Implemented)

## 1. Architecture Overview

### Core Concepts

- **Event-log sync**: Every local mutation is captured as an encrypted event. Events are pushed to the server, assigned a monotonic sequence number (`seq`), and pulled by other devices for replay.
- **E2EE**: All payloads are encrypted client-side with a shared Root Key (RK). The server never sees plaintext data.
- **Outbox pattern**: Local mutation + outbox event are written in the same SQLite transaction. The push loop drains the outbox asynchronously.
- **Last-Write-Wins (LWW)**: Conflicts are resolved by `client_timestamp` (higher wins), with `event_id` as tiebreaker.
- **Snapshot bootstrap**: New devices can restore from an encrypted R2-stored snapshot instead of replaying the full event log.

### Entity Types

| Entity | Description |
|---|---|
| `account` | Brokerage accounts |
| `asset` | Assets/securities |
| `activity` | Transactions/activities |
| `activity_import_profile` | CSV import column mappings |
| `goal` | Financial goals |
| `contribution_limit` | Contribution limits |
| `settings` | User settings |
| `snapshot` | Snapshot metadata (system-managed, never client-generated) |

### Event Type Format

Event types follow the pattern: `{entity}.{operation}.v{version}`

- **Operations**: `create`, `update`, `delete`, `request`
- **Regex**: `/^[a-z_]+\.(create|update|delete|request)\.v\d+$/`
- **Examples**: `account.create.v1`, `activity.update.v1`, `goal.delete.v1`

### Visibility Rules

- **User's own events**: Always visible (all entity types)
- **Team member events**: Only visible for `account` entities where the account has `sharedWithHousehold = true` in the `broker_accounts` table
- All other entity types are **user-scoped only** -- never shared across team members

---

## 2. HTTP Conventions

### Base URL

```
https://api.wealthfolio.app/api/v1
```

### Required Headers

Every sync API request requires:

| Header | Description |
|---|---|
| `Authorization` | `Bearer <supabase_jwt>` |
| `X-WF-Device-Id` | Device UUID obtained from enrollment |
| `Content-Type` | `application/json` (unless uploading binary) |

### Error Response Format

All errors return this structure:

```json
{
  "error": "BAD_REQUEST",
  "code": "SYNC_DEVICE_MISMATCH",
  "message": "Event device_id does not match request device"
}
```

- `error` -- HTTP-level error category (e.g., `BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`)
- `code` -- Machine-readable error code for programmatic handling (see [Appendix A](#a-error-codes-reference))
- `message` -- Human-readable description

### Success Response Format

For operations without specific return data:

```json
{
  "success": true
}
```

---

## 3. Storage Architecture

### What Goes Where

| Data | Storage Location | Reason |
|---|---|---|
| `device_nonce` | OS Keychain only | Must NOT transfer with DB backup/restore |
| `device_id` | App SQLite DB | Server-assigned, can be restored |
| `root_key` | OS Keychain only | Secret -- never in plaintext storage |
| `key_version` | App SQLite DB | Needed to detect stale keys |
| `device_secret_key` | OS Keychain only | Ed25519 private key |
| `device_public_key` | App SQLite DB | Can be public |

### SyncIdentity Structure

```
SyncIdentity:
  version: int              // Storage format version (currently 1)
  device_nonce: string      // UUID in Keychain -- physical device identifier
  device_id: string         // Server-assigned device ID
  root_key: bytes?          // 32-byte RK (null = not yet bootstrapped/paired)
  key_version: int?         // E2EE key epoch this device is trusted at
  device_secret_key: bytes? // Ed25519 private key
  device_public_key: bytes? // Ed25519 public key
```

**Critical:** `device_nonce` must be stored in OS keychain, NOT in SQLite. This ensures it doesn't transfer when user backs up and restores the database to a different device.

---

## 4. State Machine

### States

```
SyncState:
  FRESH       // No identity -- never enrolled
  REGISTERED  // Has deviceId, no rootKey -- needs bootstrap/pairing
  READY       // Has deviceId + rootKey -- can sync
  STALE       // rootKey exists but keyVersion < server version
  RECOVERY    // Server says trusted but no local rootKey
```

### State Detection on App Launch

```
                       APP LAUNCH
                          |
                          v
               Load SyncIdentity from Keychain
                          |
          +---------------+---------------+
          |               |               |
          v               v               v
      identity        identity.deviceId  identity.deviceId
      is null         exists BUT         AND identity.rootKey
                      rootKey missing    both exist
          |               |               |
          v               v               v
       FRESH           REGISTERED        READY
    (show enable      (call enroll      (verify or
     sync UI)         to continue)      sync directly)
```

### State Transitions

| Current State | Trigger | New State | Action |
|---|---|---|---|
| FRESH | User enables sync | REGISTERED | Call `enroll`, store deviceId |
| REGISTERED | enroll -> BOOTSTRAP | READY | Complete bootstrap, store rootKey |
| REGISTERED | enroll -> PAIR | READY | Complete pairing, store rootKey |
| REGISTERED | enroll -> READY | RECOVERY | Server thinks trusted, no local keys |
| READY | Sync succeeds | READY | No change |
| READY | KEY_VERSION_MISMATCH | STALE | Clear rootKey, re-pair |
| READY | DEVICE_REVOKED | FRESH | Clear identity completely |
| STALE | Re-pair completes | READY | Store new rootKey + keyVersion |
| RECOVERY | User re-pairs | READY | Store rootKey from pairing |
| RECOVERY | User starts fresh | FRESH | Clear identity, re-enroll |

---

## 5. Device Enrollment

### `POST /sync/team/devices`

Registers a device for sync. Idempotent by `device_nonce`.

**Request Body:**

```json
{
  "device_nonce": "019b606a-e90b-76a3-94ef-f719b67faa90",
  "display_name": "Aziz's MacBook Pro",
  "platform": "mac",
  "os_version": "macOS 14.0",
  "app_version": "1.2.3"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `device_nonce` | UUID | Yes | Stored in device Keychain. Uniquely identifies the physical device; does NOT transfer with DB backup/restore. |
| `display_name` | string (1-64) | Yes | User-friendly device name |
| `platform` | string (1-32) | Yes | One of: `ios`, `android`, `mac`, `windows`, `linux`, `web` |
| `os_version` | string (max 64) | No | OS version string |
| `app_version` | string (max 32) | No | App version string |

**Response -- Discriminated Union by `mode`:**

#### Mode: `BOOTSTRAP` (first device, no E2EE yet)

```json
{
  "mode": "BOOTSTRAP",
  "device_id": "019c-...",
  "e2ee_key_version": 0
}
```

Next step: Call `/sync/team/keys/initialize` to generate RK and enable E2EE.

#### Mode: `PAIR` (E2EE enabled, device not trusted)

```json
{
  "mode": "PAIR",
  "device_id": "019c-...",
  "e2ee_key_version": 1,
  "require_sas": true,
  "pairing_ttl_seconds": 300,
  "trusted_devices": [
    {
      "id": "019b-...",
      "name": "Work MacBook",
      "platform": "mac",
      "last_seen_at": "2025-12-01T10:00:00.000Z"
    }
  ]
}
```

Next step: Initiate pairing with one of the trusted devices (see Section 7).

#### Mode: `READY` (already trusted)

```json
{
  "mode": "READY",
  "device_id": "019c-...",
  "e2ee_key_version": 1,
  "trust_state": "trusted"
}
```

Next step: Start syncing immediately (push/pull events).

### Other Device Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/sync/team/devices` | List devices (query `?scope=my` or `?scope=team`) |
| `GET` | `/sync/team/devices/{deviceId}` | Get single device |
| `PATCH` | `/sync/team/devices/{deviceId}` | Update device (body: `{ "display_name": "..." }`) |
| `DELETE` | `/sync/team/devices/{deviceId}` | Delete device |
| `POST` | `/sync/team/devices/{deviceId}/revoke` | Revoke device trust |

### Device Object Schema

```json
{
  "id": "019c-...",
  "user_id": "019b-...",
  "display_name": "Aziz's MacBook Pro",
  "platform": "mac",
  "device_public_key": "<base64 or null>",
  "trust_state": "trusted",
  "trusted_key_version": 1,
  "os_version": "macOS 14.0",
  "app_version": "1.2.3",
  "last_seen_at": "2025-12-01T10:00:00.000Z",
  "created_at": "2025-11-01T08:00:00.000Z"
}
```

`trust_state` values: `"untrusted"`, `"trusted"`, `"revoked"`

---

## 6. E2EE Key Bootstrap

Two-phase operation used by the **first device** to generate the Root Key and enable E2EE.

### Phase 1: `POST /sync/team/keys/initialize`

**Request Body:**

```json
{
  "device_id": "019c-..."
}
```

**Response -- Discriminated Union by `mode`:**

#### Mode: `BOOTSTRAP`

```json
{
  "mode": "BOOTSTRAP",
  "challenge": "<base64>",
  "nonce": "<base64>",
  "key_version": 1
}
```

Client must:
1. Generate RK locally (32-byte random key via CSPRNG)
2. Generate Ed25519 keypair for device
3. Create a device key envelope (RK encrypted with device's public key)
4. Sign the `challenge` with the RK to prove possession
5. Compute `challenge_response` = HMAC(challenge || nonce, root_key)
6. Call Phase 2 commit

**Challenge TTL: 5 minutes.**

#### Mode: `PAIRING_REQUIRED`

```json
{
  "mode": "PAIRING_REQUIRED",
  "e2ee_key_version": 1,
  "require_sas": true,
  "pairing_ttl_seconds": 300,
  "trusted_devices": [
    { "id": "...", "name": "...", "platform": "...", "last_seen_at": "..." }
  ]
}
```

E2EE is already initialized by another device. This device must pair.

#### Mode: `READY`

```json
{
  "mode": "READY",
  "e2ee_key_version": 1
}
```

Device is already trusted at current key version. No action needed.

### Phase 2: `POST /sync/team/keys/initialize/commit`

**Request Body:**

```json
{
  "device_id": "019c-...",
  "key_version": 1,
  "device_key_envelope": "<base64>",
  "signature": "<base64>",
  "challenge_response": "<base64>",
  "recovery_envelope": "<base64>"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `device_id` | UUID | Yes | Must match `X-WF-Device-Id` header |
| `key_version` | int | Yes | Must match `key_version` from Phase 1 |
| `device_key_envelope` | string | Yes | RK encrypted with device's public key (base64) |
| `signature` | string | Yes | Signature over challenge proving RK possession (base64) |
| `challenge_response` | string | No | Response to server challenge (base64) |
| `recovery_envelope` | string | No | Recovery key envelope for account recovery (base64) |

**Response:**

```json
{
  "success": true,
  "key_state": "ACTIVE"
}
```

`key_state`: `"ACTIVE"` (ready to use) or `"PENDING"` (awaiting additional steps).

After a successful commit, E2EE is enabled for the team, and this device is marked as trusted.

---

## 7. Device Pairing

Pairing transfers the Root Key from a trusted device (issuer) to an untrusted device (claimer) using ephemeral X25519 key exchange.

### Session Lifecycle

```
open -> claimed -> approved -> completed
                           \-> cancelled
                           \-> expired
```

### Roles

- **Issuer**: The trusted device that creates the session and sends the RK
- **Claimer**: The untrusted device that enters the code and receives the RK

### Step 1: Issuer creates session

`POST /sync/team/devices/{deviceId}/pairings`

**Request Body:**

```json
{
  "code_hash": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "ephemeral_public_key": "<base64>"
}
```

| Field | Type | Description |
|---|---|---|
| `code_hash` | string (64 chars) | SHA-256 hex hash of the pairing code. The raw code is NEVER sent to the server. |
| `ephemeral_public_key` | string | X25519 ephemeral public key (base64) for Diffie-Hellman key exchange |

**Code normalization before hashing**: `code.toUpperCase().replace(/[^A-Z0-9]/g, "")` -- strip non-alphanumeric, uppercase, then SHA-256 hex.

**Response:**

```json
{
  "pairing_id": "019c-...",
  "expires_at": "2025-12-01T10:05:00.000Z",
  "key_version": 1,
  "require_sas": true
}
```

### Step 2: Claimer claims session

`POST /sync/team/devices/{deviceId}/pairings/claim`

**Request Body:**

```json
{
  "code": "ABCD-1234",
  "ephemeral_public_key": "<base64>"
}
```

| Field | Type | Description |
|---|---|---|
| `code` | string (6-16 chars) | Raw pairing code displayed on issuer. Server normalizes and hashes it for comparison. |
| `ephemeral_public_key` | string | Claimer's X25519 ephemeral public key (base64) |

**Response:**

```json
{
  "session_id": "019c-...",
  "issuer_ephemeral_pub": "<base64>",
  "e2ee_key_version": 1,
  "require_sas": true,
  "expires_at": "2025-12-01T10:05:00.000Z"
}
```

Both sides now have each other's ephemeral public keys and can derive a shared secret via X25519 ECDH.

### Step 3: Issuer polls for claim

`GET /sync/team/devices/{deviceId}/pairings/{pairingId}`

**Response:**

```json
{
  "pairing_id": "019c-...",
  "status": "claimed",
  "claimer_device_id": "019c-bbb...",
  "claimer_ephemeral_pub": "<base64>",
  "expires_at": "2025-12-01T10:05:00.000Z"
}
```

`status` values: `"open"`, `"claimed"`, `"approved"`, `"completed"`, `"cancelled"`, `"expired"`

### Step 4: Issuer approves

`POST /sync/team/devices/{deviceId}/pairings/{pairingId}/approve`

No request body. Response: `{ "success": true }`.

### Step 5: Issuer completes with RK bundle

`POST /sync/team/devices/{deviceId}/pairings/{pairingId}/complete`

**Request Body:**

```json
{
  "encrypted_key_bundle": "<base64>",
  "sas_proof": "<string or object>",
  "signature": "<base64>"
}
```

| Field | Type | Description |
|---|---|---|
| `encrypted_key_bundle` | string | RK bundle encrypted with the shared secret derived from both ephemeral keys (base64) |
| `sas_proof` | string or object | Proof of SAS verification |
| `signature` | string | Signature over the encrypted bundle for authenticity (base64) |

Response: `{ "success": true }`.

Internally, this sends a message with `payloadType: "rk_transfer_v1"` and auto-completes the session.

### Step 6: Claimer polls for messages

`GET /sync/team/devices/{deviceId}/pairings/{pairingId}/messages`

**Response:**

```json
{
  "session_status": "completed",
  "messages": [
    {
      "id": "019c-...",
      "payload_type": "rk_transfer_v1",
      "payload": "<base64 encrypted RK bundle>",
      "created_at": "2025-12-01T10:04:30.000Z"
    }
  ]
}
```

`session_status` values: `"open"`, `"claimed"`, `"approved"`, `"completed"`, `"canceled"`, `"expired"`

Claimer decrypts the RK bundle using the shared secret derived from the ephemeral key exchange.

### Step 7: Claimer confirms and becomes trusted

`POST /sync/team/devices/{deviceId}/pairings/{pairingId}/confirm`

**Request Body:**

```json
{
  "proof": "<optional base64 HMAC>"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `proof` | string | No | HMAC proof that device successfully decrypted the RK bundle: `HMAC(session_id, derived_key)` |

**Response:**

```json
{
  "success": true,
  "key_version": 1
}
```

After this, the claimer device is marked as **trusted** at the current `key_version` and can begin syncing.

### Cancel Session

`POST /sync/team/devices/{deviceId}/pairings/{pairingId}/cancel`

No request body. Response: `{ "success": true }`.

---

## 8. Key Rotation

Key rotation is a two-phase operation triggered when a device is revoked or for periodic security.

### Phase 1: `POST /sync/team/keys/rotate`

**Request Body:**

```json
{
  "initiator_device_id": "019c-..."
}
```

**Response:**

```json
{
  "challenge": "<base64>",
  "nonce": "<base64>",
  "new_key_version": 2
}
```

### Phase 2: `POST /sync/team/keys/rotate/commit`

**Request Body:**

```json
{
  "new_key_version": 2,
  "envelopes": [
    { "device_id": "019c-aaa...", "device_key_envelope": "<base64>" },
    { "device_id": "019c-bbb...", "device_key_envelope": "<base64>" }
  ],
  "signature": "<base64>",
  "challenge_response": "<base64>"
}
```

The `envelopes` array must contain a re-encrypted key envelope for **every** currently trusted device.

**Response:**

```json
{
  "success": true,
  "key_version": 2
}
```

---

# Part II: Event Sync (TODO)

## 9. Event Sync Overview

The event sync system has three operations:

1. **Push**: Send local events from the outbox to the server
2. **Pull**: Fetch remote events and replay them locally
3. **Cursor**: Lightweight check for new events without fetching them

All events are encrypted client-side. The server stores ciphertext and assigns monotonic sequence numbers.

---

## 10. Outbox Write Path

When the user performs a local mutation:

1. **Begin SQLite transaction**
2. Apply the mutation to the local data table (e.g., INSERT into `accounts`)
3. Write a corresponding event to the `outbox` table:
   - Generate `event_id` (UUIDv7 recommended for time-ordering)
   - Set `entity`, `entity_id`, `type` (e.g., `account.create.v1`)
   - Set `client_timestamp` to current wall-clock time (ISO 8601 with timezone offset)
   - Encrypt the payload with the current RK and set `payload` (base64)
   - Set `payload_key_version` to current E2EE key version
   - Set `device_id` to this device's ID
4. **Commit transaction**

This ensures the local state and outbox event are always consistent. If the transaction fails, neither the mutation nor the event is persisted.

### Payload Structure

The payload is the **plaintext** JSON of the entity data, encrypted with the RK. Example for `account.create.v1`:

```json
{
  "id": "019b606a-...",
  "name": "RRSP",
  "account_type": "registered",
  "currency": "CAD",
  "is_active": true,
  "shared_with_household": false
}
```

The client encrypts this to base64 before setting it in the event's `payload` field.

---

## 11. Event Push

### Push Loop

The push loop runs asynchronously, draining the outbox:

1. Query unsent events from `outbox` ordered by creation time (max 500 per batch)
2. Call `POST /sync/events/push`
3. On success:
   - For events in `accepted`: mark as sent (or delete from outbox)
   - For events in `duplicate`: mark as sent (already on server)
   - Store `server_cursor` from response for optimization
4. On failure: retry with exponential backoff

### `POST /sync/events/push`

**Request Body:**

```json
{
  "events": [
    {
      "event_id": "019b606a-e90b-76a3-94ef-f719b67faa90",
      "device_id": "019c-...",
      "type": "account.create.v1",
      "entity": "account",
      "entity_id": "019b606a-e90b-76a3-94ef-f719b67faa92",
      "client_timestamp": "2025-12-01T10:00:00.000Z",
      "payload": "ZW5jcnlwdGVkIGRhdGEgaGVyZQ==",
      "payload_key_version": 1
    }
  ]
}
```

**Per-event fields:**

| Field | Type | Description |
|---|---|---|
| `event_id` | UUID | Client-generated UUIDv7 for idempotency |
| `device_id` | UUID | This device's ID. **Must match `X-WF-Device-Id` header.** |
| `type` | string | Event type matching `{entity}.{operation}.v{version}` |
| `entity` | string | One of the 8 entity types |
| `entity_id` | UUID | ID of the entity being modified |
| `client_timestamp` | ISO 8601 | Client wall-clock time with timezone offset |
| `payload` | string | Encrypted payload (base64). Max 256 KB. |
| `payload_key_version` | int | E2EE key version used for encryption |

**Validation rules (server rejects entire batch if any fails):**

| Rule | Error Code |
|---|---|
| `events.length` must be 1-500 | `SYNC_BATCH_TOO_LARGE` |
| Each `payload` max 256 KB (base64 encoded) | `SYNC_EVENT_TOO_LARGE` |
| Each `device_id` must match `X-WF-Device-Id` header | `SYNC_DEVICE_MISMATCH` |
| Each `payload_key_version` must match team's current version | `SYNC_KEY_VERSION_MISMATCH` |
| `type` must match regex `^[a-z_]+\.(create\|update\|delete\|request)\.v\d+$` | `SYNC_INVALID_EVENT_TYPE` |
| `entity` must be one of the 8 supported types | `SYNC_INVALID_ENTITY` |

**Response (200):**

```json
{
  "accepted": [
    { "event_id": "019b606a-...", "seq": 42 }
  ],
  "duplicate": [
    { "event_id": "019b606b-...", "seq": 41 }
  ],
  "server_cursor": 42
}
```

| Field | Description |
|---|---|
| `accepted` | Events that were newly inserted, each with their assigned `seq` |
| `duplicate` | Events that already existed (idempotent retry), with their existing `seq` |
| `server_cursor` | Current max sequence number after push |

**Idempotency**: Events are deduplicated by `(user_id, event_id)`. Safe to retry on network failure.

**Atomicity**: All events in a batch are inserted in a single database transaction. If any fails validation, the entire batch is rejected.

---

## 12. Event Pull & Replay

### Pull Loop

1. Call `GET /sync/events/pull?since={local_cursor}&limit=500`
2. Check `gc_watermark`: if `local_cursor < gc_watermark`, abort pull and bootstrap from snapshot instead (see Section 15)
3. For each event in `events`:
   a. **Skip own events**: If `device_id` matches this device, skip (already applied locally)
   b. **Decrypt payload**: Use `payload_key_version` to select the correct RK version
   c. **Parse event type**: Extract entity, operation, and version from `type`
   d. **Apply with LWW**: See Section 14 for conflict resolution rules
4. Update `local_cursor` to `next_cursor` from response
5. If `has_more` is `true`, repeat immediately
6. If `has_more` is `false`, pull is caught up

### `GET /sync/events/pull`

**Query Parameters:**

| Param | Type | Default | Description |
|---|---|---|---|
| `since` | int (>= 0) | `0` | Sequence number to start from (exclusive). Use your local cursor. |
| `limit` | int (1-2000) | `500` | Maximum events to return per page |

**Response (200):**

```json
{
  "from": 0,
  "to": 42,
  "next_cursor": 42,
  "has_more": false,
  "events": [
    {
      "event_id": "019b606a-...",
      "device_id": "019c-...",
      "user_id": "019b-...",
      "team_id": "019b-...",
      "type": "account.create.v1",
      "entity": "account",
      "entity_id": "019b606a-...",
      "client_timestamp": "2025-12-01T10:00:00.000Z",
      "server_timestamp": "2025-12-01T10:00:01.000Z",
      "payload": "ZW5jcnlwdGVkIGRhdGEgaGVyZQ==",
      "payload_key_version": 1,
      "seq": 42
    }
  ],
  "gc_watermark": 500,
  "latest_snapshot_seq": 1500
}
```

| Field | Type | Description |
|---|---|---|
| `from` | int | Starting seq (same as `since` param) |
| `to` | int | Max seq in the returned events (0 if empty) |
| `next_cursor` | int | Use as `since` for the next pull call |
| `has_more` | bool | `true` if more events are available beyond this page |
| `events` | array | Events ordered by `seq` ascending (oldest first) |
| `gc_watermark` | int (optional) | Min seq clients should have. If your cursor < this, snapshot bootstrap is recommended. |
| `latest_snapshot_seq` | int (optional) | Seq of the latest snapshot event, for reference |

### StoredSyncEvent Fields

Each event in the `events` array:

| Field | Type | Description |
|---|---|---|
| `event_id` | UUID | Client-generated event ID |
| `device_id` | UUID | Originating device |
| `user_id` | UUID | Originating user |
| `team_id` | UUID | Team the event belongs to |
| `type` | string | Event type (e.g., `account.create.v1`) |
| `entity` | string | Entity type |
| `entity_id` | UUID | Entity being modified |
| `client_timestamp` | ISO 8601 | Client wall-clock time |
| `server_timestamp` | ISO 8601 | Server time when event was recorded |
| `payload` | string | Encrypted payload (base64) |
| `payload_key_version` | int | E2EE key version used for encryption |
| `seq` | int | Server-assigned monotonic sequence number |

---

## 13. Event Cursor

Lightweight endpoint to check if new events exist without fetching them.

### `GET /sync/events/cursor`

No query parameters.

**Response (200):**

```json
{
  "cursor": 42,
  "gc_watermark": 500,
  "latest_snapshot": {
    "snapshot_id": "019c1234-...",
    "schema_version": 1,
    "oplog_seq": 1500
  }
}
```

| Field | Type | Description |
|---|---|---|
| `cursor` | int | Current max visible sequence number |
| `gc_watermark` | int (optional) | GC watermark (see [Appendix B](#b-gc-watermark)) |
| `latest_snapshot` | object or null (optional) | Metadata for the latest available snapshot |
| `latest_snapshot.snapshot_id` | UUID | Snapshot ID for download |
| `latest_snapshot.schema_version` | int | Schema version of the snapshot |
| `latest_snapshot.oplog_seq` | int | Seq number the snapshot covers up to |

**Usage**: Compare `cursor` with your `local_cursor`:
- `cursor > local_cursor` -- new events available, trigger pull
- `cursor == local_cursor` -- up to date
- `local_cursor < gc_watermark` -- stale, bootstrap from snapshot

---

## 14. Conflict Resolution (LWW)

### Rules

When applying a remote event to a local entity that already exists:

1. **Compare `client_timestamp`**: The event with the higher (more recent) timestamp wins.
2. **Tiebreaker**: If timestamps are equal, the event with the lexicographically greater `event_id` wins.
3. **Create vs existing**: If a `create` event arrives for an entity that already exists locally (from a different event), treat it as an update using LWW rules.
4. **Delete events**: A delete event wins over any create/update with an older timestamp.

### Implementation Pseudocode

```
function shouldApplyEvent(localTimestamp, localEventId, remoteTimestamp, remoteEventId):
  if remoteTimestamp > localTimestamp: return true
  if remoteTimestamp == localTimestamp:
    return remoteEventId > localEventId
  return false
```

### Important Notes

- Store both `client_timestamp` and `event_id` for each entity's last mutation in the `entity_metadata` table so you can perform LWW comparison on future conflicts.
- Events from this device are already applied locally -- skip them during replay (check `device_id`).
- All timestamps use ISO 8601 format with timezone offset.

---

# Part III: Snapshot Sync (TODO)

## 15. Snapshot Bootstrap

A snapshot is an encrypted blob (e.g., SQLite dump) stored in R2. New devices use it to bootstrap quickly instead of replaying the full event log.

### When to Bootstrap

1. **First sync on a new device**: No local data exists, and a snapshot is available.
2. **Stale cursor**: `local_cursor < gc_watermark` from cursor/pull response. Events before the watermark may have been garbage-collected.
3. **Explicit request**: No recent snapshot exists, so the device requests one.

### Bootstrap Flow

#### Step 1: Check for available snapshot

`GET /sync/snapshots/latest`

**Response (200):**

```json
{
  "snapshot_id": "019c1234-...",
  "schema_version": 1,
  "covers_tables": ["accounts", "activities", "goals"],
  "oplog_seq": 1500,
  "size_bytes": 234567,
  "checksum": "sha256:a1b2c3d4e5f6...",
  "created_at": "2026-01-19T12:00:00.000Z"
}
```

| Field | Type | Description |
|---|---|---|
| `snapshot_id` | UUID | Use this to download the blob |
| `schema_version` | int | Must be compatible with client's schema version |
| `covers_tables` | string[] | Tables included in the snapshot |
| `oplog_seq` | int | The snapshot covers events up to this seq |
| `size_bytes` | int | Size of encrypted blob in bytes |
| `checksum` | string | `sha256:<hex>` for integrity verification |
| `created_at` | ISO 8601 | When snapshot was created |

**Error 404**: No snapshot available. Option A: fall back to full event replay from `since=0`. Option B: request a snapshot (see Section 17).

#### Step 2: Download snapshot blob

`GET /sync/snapshots/{snapshotId}`

**Response**: Raw binary blob (`application/octet-stream`) with metadata headers:

| Response Header | Description |
|---|---|
| `X-Snapshot-Schema-Version` | Schema version number |
| `X-Snapshot-Covers-Tables` | Comma-separated table list |
| `X-Snapshot-Checksum` | `sha256:<hex>` checksum |
| `Content-Length` | Blob size in bytes |

#### Step 3: Verify and restore

1. Compute SHA-256 of downloaded blob
2. Verify it matches the `X-Snapshot-Checksum` header: `sha256:<hex>`
3. Decrypt the blob using the RK at the appropriate key version
4. Restore decrypted data into local SQLite tables
5. Set `local_cursor = oplog_seq` from the snapshot metadata

#### Step 4: Catch up with incremental pull

After restoring the snapshot, pull events from `since=oplog_seq` to catch up on any events created after the snapshot:

```
GET /sync/events/pull?since={oplog_seq}&limit=500
```

Continue pulling until `has_more = false`.

---

## 16. Snapshot Generation

Trusted devices should generate snapshots periodically or in response to `snapshot.request.v1` events detected during pull.

### When to Generate

- After processing a `snapshot.request.v1` event from the pull stream
- On a periodic schedule (e.g., once per day, or after N events since last snapshot)
- Before the event log grows too large

### Upload Flow

`POST /sync/snapshots/upload`

**Content-Type**: `application/octet-stream` (raw encrypted binary blob in body)

**Required Headers:**

| Header | Type | Required | Description |
|---|---|---|---|
| `X-WF-Device-Id` | UUID | Yes | Device ID |
| `X-Snapshot-Event-Id` | UUID | No | Event ID for idempotent upload. If provided and matches existing, returns 200 instead of re-uploading. |
| `X-Snapshot-Schema-Version` | int | Yes | Schema version of the snapshot data |
| `X-Snapshot-Covers-Tables` | string | Yes | Comma-separated table list (e.g., `accounts,activities,goals`) |
| `X-Snapshot-Size-Bytes` | int | Yes | Expected size of the blob in bytes |
| `X-Snapshot-Checksum` | string | Yes | `sha256:<hex>` checksum of the encrypted blob |
| `X-Snapshot-Metadata-Payload` | string | Yes | Base64-encoded encrypted metadata for the oplog event |
| `X-Snapshot-Payload-Key-Version` | int | Yes | E2EE key version used to encrypt the metadata payload |

**Request Body**: Raw encrypted blob bytes.

**Response (201 -- new upload):**

```json
{
  "snapshot_id": "019c1234-...",
  "r2_key": "snapshots/019b-user.../019c1234-...",
  "oplog_seq": 1500,
  "created_at": "2026-01-19T12:00:00.000Z"
}
```

**Response (200 -- idempotent retry):** Same format, returned when `X-Snapshot-Event-Id` matches an existing upload.

**Client reliability behavior (single-call protocol):**

- Upload remains a single `POST /sync/snapshots/upload` call (no initiate/confirm or presigned URL flow).
- Client computes `X-Snapshot-Size-Bytes` and `X-Snapshot-Checksum` from payload bytes before send.
- For transient failures (`408`, `429`, `5xx`, timeout, connection drop), client retries with exponential backoff + jitter.
- Retries reuse the same `X-Snapshot-Event-Id` for the same upload operation to keep retries idempotent.
- Client deduplicates concurrent in-flight uploads of the same payload for the same device.

**Server-side validation:**

| Rule | Error |
|---|---|
| Blob size must match `X-Snapshot-Size-Bytes` | `SIZE_MISMATCH` |
| SHA-256 must match `X-Snapshot-Checksum` | `SNAPSHOT_CHECKSUM_MISMATCH` |
| Max size: 100 MB | `SNAPSHOT_TOO_LARGE` |
| `X-Snapshot-Payload-Key-Version` must match team's version | `SYNC_KEY_VERSION_MISMATCH` |
| Device must be trusted | `DEVICE_NOT_TRUSTED` |

### Generation Steps

1. Query local SQLite for all sync-managed tables
2. Serialize to a structured format (e.g., JSON, SQLite dump)
3. Encrypt with the current RK
4. Compute SHA-256 checksum of the encrypted blob: `sha256:<hex>`
5. Create encrypted metadata payload (JSON with snapshot details, encrypted with RK)
6. Upload via `POST /sync/snapshots/upload` with all required headers

---

## 17. Snapshot Request

If no snapshot is available and the event log is too large (or the device is new), a device can request that a trusted device generate one.

### `POST /sync/snapshots/request`

**Request Body:**

```json
{
  "payload": "<base64 encrypted request metadata>",
  "payload_key_version": 1,
  "min_schema_version": 1,
  "covers_tables": ["accounts", "activities"]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `payload` | string | Yes | Encrypted request metadata (base64) |
| `payload_key_version` | int | Yes | Must match team's current E2EE key version |
| `min_schema_version` | int | No | Minimum schema version needed |
| `covers_tables` | string[] | No | Tables that must be included |

**Response (202):**

```json
{
  "request_id": "019c5555-...",
  "status": "pending",
  "message": "Snapshot request published to oplog"
}
```

This writes a `snapshot.request.v1` event to the oplog. Trusted devices pulling events will see this and may generate a snapshot. The requesting device should poll `GET /sync/snapshots/latest` periodically after making this request.

---

# Part IV: Client Architecture (TODO)

## 18. Client-Side Data Model

### Required Local Tables

#### `sync_cursor`

Tracks the pull cursor position.

| Column | Type | Description |
|---|---|---|
| `id` | int (PK) | Always 1 (singleton row) |
| `cursor` | int | Last pulled sequence number |
| `updated_at` | datetime | Last update time |

#### `outbox`

Queue of events waiting to be pushed to the server.

| Column | Type | Description |
|---|---|---|
| `event_id` | UUID (PK) | Client-generated UUIDv7 |
| `device_id` | UUID | This device's ID |
| `type` | text | Event type (e.g., `account.create.v1`) |
| `entity` | text | Entity type |
| `entity_id` | UUID | Entity being modified |
| `client_timestamp` | text | ISO 8601 wall-clock time of mutation |
| `payload` | text | Encrypted payload (base64) |
| `payload_key_version` | int | E2EE key version |
| `created_at` | text | When event was queued |
| `sent` | int | 0 = unsent, 1 = sent |

#### `entity_metadata` (for LWW tracking)

| Column | Type | Description |
|---|---|---|
| `entity` | text | Entity type |
| `entity_id` | text (UUID) | Entity ID |
| `last_event_id` | text (UUID) | Event ID of the last applied mutation |
| `last_client_timestamp` | text | ISO 8601 timestamp of the last applied mutation |
| `last_seq` | int | Seq of the last applied mutation |

Composite PK: `(entity, entity_id)`

#### `device_config` (singleton)

| Column | Type | Description |
|---|---|---|
| `device_id` | text (UUID) | This device's ID from enrollment |
| `device_nonce` | text (UUID) | Reference only -- actual value is in Keychain |
| `e2ee_key_version` | int | Current E2EE key version |
| `trust_state` | text | `untrusted`, `trusted`, `revoked` |

---

## 19. Sync Engine Scheduling

### Push Schedule

- **Trigger**: After any local mutation adds an event to the outbox
- **Debounce**: 500ms (batch nearby mutations together)
- **Retry**: Exponential backoff on failure (1s, 2s, 4s, 8s, max 60s)
- **Batch size**: Up to 500 events per push

### Pull Schedule

- **Trigger**: After each successful push (piggyback)
- **Periodic**: Every 30-60 seconds when app is in foreground
- **On app foreground**: Immediate pull
- **Cursor check first**: Call `GET /sync/events/cursor` to avoid unnecessary full pull
- **Background**: No pull when app is in background (or very infrequent)

### Stale Cursor Handling

On each pull or cursor check, compare `local_cursor` with `gc_watermark`:

```
if gc_watermark is present AND local_cursor < gc_watermark:
  -> Trigger snapshot bootstrap (Section 15)
  -> Do NOT attempt incremental pull -- events may have been GC'd
```

**Note**: The server does NOT enforce this -- `gc_watermark` is informational. But if events have been garbage-collected, the incremental pull will have gaps and produce an inconsistent state. Always bootstrap from snapshot when stale.

### Concurrency

- Push and pull should NOT run concurrently to avoid race conditions on the cursor.
- Use a simple mutex/lock per sync operation.
- A single sync engine instance should manage all scheduling.
- The pattern: `push outbox -> pull new events -> update cursor -> schedule next`

---

# Appendices

## A. Error Codes Reference

### Device & Trust Errors

| Code | HTTP | Description | Client Action |
|---|---|---|---|
| `DEVICE_ID_REQUIRED` | 400 | Missing `X-WF-Device-Id` header | Add header to request |
| `DEVICE_NOT_FOUND` | 404 | Device ID not registered | Re-enroll device |
| `DEVICE_REVOKED` | 403 | Device trust has been revoked | Clear identity, show "Enable Sync" UI |
| `DEVICE_NOT_TRUSTED` | 403 | Device exists but is not trusted | Initiate pairing flow |
| `E2EE_NOT_ENABLED` | 403 | E2EE not enabled for team | Bootstrap E2EE (first device flow) |
| `KEY_VERSION_MISMATCH` | 403 | Device trust expired due to key rotation | Clear rootKey, re-pair device |
| `LAST_TRUSTED_DEVICE` | 400 | Cannot revoke the last trusted device | Use resetSync instead |
| `DEVICE_LIMIT_EXCEEDED` | 403 | Plan device limit reached | Upgrade plan or remove a device |

### Pairing Errors

| Code | HTTP | Description | Client Action |
|---|---|---|---|
| `PAIRING_SESSION_NOT_FOUND` | 404 | Session doesn't exist | Start new pairing |
| `PAIRING_SESSION_EXPIRED` | 400 | Session TTL exceeded | Start new pairing |
| `PAIRING_INVALID_CODE` | 400 | Code doesn't match | Re-enter code (check normalization) |
| `PAIRING_MAX_ATTEMPTS` | 429 | Too many failed attempts | Wait and retry later |

### Sync Event Errors

| Code | HTTP | Description | Client Action |
|---|---|---|---|
| `SYNC_BATCH_TOO_LARGE` | 400 | More than 500 events in batch | Split into smaller batches |
| `SYNC_EVENT_TOO_LARGE` | 400 | Single event payload > 256 KB | Reduce payload size |
| `SYNC_DEVICE_MISMATCH` | 400 | Event `device_id` != header | Fix `device_id` in events |
| `SYNC_KEY_VERSION_MISMATCH` | 400 | Key version doesn't match team's | Re-encrypt with current key version |
| `SYNC_INVALID_EVENT_TYPE` | 400 | Type doesn't match required pattern | Fix event type format |
| `SYNC_INVALID_ENTITY` | 400 | Entity type not recognized | Fix entity type |
| `SYNC_TRANSACTION_FAILED` | 500 | Server transaction failed | Retry with backoff |
| `CHALLENGE_INVALID` | 400 | Challenge expired or invalid | Restart the key operation |

### Snapshot Errors

| Code | HTTP | Description | Client Action |
|---|---|---|---|
| `SNAPSHOT_NOT_FOUND` | 404 | Snapshot doesn't exist | Request snapshot generation |
| `SNAPSHOT_TOO_LARGE` | 400 | Snapshot exceeds 100 MB limit | Reduce data size |
| `SNAPSHOT_CHECKSUM_MISMATCH` | 400 | Checksum verification failed | Recompute and re-upload |
| `SNAPSHOT_SCHEMA_INCOMPATIBLE` | 400 | Schema version mismatch | Upgrade client schema |
| `SYNC_CURSOR_TOO_OLD` | 400 | Client cursor behind GC watermark | Bootstrap from snapshot |

### Authentication Errors

| Code | HTTP | Description | Client Action |
|---|---|---|---|
| `AUTH_MISSING_TOKEN` | 401 | No Bearer token provided | Authenticate first |
| `AUTH_INVALID_TOKEN` | 401 | JWT is invalid or expired | Refresh token |
| `AUTH_UNAUTHORIZED` | 401 | Authentication required | Re-authenticate |
| `RATE_LIMITED` | 429 | Too many requests | Wait and retry |

---

## B. GC Watermark

The GC watermark is calculated server-side as:

```
gc_watermark = max(latest_snapshot_seq - 1000, 0)
```

Where:
- `latest_snapshot_seq` is the seq of the most recent `snapshot.create.v1` event
- The safety margin (1000) ensures a buffer of events is preserved after the snapshot
- If no snapshot exists, the watermark is 0 (no GC possible)

The watermark is **informational only** -- the server does not reject pulls with stale cursors. However, events below the watermark may be deleted by garbage collection, so clients with `local_cursor < gc_watermark` should bootstrap from a snapshot to avoid data gaps.

---

## C. Event Encryption

All event payloads are encrypted client-side before being sent to the server:

1. **Encryption**: `payload = base64(encrypt(json_data, RK[key_version]))`
2. **Key version**: Set `payload_key_version` to the current team E2EE key version
3. **Decryption**: On pull, use `payload_key_version` from each event to select the correct RK version for decryption
4. **Key rotation**: After a key rotation, new events use the new key version. Old events remain encrypted with the old key. The client should retain old RK versions to decrypt historical events.

---

## D. Complete API Endpoint Summary

| Method | Path | Description |
|---|---|---|
| **Devices** | | |
| `POST` | `/sync/team/devices` | Enroll device (idempotent by nonce) |
| `GET` | `/sync/team/devices` | List devices (`?scope=my\|team`) |
| `GET` | `/sync/team/devices/{id}` | Get device |
| `PATCH` | `/sync/team/devices/{id}` | Update device |
| `DELETE` | `/sync/team/devices/{id}` | Delete device |
| `POST` | `/sync/team/devices/{id}/revoke` | Revoke device trust |
| **Pairing** | | |
| `POST` | `/sync/team/devices/{id}/pairings` | Create session (issuer) |
| `POST` | `/sync/team/devices/{id}/pairings/claim` | Claim session (claimer) |
| `GET` | `/sync/team/devices/{id}/pairings/{pid}` | Get session status |
| `POST` | `/sync/team/devices/{id}/pairings/{pid}/approve` | Approve (issuer) |
| `POST` | `/sync/team/devices/{id}/pairings/{pid}/complete` | Complete with RK (issuer) |
| `GET` | `/sync/team/devices/{id}/pairings/{pid}/messages` | Poll messages (claimer) |
| `POST` | `/sync/team/devices/{id}/pairings/{pid}/confirm` | Confirm and trust (claimer) |
| `POST` | `/sync/team/devices/{id}/pairings/{pid}/cancel` | Cancel session |
| **Keys** | | |
| `POST` | `/sync/team/keys/initialize` | Phase 1: Get mode/challenge |
| `POST` | `/sync/team/keys/initialize/commit` | Phase 2: Commit bootstrap |
| `POST` | `/sync/team/keys/rotate` | Phase 1: Start rotation |
| `POST` | `/sync/team/keys/rotate/commit` | Phase 2: Commit rotation |
| **Events** | | |
| `POST` | `/sync/events/push` | Push events from outbox |
| `GET` | `/sync/events/pull` | Pull events for replay |
| `GET` | `/sync/events/cursor` | Get current cursor |
| **Snapshots** | | |
| `POST` | `/sync/snapshots/upload` | Upload snapshot blob |
| `GET` | `/sync/snapshots/{id}` | Download snapshot blob |
| `GET` | `/sync/snapshots/latest` | Get latest snapshot metadata |
| `POST` | `/sync/snapshots/request` | Request snapshot generation |

All paths are prefixed with the base URL: `https://api.wealthfolio.app/api/v1`

---

## E. Security Checklist

### Storage
- [ ] `device_nonce` stored in Keychain only (NOT in app database)
- [ ] `root_key` stored in Keychain with highest protection level
- [ ] `device_secret_key` stored in Keychain
- [ ] Keys never logged or included in crash reports

### Cryptography
- [ ] RK is 256-bit cryptographically random
- [ ] X25519 ephemeral keys generated fresh per pairing session
- [ ] Ephemeral private keys cleared from memory after use
- [ ] SAS verification mandatory when `require_sas: true`
- [ ] AES-GCM used for payload encryption and RK transfer

### API
- [ ] `X-WF-Device-Id` header included in all sync API calls
- [ ] Pairing code never sent to server (only hash)
- [ ] Challenge has 5-minute TTL
- [ ] Pairing session expires after TTL

### Memory
- [ ] Sensitive keys zeroed after use
- [ ] Keys loaded into memory only when needed
- [ ] No plaintext keys in logs, crash reports, or analytics

---

## F. Implementation Checklist

### Already Done (App Side)

- [x] Device enrollment (`POST /sync/team/devices`)
- [x] E2EE key bootstrap (initialize + commit)
- [x] Device pairing (full issuer + claimer flow)
- [x] Device management (list, get, update, revoke)
- [x] State machine (FRESH/REGISTERED/READY/STALE/RECOVERY)
- [x] Keychain storage for device_nonce, root_key, device_secret_key

### TODO (App Side)

#### Core Sync Engine
- [ ] Local `outbox` table in SQLite
- [ ] Local `sync_cursor` table in SQLite
- [ ] Local `entity_metadata` table for LWW tracking
- [ ] Outbox write path: mutation + outbox event in same SQLite transaction
- [ ] Push loop with batching (max 500), debounce (500ms), and exponential backoff
- [ ] Pull loop with cursor-based pagination
- [ ] Event decryption using `payload_key_version`
- [ ] Event replay with LWW conflict resolution
- [ ] Skip own-device events during replay
- [ ] Local cursor persistence

#### Sync Scheduling
- [ ] Push on mutation (debounced)
- [ ] Pull after push (piggyback)
- [ ] Periodic pull (30-60s in foreground)
- [ ] Pull on app foreground
- [ ] Cursor check before pull (`GET /sync/events/cursor`)
- [ ] Stale cursor detection (`local_cursor < gc_watermark`)
- [ ] Concurrency control (mutex/lock)

#### Snapshot Bootstrap
- [ ] Check for latest snapshot (`GET /sync/snapshots/latest`)
- [ ] Download snapshot blob (`GET /sync/snapshots/{snapshotId}`)
- [ ] Verify checksum (SHA-256)
- [ ] Decrypt and restore into local SQLite
- [ ] Set local cursor from snapshot's `oplog_seq`
- [ ] Incremental catch-up pull after restore

#### Snapshot Generation (Trusted Devices)
- [ ] Detect `snapshot.request.v1` events during pull
- [ ] Serialize local data tables
- [ ] Encrypt with current RK
- [ ] Compute checksum
- [ ] Upload via `POST /sync/snapshots/upload`
- [ ] Periodic snapshot generation schedule

#### Snapshot Request (New Devices)
- [ ] Request snapshot generation (`POST /sync/snapshots/request`)
- [ ] Poll for snapshot availability after requesting

#### Error Handling
- [ ] Handle `SYNC_KEY_VERSION_MISMATCH` (re-encrypt and retry)
- [ ] Handle `DEVICE_REVOKED` (clear identity, stop sync)
- [ ] Handle `KEY_VERSION_MISMATCH` (clear rootKey, re-pair)
- [ ] Handle `SYNC_CURSOR_TOO_OLD` (trigger snapshot bootstrap)
- [ ] Handle `SYNC_TRANSACTION_FAILED` (retry with backoff)
- [ ] Handle 401 (token refresh)
- [ ] Handle network errors (retry with backoff)
