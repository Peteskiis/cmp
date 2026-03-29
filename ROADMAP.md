# CMP Roadmap

Encrypted messaging service — milestone 1: 1:1 E2EE chat.

---

## Phase 1: Workspace Scaffolding

- [x] Convert root `Cargo.toml` to workspace manifest
- [x] Add `[workspace.dependencies]` with pinned versions for all shared deps
- [x] Add `[workspace.lints.clippy]` with full pedantic + nursery + deny rules
- [x] Create `clippy.toml` (cognitive-complexity=10, too-many-lines=100, too-many-arguments=7)
- [x] Create `crates/protocol/` skeleton (Cargo.toml + `src/lib.rs`)
- [x] Create `crates/crypto/` skeleton (Cargo.toml + `src/lib.rs`)
- [x] Create `crates/server/` skeleton (Cargo.toml + `src/main.rs`)
- [x] Create `crates/client/` skeleton (Cargo.toml + `src/main.rs`)
- [x] Each crate has `[lints] workspace = true`
- [x] Remove old `src/main.rs`
- [x] Create `ROADMAP.md` (this file)
- [x] Update `CLAUDE.md` for Rust project (cargo commands, Rust conventions, crypto rules)
- [x] `cargo check --workspace` passes
- [x] `cargo clippy --workspace -- -D warnings` passes
- [x] `cargo fmt --all -- --check` passes

---

## Phase 2: Protocol Crate (`protocol`)

### Wire types
- [x] `UserId` newtype (ASCII-only, validated via `#[serde(try_from)]`)
- [x] `MessageId` newtype (UUID v4 wrapper, no `Default`)
- [x] `EncryptedEnvelope` struct (version, `MessageHeader`, ciphertext)
- [x] `MessageHeader` enum (`PreKey` with X3DH material, `Ratchet` with DH header)
- [x] `RatchetHeader` struct (ratchet_key, previous_chain_length, message_number)
- [x] `PreKeyBundle` struct (identity_key, signed_prekey, one_time_prekey, signatures)
- [x] `OneTimePreKey` struct (shared between bundle and upload)
- [x] `InboundMessage` struct (shared between live and queued delivery)
- [x] `consts` module (MAX_PREKEYS_PER_UPLOAD, MAX_ACK_BATCH, MAX_QUEUED_MESSAGES, MAX_CIPHERTEXT_BYTES)

### Client -> Server messages (`ClientMessage` enum, `#[non_exhaustive]`)
- [x] `Register { user_id, bundle, one_time_prekeys }`
- [x] `AuthChallenge { user_id }`
- [x] `AuthResponse { signature }` (base64 Ed25519)
- [x] `UploadPreKeys { prekeys }`
- [x] `FetchPreKeyBundle { target_user_id }`
- [x] `SendMessage { recipient_id, message_id, envelope }`
- [x] `Ack { message_ids }`

### Server -> Client messages (`ServerMessage` enum, `#[non_exhaustive]`)
- [x] `Challenge { nonce, timestamp, server_id }` (timestamp = seconds since epoch)
- [x] `AuthSuccess`
- [x] `AuthFailure { reason }`
- [x] `PreKeyBundleResponse { user_id, bundle }`
- [x] `IncomingMessage(InboundMessage)`
- [x] `QueuedMessages { messages }`
- [x] `MessageSent { message_id }`
- [x] `PreKeyLow { remaining }`
- [x] `Error { code, message }`

### Error types
- [x] `ProtocolError` enum (`#[non_exhaustive]`, no serde — internal only)
- [x] Includes `UnsupportedVersion { got, max_supported }`

### Hardening (from code reviews)
- [x] `#[non_exhaustive]` on all public enums
- [x] `#[serde(try_from = "String")]` on `UserId` — validation at deserialization boundary
- [x] UserId rejects empty, whitespace-only, non-ASCII, control chars, >128 bytes
- [x] `#![deny(unsafe_code)]` on crypto crate
- [x] `.gitignore` covers `*.db`, `.env*`, `*.pem`, `*.key`
- [x] `cast_possible_truncation` / `cast_sign_loss` promoted to warn (not silently allowed)
- [x] `make check` uses `fmt-check` (no auto-fix in CI)
- [x] Collection size limits documented via `consts` module

### Tests
- [x] Serde round-trip test for every `ClientMessage` variant
- [x] Serde round-trip test for every `ServerMessage` variant
- [x] Serde round-trip test for both `EncryptedEnvelope` header types (PreKey + Ratchet)
- [x] Unknown fields are ignored (forward compatibility)
- [x] Unknown enum variants are rejected
- [x] UserId validation: empty, whitespace, control chars, non-ASCII, oversized, valid
- [x] UserId deserialization enforces validation
- [x] `make check` passes (28 tests)
- [x] `cargo clippy -p protocol -- -D warnings` passes

---

## Phase 3: Crypto Crate (`crypto`)

### Key types (`keys.rs`)
- [x] `IdentityKeyPair` (Ed25519 `SigningKey` + `VerifyingKey`)
- [x] `SignedPreKey` (X25519 keypair + signature + key_id)
- [x] `OneTimePreKey` (X25519 keypair + key_id)
- [x] `EphemeralKey` (X25519 keypair, zeroized after use)
- [x] `ZeroizingStaticSecret` newtype wrapper (manual `ZeroizeOnDrop` for `StaticSecret`)
- [x] Ed25519 <-> X25519 conversion helpers (`to_montgomery()`, `to_scalar_bytes()`)
- [x] Key generation functions (all using `OsRng`)
- [x] Tests: key generation, conversion round-trips

### KDF functions (`kdf.rs`)
- [x] `kdf_rk(root_key, dh_output) -> (new_root_key, chain_key)` — HKDF with `info=b"CMP_RATCHET"`
- [x] `kdf_ck(chain_key) -> (new_chain_key, message_key)` — HMAC with 0x01 / 0x02
- [x] `derive_message_keys(message_key) -> (aes_key, nonce)` — HKDF with `info=b"CMP_MsgKey"`, 44 bytes output
- [x] Tests: known-answer tests with hardcoded inputs/outputs

### AEAD (`aead.rs`)
- [x] `encrypt(message_key, plaintext, aad) -> ciphertext` — AES-256-GCM with deterministic nonce from HKDF
- [x] `decrypt(message_key, ciphertext, aad) -> plaintext`
- [x] Tests: encrypt/decrypt round-trip, tampered ciphertext fails, tampered AAD fails

### X3DH (`x3dh.rs`)
- [x] `alice_initiate(ik_a, bundle_b) -> (shared_secret, x3dh_header)` — handles 3 and 4 DH cases
- [x] `bob_respond(ik_b, spk_b, opk_b, x3dh_header) -> shared_secret`
- [x] PreKey bundle signature verification (Ed25519 over SPK public key)
- [x] Exact byte-level IKM construction: `0xFF*32 || DH1 || DH2 || DH3 [|| DH4]`
- [x] HKDF with `salt=0x00*32`, `info=b"CMP_X3DH"`, output 32 bytes
- [x] Tests: Alice and Bob derive same shared secret (with OPK)
- [x] Tests: Alice and Bob derive same shared secret (without OPK)
- [x] Tests: invalid SPK signature is rejected

### Double Ratchet (`ratchet.rs`)
- [x] `SessionState` struct (root_key, chains, ratchet keys, counters)
- [x] `SessionState` derives `Serialize`/`Deserialize` for persistence
- [x] `initialize_alice(shared_secret, bob_ratchet_pubkey) -> SessionState`
- [x] `initialize_bob(shared_secret, bob_ratchet_keypair) -> SessionState`
- [x] `encrypt(state, plaintext) -> (header, ciphertext)` — symmetric ratchet step
- [x] `decrypt(state, header, ciphertext) -> plaintext` — handles DH ratchet step if new key
- [x] Out-of-order message handling (skip and store message keys)
- [x] Skipped key limit (1000 per session)
- [ ] Skipped key TTL (caller passes current timestamp — not yet implemented)
- [x] `RatchetHeader` struct (ratchet_public_key, previous_chain_length, message_number) — used as AAD
- [x] Tests: multi-message exchange (Alice sends 3, Bob replies 2, Alice sends 1)
- [x] Tests: out-of-order delivery (deliver messages 3, 1, 2 — all decrypt)
- [x] Tests: skipped key limit exceeded returns error
- [x] Tests: session state serialize/deserialize round-trip

### Storage traits (`store.rs`)
- [x] `trait SessionStore` (load_session, store_session)
- [x] `trait PreKeyStore` (load_prekey, remove_prekey)
- [x] `trait SignedPreKeyStore` (load_signed_prekey)
- [x] `trait IdentityKeyStore` (get_identity)
- [x] All traits are **sync** (no async, no platform deps)

### Crate-level
- [ ] `CryptoManager` — high-level API composing X3DH + Double Ratchet + store traits
- [x] `cargo test -p crypto` passes (38 tests)
- [x] `cargo clippy -p crypto -- -D warnings` passes

---

## Phase 4: Server (`server`)

### Database (`db/`)
- [x] SQLite schema: `users` table
- [x] SQLite schema: `signed_prekeys` table
- [x] SQLite schema: `prekeys` table (one-time, atomic `DELETE RETURNING` on fetch)
- [x] SQLite schema: `message_queue` table with indexes on `(recipient_id, created_at)` and `created_at`
- [x] Schema versioning via `PRAGMA user_version`
- [x] `PRAGMA foreign_keys = ON` and `journal_mode = WAL`
- [x] `db/users.rs` — `register_atomic` (single transaction), lookup, exists
- [x] `db/prekeys.rs` — upload prekeys, fetch+delete bundle atomically, count remaining
- [x] `db/queue.rs` — enqueue (dedup on `message_id`), get pending (with LIMIT), delete scoped to recipient

### Core server state
- [x] `AppState` struct (db connection, connection registry, server_id)
- [x] `ConnectionRegistry` using `DashMap` with conn_id for safe replacement
- [x] `remove_if_match(conn_id)` — prevents old connection from evicting new one
- [x] Displaced connection notified with 409 error before replacement

### WebSocket handler (`ws.rs`)
- [x] axum router with WebSocket upgrade at `GET /ws`
- [x] Per-connection tokio task (split into SplitStream + SplitSink)
- [x] Bounded `mpsc::channel(256)` per connection with `try_send` backpressure
- [x] Connection cleanup on disconnect (conditional `remove_if_match`)
- [x] `max_frame_size` / `max_message_size` set (512KB + 16KB headroom)
- [ ] WebSocket ping/pong keepalive (deferred — operational concern)

### Auth handlers (`handlers/auth.rs`)
- [x] `Register` — atomic TOFU with identity key validation (`VerifyingKey::from_bytes`) and SPK signature verification
- [x] Rejects re-registration of existing users (must use challenge-response)
- [x] Rejects registration from already-authenticated connections
- [x] `AuthChallenge` — generate 32-byte nonce + timestamp, store transiently
- [x] `AuthResponse` — verify Ed25519 signature over `nonce || timestamp || server_id`, time-limited (60s)
- [x] Mark connection as authenticated with conn_id in registry
- [x] `QueuedMessages` delivered after `AuthSuccess` is on the wire

### PreKey handlers (`handlers/prekey.rs`)
- [x] `FetchPreKeyBundle` — return identity key + signed prekey + one OPK (atomically deleted)
- [x] `UploadPreKeys` — store new one-time prekeys (rejects invalid base64 batches)
- [x] `PreKeyLow` alert — send when count drops below threshold (10)
- [x] `MAX_PREKEYS_PER_UPLOAD` enforced on both register and upload

### Message handlers (`handlers/message.rs`)
- [x] `SendMessage` — verify recipient exists (404), enforce `MAX_CIPHERTEXT_BYTES`, store in queue, push if online
- [x] `QueuedMessages` — deliver pending on connect (limited by `MAX_QUEUED_MESSAGES`)
- [x] `Ack` — delete scoped to authenticated user (`AND recipient_id = ?`), enforce `MAX_ACK_BATCH`
- [x] Malformed queued messages logged with `warn!` (not silently dropped)

### Background tasks
- [x] Message queue GC (hourly, delete messages older than 30 days)
- [ ] Rate limiting on prekey bundle requests and message sending (deferred)

### Server entry point
- [x] `main.rs` — env-based config (bind address, db path, server_id), init DB, start axum server
- [x] Graceful shutdown on SIGINT/SIGTERM

### Hardening (from code reviews)
- [x] Atomic registration — partial failure cannot brick a user
- [x] Identity key validated as Ed25519 before storage
- [x] SPK signature verified at registration (defense-in-depth)
- [x] Bounded WebSocket channels with backpressure
- [x] Connection replacement race prevented via conn_id matching
- [x] Ack authorization scoped to authenticated user
- [x] All `protocol::consts` limits enforced
- [x] Recipient existence checked before enqueue (404 vs FK 500)
- [x] Silent error paths replaced with `warn!` logging

### Tests
- [x] Integration test: full auth flow (register -> challenge -> response -> authenticated)
- [x] Integration test: prekey upload and fetch (including OPK exhaustion)
- [ ] Integration test: prekey fetch race condition (concurrent requests get different OPKs)
- [x] Integration test: store-and-forward (send while offline, connect, receive, ack, verify deleted)
- [ ] Integration test: message deduplication (same message_id sent twice)
- [x] `cargo clippy -p server -- -D warnings` passes

### Deferred (not M1 blockers)
- [ ] `handle_upload` returns wrong response type — needs `ServerMessage::PreKeysUploaded` variant
- [ ] Timestamps always 0 — needs `QueuedRow.created_at` propagation
- [ ] Self-fetch drains own prekeys
- [ ] Total prekey cap per user
- [ ] WebSocket ping/pong keepalive
- [ ] Prekey bundle fetch rate limiting
- [x] User existence oracle — all 404s use generic "not found"

---

## Phase 5: Client (`client`)

### CLI entry point (`main.rs`)
- [x] clap CLI: `--user <name>`, `--server <ws://url>`
- [x] Data directory: `~/.cmp/<user_id>/`

### Network layer (`net.rs`)
- [x] WebSocket client connection (tokio-tungstenite with rustls)
- [x] Reconnect with exponential backoff (1s → 30s cap, resets only after auth succeeds)
- [x] Send `ClientMessage` to server via channel
- [x] Receive `ServerMessage` from server, forward to UI via `AppEvent` channel
- [x] Challenge-response authentication (Ed25519 signature)
- [x] `AuthFailed` event for clear UX on persistent auth failure
- [x] Unparseable server messages logged with `warn!` (not silently dropped)

### Crypto integration (`crypto_mgr.rs`)
- [x] `CryptoManager` — manages identity, sessions, encrypt/decrypt
- [x] Persistent identity key (`~/.cmp/<user_id>/identity.key`, 0o600 permissions)
- [x] Registration flow: generate identity key, signed prekey, 100 OPKs
- [x] X3DH session init: `/chat <user>` → `FetchPreKeyBundle` → `init_session_from_bundle`
- [x] Alice sends `PreKey` header on first message (ephemeral key + SPK/OPK IDs)
- [x] Bob handles `PreKey` messages via `init_session_from_prekey` + `bob_respond`
- [x] Send: encrypt with Double Ratchet → `EncryptedEnvelope`
- [x] Receive: decrypt `EncryptedEnvelope` → display text
- [x] Only ack messages that successfully decrypt (failed messages re-delivered)
- [x] Plaintext size checked before encrypting (prevents ratchet desync)
- [x] OPK decode failures return error (no silent 3-DH degradation)
- [x] No plaintext fallback — decrypt failure shows `[undecryptable message]`
- [x] `decrypt_to_text` returns `(text, ok)` for conditional ack
- [x] `b64_decode_fixed::<N>()` helper with parameterized error variant
- [x] Concurrent session inits via `HashSet<String>` (not single pending)
- [x] Session persistence to disk (`~/.cmp/<user_id>/sessions/<peer_id>.json`)
- [x] SPK/OPK private key persistence (Bob can decrypt first messages after restart)
- [x] Prekey headers persistence (`prekey_headers.json`)
- [x] `needs_registration()` guard (checks SPK presence, not first-launch)
- [x] Bob-side X3DH tests (5 tests: happy path, forged PreKey, existing session, missing OPK, persistence)

### Inline TUI (`ui.rs` + `app.rs`)
- [x] `Viewport::Inline(INPUT_HEIGHT)` terminal setup (not full-screen)
- [x] Raw mode with RAII `Drop` guard + panic hook (restores cursor style too)
- [x] Input widget: dark bg `rgb(40,44,52)`, teal prompt `rgb(34,199,168)`, blinking cursor
- [x] Placeholder text when input is empty
- [x] Message rendering via `terminal.insert_before()`:
  - [x] Your messages: `"› "` bold+dim prefix, dark background
  - [x] Friend messages: `"• sender: "` dim prefix, plain background
  - [x] Line wrapping with per-message-type prefix width
- [x] Footer with keyboard hints
- [x] Horizontal input scrolling for long messages
- [x] Ctrl+modifier filtering (only printable chars inserted)
- [ ] Adaptive background color (query terminal bg via crossterm)
- [ ] Input history (up/down arrow)

### App event loop (`app.rs`)
- [x] `AppEvent` enum (Key, ServerMessage, Connected, Disconnected, AuthFailed)
- [x] `App` struct owns `Terminal` exclusively
- [x] `tokio::select!` loop: poll crossterm `EventStream` + network event channel
- [x] Enter to send message (encrypt + send + insert_before for local echo)
- [x] Display incoming messages (decrypt + insert_before)
- [x] Connection status display
- [x] Ctrl+D / Ctrl+C to quit (with raw mode cleanup)
- [x] `/chat <username>` command with UserId validation
- [x] `/quit` and `/q` command
- [x] `/contacts` and `/c` command (shows session peers with active marker)
- [x] `/help` and `/h` command
- [x] Typing indicators: debounced send (3s), peer display with auto-expire (5s)
- [x] Delivery status display: ✓ sent (`MessageSent`), ✓✓ delivered (`MessageDelivered`)
- [x] E2EE read receipts: encrypt message IDs via Double Ratchet, send on read, decrypt+display 👁

### Tests
- [x] `wrap_message` unit tests (7 tests: empty, short, long, overflow, zero width)
- [ ] Crypto store trait SQLite implementation tests
- [ ] Network handler tests with mock WebSocket
- [x] `cargo test -p client` passes (12 tests)
- [x] `cargo clippy -p client -- -D warnings` passes

### Hardening (from code reviews)
- [x] Identity key file permissions 0o600 on Unix
- [x] No unauthenticated content displayed as message text
- [x] Plaintext size check before encrypt (prevents ratchet desync)
- [x] OPK decode failures are errors, not silent degradation
- [x] Only ack successfully decrypted messages
- [x] `CryptoError` uses `thiserror::Error` + `#[non_exhaustive]`
- [x] Backoff only resets after successful authentication
- [x] Auth challenge failure sends `AuthFailed`, not `Disconnected`

### Deferred (not M1 blockers)
- [ ] SQLCipher-encrypted local database
- [x] Message history persistence (SQLite, `/chat` reloads last 100 messages)
- [ ] Adaptive terminal background color detection

---

## Phase 6: End-to-End Integration

- [x] Integration test: start server on random port
- [x] Integration test: two programmatic clients (no TUI) register
- [x] Integration test: Alice fetches Bob's prekey bundle
- [x] Integration test: Alice sends encrypted message, Bob receives and decrypts
- [x] Integration test: Bob replies, Alice receives and decrypts
- [x] Integration test: offline delivery (send while offline, connect, receive, ack)
- [x] Integration test: ack removes from queue (no re-delivery)
- [x] Integration test: send to nonexistent user fails
- [x] Integration test: unauthenticated send rejected
- [x] Integration test: auth with wrong key rejected
- [x] Integration test: typing indicator relay
- [x] Integration test: server-generated delivery receipt on push
- [x] Integration test: read receipt relay
- [x] Manual test: run server + two TUI clients in separate terminals
- [x] Full workspace verification:
  - [x] `cargo check --workspace`
  - [x] `cargo test --workspace` (129 tests)
  - [x] `cargo clippy --workspace -- -D warnings`
  - [x] `cargo fmt --all -- --check`

---

## Future Milestones (not in scope for M1)

- [ ] Group chat / channels (Sender Keys protocol)
- [ ] Web client (`clients/web/` — WASM crypto, React/TS frontend)
- [ ] Mobile clients (`clients/mobile/` — uniffi bindings for Swift/Kotlin)
- [ ] File/image sharing (encrypted upload with symmetric key in message)
- [x] Typing indicators (debounced, ephemeral relay, no queueing)
- [x] Delivery receipts (server-generated on successful push)
- [x] Read receipts (E2EE encrypted inside envelope, server can't see who read what)
- [x] Safety number verification (`/verify`, `/verify confirm`, identity key change warnings)
- [ ] Session reset UI
- [x] TLS (wss://) for production server (rustls + ring)
- [ ] Phone number auth (Signal/WhatsApp style OTP — SMS provider, phone-as-identity, server-side verification)
