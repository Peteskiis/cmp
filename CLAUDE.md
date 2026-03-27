# CLAUDE.md - Project Instructions for Claude Code

## Project Overview

CMP is an end-to-end encrypted messaging service built in Rust. Uses Signal Protocol (X3DH key agreement + Double Ratchet) for true E2EE. The server is a dumb relay that never sees plaintext.

**Crate structure:**
- `protocol` — shared wire types (serde JSON), no business logic
- `crypto` — Signal Protocol implementation from primitives (pure, no I/O, WASM-portable, `#![deny(unsafe_code)]`)
- `server` — axum WebSocket relay + store-and-forward queue
- `client` — ratatui inline TUI (Codex-style chat, CCP `db connect` pattern)

## Development Workflow

1. Make changes
2. `make check` (runs fmt-check + lint + test)

Or individually:
1. `make fmt` — format code
2. `make lint` — clippy (strict)
3. `make test` — run all tests

## Commands Reference

```sh
make               # Show help
make check         # fmt-check + lint + test (CI-safe, no auto-fix)
make fmt           # Format all code (modifies files)
make fmt-check     # Verify formatting (no changes)
make lint          # Run clippy (strict)
make lint-fix      # Auto-fix clippy warnings
make test          # Run all tests

cargo run -p server                # Run server
cargo run -p client -- --user alice --server ws://127.0.0.1:3000/ws  # Run client
```

## Code Style & Conventions

- Strict clippy: pedantic + nursery enabled, `unwrap_used` and `expect_used` are **denied**
- Use `?` operator for error propagation, never `unwrap()` or `expect()`
- `expect()`/`unwrap()` are automatically allowed in `#[cfg(test)]` via `clippy.toml` — no manual `#[allow]` needed
- Keep functions small and focused (max 100 lines, cognitive complexity < 10)
- Handle errors explicitly via `Result` and `thiserror`/`anyhow`
- All public enums must be `#[non_exhaustive]` for forward compatibility
- Use `#[serde(try_from = "...")]` on validated newtypes to enforce invariants at the deserialization boundary
- `cast_possible_truncation` and `cast_sign_loss` are warnings — use targeted `#[allow(...)]` with a safety comment, never silence globally
- Protocol size limits are defined in `protocol::consts` — server must enforce them

## Crypto Rules

- `#![deny(unsafe_code)]` on the crypto crate
- All secret key types must derive `Zeroize` + `ZeroizeOnDrop` (use newtype wrappers where upstream types lack it)
- Never log or print secret key material
- AES-GCM nonces are derived deterministically from message keys via HKDF — never random
- The `crypto` crate must stay pure: no I/O, no async, no `SystemTime`, no platform deps (for WASM/FFI portability)
- Storage traits in `crypto` are trait-only; concrete impls live in `client`
- **Never mutate session state before AEAD authentication succeeds** — snapshot state, attempt decrypt, roll back on failure. A forged message must not corrupt the session.
- Use `u64` arithmetic for overflow-sensitive checks (e.g., skipped key limits) — `u32` addition can wrap in release mode, bypassing guards
- Counter increments (`send_count`, `recv_count`) must use checked arithmetic or explicit bounds checks before incrementing

## Architecture Rules

- `protocol` and `crypto` crates must stay platform-agnostic (no TUI, no async runtime in core API)
- Server never depends on `crypto` — it only routes opaque encrypted blobs
- Client TUI uses `ratatui::Viewport::Inline` with `insert_before()` — NOT full-screen alternate screen
- Terminal is exclusively owned by the UI task; network task communicates via `mpsc` channels
- `UserId` is ASCII-only to prevent Unicode normalization attacks

## Server Rules

- Registration must be **atomic** (single SQLite transaction for user + SPK + OPKs) — partial failure must not leave a user in the DB without keys
- **Validate identity keys** as real Ed25519 (`VerifyingKey::from_bytes`) before storing — garbage keys permanently brick usernames under TOFU
- **Verify SPK signatures** at registration time (defense-in-depth) — prevents garbage bundles that break X3DH for other users
- Already-authenticated connections must not be allowed to re-register — prevents username squatting
- Ack operations must be **scoped to the authenticated user** (`AND recipient_id = ?`) — otherwise any user can delete anyone's queued messages
- Connection removal must use **conditional removal** (`remove_if_match` with conn_id) — prevents a closing old connection from evicting a newer one
- Use **bounded channels** for WebSocket connections (`mpsc::channel(N)` + `try_send`) — unbounded channels allow slow/malicious clients to exhaust server memory
- `QueuedMessages` must be delivered **after** `AuthSuccess` is on the wire — clients need auth confirmation before processing messages
- **Auth guards must cover all auth-related messages** — if Register blocks re-auth, so must AuthChallenge and AuthResponse. Apply guards at the router level, not scattered across handlers.
- **Validate all cryptographic key lengths at the server boundary** — Ed25519 keys (32 bytes), X25519 keys (32 bytes), signatures (64 bytes). Invalid lengths brick bundles for other users.
- **Never send internal error details to clients** — log with `tracing::error!`, return generic "internal server error" to the wire. Rust/SQLite error strings leak schema details.

## Reference Implementations

- CCP `db connect` inline TUI pattern: `~/Developer/projects/cluster/infra/crates/cli/src/commands/db/connect.rs`
- Codex TUI message styling: `~/Developer/research/codex/codex-rs/tui/src/history_cell.rs`
- Codex adaptive background: `~/Developer/research/codex/codex-rs/tui/src/style.rs`

## Things Claude Should NOT Do

- Don't use `unwrap()` or `expect()` — they are clippy-denied (except in `#[cfg(test)]` with `#[allow]`)
- Don't add async, I/O, or `unsafe` to the `crypto` crate
- Don't skip error handling
- Don't commit without running `make check` first
- Don't make breaking protocol changes without discussion
- Don't use full-screen alternate screen for the TUI
- Don't add `Serialize`/`Deserialize` to error types unless they're sent over the wire
- Don't accept unbounded user input without checking `protocol::consts` limits
- Don't allow `cast_possible_truncation` or `cast_sign_loss` without a targeted `#[allow]` + safety comment

## Self-Improvement

After every correction or mistake, update this CLAUDE.md with a rule to prevent repeating it.
