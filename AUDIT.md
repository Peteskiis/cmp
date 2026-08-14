# CMP Open-Source Release Readiness Audit

**Audit date:** 2026-08-12

**Audited revision:** `3c1915b` (`main`)

**Scope:** repository hygiene, protocol and cryptographic boundaries, client and
server correctness, automated testing, dependency health, packaging, and
open-source release readiness.

**Remediation status updated:** 2026-08-14. The findings and command output
below preserve the original audit evidence; the status summary records the
current implementation after PRs #2 through #4 and subsequent remediation.

## Executive summary

CMP has a solid foundation, but it is not ready for a stable,
security-sensitive release. The code demonstrates good defensive practices:
strict linting, atomic server registration, authenticated-ratchet rollback,
recipient-scoped acknowledgements, restricted key-file permissions, and broad
unit coverage. The most important remaining risks sit at real-world failure
boundaries: durable ratchet state, lost acknowledgements, large queued
deliveries, and one-time-prekey lifecycle management.

The recommended first public release is `0.1.0-alpha.1`, clearly marked as
experimental and unaudited. CMP should not be described as production-secure
until the P1 issues below are fixed and the protocol and implementation receive
independent cryptographic review.

## Remediation status

- **All five P1 findings are resolved.** Ratchet transitions and every
  ratchet-advancing outbound item are durable, duplicate delivery is
  re-acknowledged through a correlated outbox, queued delivery is paged by
  bytes and count, one-time and signed prekeys have bounded lifecycles, and the
  canonical local gate is green with an enforced dependency policy.
- **Protocol version enforcement and authentication are resolved.** Version 2
  is defined in `protocol::consts`; the server rejects other
  versions on every encrypted relay path; the client rejects them before
  duplicate handling or crypto-state mutation; and AEAD associated data binds
  the version, envelope type, X3DH header fields, and Double Ratchet header.
- **Connection replacement remains open.** The displaced connection is
  notified but its authenticated read loop is not cancelled immediately.
- **Public-release material remains open.** The repository still needs the
  policy, threat-model, contributor, packaging, and release documentation
  listed below, followed by a full Git-history secret scan.

## Findings

### P1 — Ratchet persistence can cause key and nonce reuse after a crash — Resolved

Encryption advances the in-memory ratchet before its updated state is persisted
(`crates/client/src/crypto_mgr.rs:234-275`). Session persistence returns no
error to the caller and only logs write failures
(`crates/client/src/crypto_mgr.rs:469-485`). The file writer truncates the
existing file in place before writing the replacement
(`crates/client/src/crypto_mgr.rs:623-641`).

If persistence fails or the process crashes during the write, a restart can
load the pre-encryption ratchet state. Sending another message from that state
can reuse an AES-GCM message key and its deterministically derived nonce. It can
also desynchronize the peers permanently.

Required work:

- Make session persistence atomic by writing and syncing a same-directory
  temporary file, renaming it over the destination, and syncing the directory
  where supported.
- Propagate persistence errors through encryption and decryption operations.
- Do not release ciphertext to the network unless the corresponding next
  ratchet state is durably committed.
- Add disk-full, partial-write, and crash/restart fault-injection tests.

### P1 — Lost acknowledgements create permanently undecryptable queued messages — Resolved

The network loop removes an outbound item from the channel before its WebSocket
write succeeds (`crates/client/src/net.rs:122-127`). A disconnect can therefore
lose an acknowledgement. The server retains and redelivers the message, but the
client's ratchet correctly rejects the ciphertext as a replay. The client only
acknowledges messages that decrypt successfully
(`crates/client/src/app.rs:577-619`), so the redelivered item becomes stuck until
server garbage collection and can be displayed as undecryptable on every
reconnect.

The same lossy path affects encrypted messages and read receipts after their
ratchet state has advanced.

Required work:

- Persist successfully received message IDs before acknowledging them.
- Re-acknowledge already-persisted message IDs without decrypting their
  ciphertext again.
- Add a durable outbound queue or transactional outbox for messages,
  acknowledgements, and read receipts.
- Bound the client channels and surface backpressure instead of silently
  discarding send failures.
- Test disconnects before, during, and after WebSocket writes and ACK delivery.

### P1 — Queued delivery can allocate and transmit roughly 500 MiB at once — Resolved

The protocol permits 1,000 queued messages in one response and approximately
512 KiB of base64 ciphertext per message
(`crates/protocol/src/consts.rs:7-15`). Authentication gathers the entire batch
into one `QueuedMessages` value and sends it as a single WebSocket message
(`crates/server/src/handlers/auth.rs:205-280`).

At the limits, this is roughly 500 MiB before accounting for JSON, temporary
copies, and object overhead. It can exhaust server or client memory and exceed
WebSocket client message limits, leaving a user unable to retrieve and
acknowledge the front of their queue.

Required work:

- Page queued delivery by total encoded bytes as well as message count.
- Use a small per-page byte limit compatible with both WebSocket peers.
- Avoid constructing one large serialized response in memory.
- Add boundary tests for maximum ciphertext, maximum queue depth, slow clients,
  and reconnecting clients with large queues.

### P1 — One-time prekeys permanently run out and can be deliberately drained — Resolved

The client creates 100 one-time prekeys during initial registration
(`crates/client/src/net.rs:177-201`). Each authenticated prekey-bundle fetch
deletes one of the target's keys
(`crates/server/src/handlers/prekey.rs:37-49`). There is no fetch rate limit or
self-fetch guard. When the supply becomes low, the client only displays a
warning (`crates/client/src/app.rs:651-653`); it never generates and uploads a
replacement batch.

An authenticated account can drain another user's prekeys, and normal use will
eventually exhaust them permanently. New sessions then lose the protection
provided by the fourth X3DH DH operation. Signed prekeys also have no rotation
lifecycle.

Required work:

- Automatically replenish OPKs with monotonic, non-reused key IDs.
- Rotate signed prekeys on a documented schedule while retaining only the
  minimum receiver-side state needed for in-flight messages.
- Reject self-fetches and apply per-account and per-target rate limits.
- Cap the total stored prekeys per user.
- Test concurrent fetches, exhaustion, replenishment, malicious draining, and
  rotation across restarts.

### P1 — The canonical release gate is red and dependencies have active advisories — Resolved

`make check` currently stops at `fmt-check` because
`crates/server/src/lib.rs` is not rustfmt-clean. Running the lint target
independently also fails on `clippy::map_unwrap_or` at
`crates/server/src/handlers/mod.rs:39-42`.

A current `cargo deny check advisories bans licenses sources` scan reported
advisories affecting these locked dependencies:

- `anyhow 1.0.102` — `RUSTSEC-2026-0190`
- `rand 0.8.5` — `RUSTSEC-2026-0097`
- `rustls-webpki 0.103.10` — `RUSTSEC-2026-0098`,
  `RUSTSEC-2026-0099`, and `RUSTSEC-2026-0104`
- `paste 1.0.15` — unmaintained (`RUSTSEC-2024-0436`), pulled in through
  `ratatui 0.29`

Not every advisory is necessarily reachable through CMP's current use, but a
security-sensitive release needs a reviewed, reproducible dependency policy.
The license portion of the ad hoc scan failed because the repository has no
`deny.toml`; this does not by itself prove a dependency license conflict.

Required work:

- Restore a green `make check` baseline.
- Update or replace affected dependencies and document any reviewed advisory
  exceptions.
- Check in a `deny.toml` defining accepted licenses, allowed sources, duplicate
  policy, and advisory handling.
- Add dependency-policy checks to the canonical local gate and CI.
- Remove unused direct dependencies and rationalize duplicate major/minor
  dependency versions where practical.

### P2 — Protocol versions are serialized but never authenticated or enforced — Resolved

`EncryptedEnvelope.version` is part of the wire format
(`crates/protocol/src/types.rs:100-109`), but neither the client nor server
validates it. It is also absent from the AEAD associated data. The crypto crate
defines `UnsupportedVersion`, but the application does not use it.

Required work:

- Define one current protocol version in a central protocol constant.
- Reject unsupported versions at client and server boundaries.
- Authenticate the version and every semantically relevant header field as
  AEAD associated data.
- Add upgrade, downgrade, unsupported-version, and header-tampering tests.

### P2 — Connection replacement does not terminate the displaced session — Open

Replacing a registered connection sends the old connection a 409 response
(`crates/server/src/connection.rs:42-56`), but the old server-side read loop is
not cancelled. It remains authenticated and can continue submitting messages
even though it is no longer the connection stored in the registry.

Required work:

- Give each connection an explicit cancellation or close signal.
- Stop accepting messages from a displaced connection immediately.
- Test old-connection rejection, new-connection delivery, and conditional
  registry cleanup under races.

### P2 — Public-release material is largely absent — Open

The repository has no root README, license text, security policy, contribution
guide, code of conduct, changelog, CI workflow, automated release workflow, or
pinned Rust toolchain. Cargo packages lack descriptions, repository URLs,
readme declarations, and explicit publication policy. Generic package names
such as `client`, `server`, `crypto`, and `protocol` also need a deliberate
crates.io publication decision.

`cluster.toml` contains a developer-specific absolute path and deployment
identifiers. The released client defaults to the hosted production server at
`wss://cmp.clusterbase.dev/ws`, but there is no public service or privacy
documentation.

Required work:

- Add `README.md`, `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, and `CHANGELOG.md`.
- Document installation, self-hosting, backup/recovery, environment variables,
  supported platforms, and the release lifecycle.
- Add an explicit threat model. Explain that the relay can observe IP
  addresses, accounts, sender/recipient relationships, timing, and message
  sizes, and that local message history and ratchet state are protected by
  filesystem permissions rather than encryption at rest.
- State prominently that the custom cryptographic implementation is
  experimental and has not received an independent security audit.
- Decide whether the hosted server remains the default. If it does, publish its
  availability expectations, privacy policy, and abuse policy.
- Replace developer-specific deployment values with a safe example or clearly
  separate private deployment configuration from public source.
- Add complete Cargo package metadata and set `publish = false` on packages not
  intended for crates.io.

## Testing assessment

### Existing strengths

- `cargo test --workspace` passes 173 tests: 75 client tests, 50 crypto tests,
  35 protocol tests, and 13 server integration tests.
- Server integration tests use a real WebSocket listener.
- The suite covers an E2EE round trip, offline delivery, authentication,
  recipient-scoped ACK behavior, forged-ciphertext rollback, replay rejection,
  out-of-order ratchet delivery, skipped-key and counter limits, persistence
  reloads, identity-key changes, filesystem permissions, and TUI behavior.
- The crypto crate denies unsafe code.
- A native optimized workspace build succeeds with
  `cargo build --release --workspace`.

### Release-critical gaps

- Disk-full, partial-write, and crash/restart fault injection around identity,
  prekey, and ratchet persistence.
- Lost ACK, duplicate delivery, reconnect, and re-acknowledgement behavior.
- Durable retry without ratchet-state reuse when a WebSocket send fails.
- Maximum-size message and queue tests with bounded-memory assertions.
- Concurrent prekey fetch, malicious draining, replenishment, and signed-prekey
  rotation.
- Connection replacement and cancellation races.
- Unsupported versions and authenticated-header tampering.
- Client network-layer tests using mock or local WebSocket peers.
- Property tests and fuzz targets for wire JSON, persisted session state,
  base64/key decoding, and adversarial ratchet counters.
- Independent X3DH and Double Ratchet known-answer vectors or interoperability
  tests. Existing round trips can allow the same mistake on both sides to pass.
- Clean-machine installation and packaged-binary lifecycle tests on every
  supported target.

## Recommended release plan

### Phase 0 — Restore a trustworthy baseline

1. Pin the Rust toolchain and document the minimum supported Rust version.
2. Fix rustfmt and Clippy failures.
3. Update vulnerable dependencies and add `deny.toml`.
4. Make the canonical gate run formatting, linting, tests, and dependency
   policy checks.
5. Keep the tree green before beginning release hardening.

### Phase 1 — Fix correctness and security boundaries

1. Introduce atomic, durable ratchet-state writes with propagated failures.
2. Couple ciphertext/outbound-message persistence with ratchet advancement so a
   crash cannot reuse state or silently lose an encrypted message.
3. Persist inbound message IDs and safely re-acknowledge duplicates.
4. Replace lossy unbounded channels with bounded, observable backpressure.
5. Page queued delivery by bytes and count.
6. Implement OPK replenishment, signed-prekey rotation, fetch limits, and
   exhaustion handling.
7. Enforce and authenticate protocol versions.
8. Terminate replaced connections on the server.

### Phase 2 — Add release-grade verification

1. Add fault-injection and crash/restart tests for every durable crypto state
   transition.
2. Add reconnect, duplicate, lost-ACK, and retry end-to-end tests through the
   real client network layer.
3. Add queue-limit, slow-client, concurrency, and abuse tests.
4. Add fuzzing/property tests for all untrusted deserialization boundaries.
5. Add independent cryptographic vectors and arrange an external protocol and
   implementation review.
6. Add Linux and macOS CI for the pinned toolchain, canonical gate, dependency
   policy, and release builds.

### Phase 3 — Prepare the public repository

1. Add the public documentation and policy files listed above.
2. Explain the architecture, security boundaries, metadata leakage, local
   storage model, deployment model, and current limitations.
3. Sanitize deployment configuration and perform a full Git-history secret
   scan before changing repository visibility.
4. Define issue and pull-request templates and a vulnerability-reporting path.
5. Clearly label the project experimental and unaudited.

### Phase 4 — Produce an alpha release

1. Build client and server artifacts in an automated target matrix.
2. Produce checksums, an SBOM, and signed artifacts/provenance.
3. Verify archives on clean machines and test the installed binaries, not only
   workspace builds.
4. Exercise a real two-client lifecycle against the staged hosted service:
   registration, initial OPK handshake, bidirectional messaging, offline queue,
   reconnect, duplicate handling, read receipts, and restart persistence.
5. Publish `0.1.0-alpha.1` with exact known limitations and upgrade guidance.

### Phase 5 — Stable-release gate

A stable release should require all of the following:

- No open P1 findings.
- Green canonical checks and release CI from a clean checkout.
- No unreviewed relevant security advisories.
- Passing crash, reconnect, queue-limit, concurrency, and packaged-binary tests.
- Reproducible signed artifacts with verified checksums and SBOMs.
- A documented production operations and incident-response path.
- Completion of an independent cryptographic and application-security audit,
  with material findings resolved.

## Verification record

Commands run during this audit:

```text
make check
make lint
make test
cargo deny check advisories bans licenses sources
cargo build --release --workspace
cargo tree -d
```

Results:

- `make check`: **failed** at `fmt-check`.
- `make lint`: **failed** on one Clippy warning promoted to an error.
- `make test`: **passed**, 173 tests total.
- `cargo deny`: **failed** on advisories and lacked a repository license policy.
- Native optimized workspace build: **passed**.
- Worktree remained clean throughout the read-only audit.

## Release recommendation

Opening the source after adding the public security and threat-model warnings is
reasonable and can help attract review. Shipping a stable release is not yet
recommended. Fix the P1 runtime issues, make the release gate reproducibly
green, complete the missing failure-boundary tests, and then publish an
explicitly experimental alpha. Reserve a stable security claim for after
independent review.
