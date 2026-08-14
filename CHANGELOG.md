# Changelog

All notable user-visible changes are recorded here. CMP does not promise stable
wire or storage compatibility before 1.0.

## Unreleased

### Added

- Version 2 authenticated envelope semantics.
- Durable encrypted outboxes, acknowledgements, replay markers, and bounded
  server acceptance ledgers.
- One-time-prekey replenishment, signed-prekey rotation, and fetch controls.
- Immediate cancellation of displaced authenticated connections.
- Public security, threat-model, contribution, operations, and release docs.

### Security

- Ratchet state is committed before ciphertext is released.
- Encrypted envelope versions and semantic headers are authenticated as AEAD
  associated data.
- Queue and receipt acknowledgements are correlated and retry-safe.

## 0.1.0-alpha.1

Not yet released. The first alpha will remain experimental and unaudited.
