# Threat Model

## Status and scope

CMP provides experimental end-to-end encryption for one-to-one text messages.
It is not independently audited. This model describes intended properties; it
is not proof that the implementation achieves them.

The protected content is message plaintext, identity private keys, signed and
one-time prekey private material, Double Ratchet keys, and local verification
state. The relay is deliberately outside the plaintext trust boundary.

## Adversaries considered

- A malicious or compromised relay that can inspect, delay, drop, duplicate,
  reorder, replay, or modify network traffic and stored ciphertext.
- A network observer that can see endpoints, timing, and traffic volume.
- An authenticated abusive account attempting queue, prekey, or memory
  exhaustion within protocol limits.
- An attacker who later obtains old server ciphertext.

CMP aims to detect ciphertext/header modification, authenticate established
sessions, preserve ratchet state across crashes, prevent replay from mutating a
session, and limit server/client queues. Safety numbers allow users to compare
authenticated identity keys through a separate trusted channel.

## Explicitly not protected

The relay can observe and retain:

- usernames, IP addresses, and connection times;
- sender and recipient relationships;
- message, receipt, and typing timing;
- ciphertext sizes and delivery/retry behavior;
- public identity keys, signed prekeys, and one-time prekeys.

CMP does not provide anonymity, traffic-analysis resistance, sender/recipient
privacy from the relay, deniable authentication, group messaging, multi-device
state synchronization, or protection from endpoint compromise. Typing events
are relay-visible metadata. The server can deny service or withhold messages.

## Endpoint and local-storage boundary

Client files under `~/.cmp/<user>/` are protected by Unix filesystem
permissions, not encryption at rest. They include plaintext message history and
live cryptographic state. Malware, a compromised user account, root access,
unsafe backups, terminal capture, or an unlocked device can expose them.

Identity keys use trust on first use. A user must compare `/verify` safety
numbers out of band to detect an incorrect first key or a later identity
change. CMP has no certificate authority or account-recovery authority.

## Cryptographic lifecycle

Protocol version 2 binds the version, envelope type, X3DH header fields, and
Double Ratchet header into AEAD associated data. One-time prekeys are reserved
and consumed with bounded lifetimes; signed prekeys rotate while receiver-side
private history covers accepted delayed messages.

Restoring stale client ratchet state can reuse message keys and deterministic
nonces. A client data snapshot must never be rolled back after newer messages
have been sent or received. See [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md).

## Operational assumptions

- Clients and servers run the same supported protocol version.
- Host clocks are sufficiently accurate for challenge, queue, and prekey
  lifetimes.
- Randomness supplied by the operating system is secure.
- Operators protect server databases and logs even though message bodies are
  ciphertext.
- Users protect endpoints and perform safety-number verification when identity
  assurance matters.

## Remaining assurance work

Before any stable security claim, CMP needs independent cryptographic and
application review, external known-answer/interoperability vectors, fuzzing of
untrusted boundaries, packaged-binary tests, and a documented incident-response
process.
