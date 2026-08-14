# CMP

CMP is an experimental end-to-end encrypted, one-to-one messaging system with
a Rust terminal client and a store-and-forward WebSocket relay. Message content
is encrypted on clients using X3DH session establishment and a Double Ratchet;
the relay stores and routes opaque ciphertext.

> [!WARNING]
> CMP contains a custom cryptographic implementation. It has not received an
> independent security audit and must not be treated as production-secure. The
> first release will be an explicitly experimental alpha.

## Status

CMP is preparing for an open-source `0.1.0-alpha.1` release. Protocol version 2
is intentionally incompatible with version 1. There is no compatibility
fallback; durable version 1 queues and outboxes must be drained or reset before
upgrading.

The current security and release-readiness work is tracked in [AUDIT.md](AUDIT.md).
The security boundary and known limitations are documented in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Architecture

| Crate | Responsibility |
| --- | --- |
| `protocol` | Versioned JSON wire types, canonical AEAD context, and limits |
| `crypto` | Pure X3DH, Double Ratchet, key derivation, and fingerprints |
| `server` | Authentication, prekey service, and opaque store-and-forward relay |
| `client` | Inline terminal UI, local persistence, and encrypted messaging |

The server never depends on the crypto crate and never receives plaintext.
This does not hide metadata: the relay can observe accounts, IP addresses,
sender/recipient relationships, timing, frequency, and ciphertext sizes.

## Build

Prerequisites:

- Rust 1.97.1, installed automatically by `rust-toolchain.toml`
- a C toolchain suitable for the target platform
- `cargo-deny` for the full local gate
- `cross` only for the multi-target release commands

```sh
git clone https://github.com/Peteskiis/cmp.git
cd cmp
make check
make build-cli
```

`make build-cli` installs the client as `~/.local/bin/cmp`. Ensure that
`~/.local/bin` appears before `/usr/bin` in `PATH`; many systems already provide
an unrelated coreutils program named `cmp`.

## Use the client

The hosted experimental relay is the default:

```sh
cmp --user alice
```

To use a self-hosted relay:

```sh
cmp --user alice --server ws://127.0.0.1:3000/ws
```

The first connection registers the username and its identity key. Later
connections authenticate with that key. The full-screen client lists existing
conversations on the left. Press `n` from the list or `Ctrl+N` anywhere to start
a conversation, `Tab` to move between the list and composer, `v` from the list
or `F2` anywhere to compare safety numbers, and `F1` for all shortcuts. `Enter`
sends a message and `Shift+Enter` inserts a newline.

Client state is stored under `~/.cmp/<user>/`. It contains key material,
ratchet state, durable encrypted outbox entries, and plaintext local message
history. See [Self-hosting and operations](docs/SELF_HOSTING.md) before backing
up, restoring, or moving this directory.

## Run a relay

```sh
make build-server
CMP_BIND=127.0.0.1:3000 \
CMP_DB_PATH=./cmp-server.db \
CMP_SERVER_ID=local-dev \
  target/release/server
```

The relay exposes `/health` and the WebSocket endpoint `/ws`. Configuration,
backup guidance, and the credential-free Cluster deployment manifest are in
[docs/SELF_HOSTING.md](docs/SELF_HOSTING.md).

## Hosted service

`wss://cmp.clusterbase.dev/ws` is currently an experimental testing service,
not a production communications service. It has no uptime, durability, privacy,
or support SLA. Read [docs/HOSTED_SERVICE.md](docs/HOSTED_SERVICE.md) before use.
The testing-service data practices and use restrictions are documented in
[PRIVACY.md](PRIVACY.md) and [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).

## Development and releases

Run `make check` before every commit. It enforces formatting, compilation,
strict Clippy, tests, documentation warnings, source-file limits, and the
dependency policy. GitHub Actions are not the project gate; verification is run
locally and recorded in pull requests.

See [CONTRIBUTING.md](CONTRIBUTING.md) for changes and
[docs/RELEASING.md](docs/RELEASING.md) for the alpha release contract.

## License

CMP is available under the [MIT License](LICENSE).
