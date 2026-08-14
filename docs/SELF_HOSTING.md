# Self-hosting and operations

## Server configuration

The relay is configured with environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CMP_BIND` | `0.0.0.0:3000` | HTTP/WebSocket listen address |
| `CMP_DB_PATH` | `cmp-server.db` | SQLite database path |
| `CMP_SERVER_ID` | `cmp-server-1` | Domain separator signed during authentication |
| `RUST_LOG` | `info` | `tracing-subscriber` log filter |

`CMP_SERVER_ID` is part of authentication challenge signatures. Keep it stable
for a deployment and use a distinct value for each independent service.

```sh
cargo build --release -p server
CMP_BIND=127.0.0.1:3000 \
CMP_DB_PATH=/var/lib/cmp/server.db \
CMP_SERVER_ID=example-production \
RUST_LOG=info \
  target/release/server
```

Terminate TLS in a trusted reverse proxy and forward WebSocket traffic to
`/ws`. The relay also exposes `GET /health`.

## Cluster manifest

The root `cluster.toml` is credential-free and uses the Debian binary runtime
with explicit CPU and memory limits. It expects the Linux release binary at
`target/x86_64-unknown-linux-gnu/release/server`. Environment-specific secrets
or service credentials must not be added to the manifest or committed.

## Server backups

The server database contains accounts, public key bundles, delivery metadata,
and queued ciphertext. Treat it as sensitive metadata.

For a consistent SQLite backup, stop the server and copy the database together
with any `-wal` and `-shm` files, or use SQLite's online backup API from an
operator-controlled tool. Test restoration to an isolated path before relying
on a backup. Restoring a server snapshot can resurrect acknowledged ciphertext
or old public prekeys, so clients may need explicit reset and re-registration;
server restoration is not a transparent rollback.

## Client backups and recovery

Stop the client before copying `~/.cmp/<user>/`. Preserve permissions and all
files as one unit: `identity.key`, `crypto.db`, `client.db`, and SQLite sidecars
must remain consistent.

Never restore an older client snapshot after that identity has sent or received
newer messages. Rolling back Double Ratchet state can reuse message keys and
deterministic nonces, violate forward-security assumptions, and permanently
desynchronize peers. CMP does not currently provide safe account recovery or
multi-device state transfer. If the current state is lost, create a new
username/identity and re-verify it with contacts.

## Upgrade procedure

1. Read `CHANGELOG.md` for protocol or storage changes.
2. Stop clients from sending and drain server queues and client outboxes.
3. Back up current state without rolling it back later.
4. Upgrade the relay and all clients together.
5. Run registration, messaging, offline delivery, receipt, reconnect, and
   restart smoke tests before reopening use.

Version 2 intentionally refuses to start or replay when durable version 1
ciphertext remains. There is no compatibility migration.
