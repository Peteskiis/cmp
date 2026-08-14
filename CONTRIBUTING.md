# Contributing

CMP welcomes focused bug fixes, tests, documentation, and carefully scoped
protocol improvements. Because this is security-sensitive software, small and
reviewable changes are strongly preferred.

## Before changing code

1. Read [AGENTS.md](AGENTS.md), [THREAT_MODEL.md](THREAT_MODEL.md), and the
   relevant section of [AUDIT.md](AUDIT.md).
2. Search existing issues and pull requests before proposing duplicate work.
3. Discuss breaking wire-format or cryptographic changes before implementation.

Do not use a public issue for vulnerability reports; follow
[SECURITY.md](SECURITY.md).

## Local workflow

```sh
make fmt
make check
```

`make check` is the authoritative gate. It runs locally rather than through
GitHub Actions and includes strict Clippy, all tests, rustdoc warnings, the
800-line source limit, and `cargo-deny`.

Tests may use `unwrap()` and `expect()`; production code may not. The `crypto`
crate must remain pure, platform-independent, I/O-free, and free of unsafe code.
Never log private keys, plaintext, ratchet state, or credentials.

## Pull requests

Keep each pull request to one concern. Explain why the change is needed, the
security or compatibility impact, and the exact verification performed. A
protocol change must state its versioning and durable-upgrade behavior. New
failure paths need tests at the relevant persistence or network boundary.

By contributing, you agree that your contribution is licensed under the MIT
License.
