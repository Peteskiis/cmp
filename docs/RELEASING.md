# Release process

CMP uses semantic versioning for release labels, but versions before 1.0 may
break wire formats, persisted state, command behavior, and deployment contracts.

## Alpha contract

The first planned release is `0.1.0-alpha.1`. It must be described as
experimental and unaudited. A release is identified by an annotated Git tag and
the exact source commit; repository version metadata and `CHANGELOG.md` must
match that tag.

## Required checks

1. Start from a clean checkout of the intended tag.
2. Run `make check` with the pinned Rust toolchain.
3. Build client and server archives with `make release` and
   `make release-server`.
4. Generate SHA-256 checksums and an SBOM for every archive.
5. Verify archives on clean Linux and macOS machines.
6. Exercise registration, X3DH setup, bidirectional messaging, offline queue,
   reconnect, duplicate delivery, receipts, and restart persistence using the
   packaged binaries.
7. Review current advisories and the Git-history secret scan.
8. Publish exact known limitations and upgrade/reset instructions.

Release artifacts and provenance are not automated yet. Until a reviewed,
reproducible workflow exists, a local build is development evidence only and
must not be presented as an official release.

## Stable releases

A stable release additionally requires the gates in `AUDIT.md`, including an
independent cryptographic and application-security review with material
findings resolved.
