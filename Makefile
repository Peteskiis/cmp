.PHONY: help fmt fmt-check cargo-check lint lint-fix test doc line-check dependencies check build-cli build-server run-server release release-server
.DEFAULT_GOAL := help

MAC_TARGETS := aarch64-apple-darwin
LINUX_TARGETS := x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl

help:
	@echo "usage: make <target>"
	@echo ""
	@echo "  fmt        format all code"
	@echo "  fmt-check  verify formatting (no changes)"
	@echo "  cargo-check type-check all targets and features"
	@echo "  lint       run clippy (strict)"
	@echo "  lint-fix   auto-fix clippy warnings"
	@echo "  test       run all tests"
	@echo "  doc        build documentation with warnings denied"
	@echo "  line-check enforce the 800-line Rust source-file limit"
	@echo "  dependencies check dependency advisories, licenses, bans, and sources"
	@echo "  check      fmt-check + lint + test + dependency policy"
	@echo "  build-cli    build and install client to ~/.local/bin/"
	@echo "  build-server build and install server to ~/.local/bin/"
	@echo "  run-server   start the server on 0.0.0.0:3000"
	@echo "  release         cross-compile client for mac + linux (gnu/musl, x86_64/arm)"
	@echo "  release-server  cross-compile server for linux (gnu/musl, x86_64/arm)"

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

cargo-check:
	cargo check --workspace --all-targets --all-features

lint:
	cargo clippy --workspace --all-targets --all-features

lint-fix:
	cargo clippy --workspace --all-targets --all-features --fix --allow-dirty --allow-staged

test:
	cargo test --workspace --all-targets --all-features

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

line-check:
	bash scripts/line-check.sh

dependencies:
	cargo deny check advisories bans licenses sources

check: fmt-check cargo-check lint test doc line-check dependencies

run-server:
	cargo run -p server

build-cli:
	cargo build --release -p client
	@mkdir -p $(HOME)/.local/bin
	cp target/release/client $(HOME)/.local/bin/cmp
	@echo "installed cmp to ~/.local/bin/"

build-server:
	cargo build --release -p server

release:
	@mkdir -p dist
	@for target in $(MAC_TARGETS); do \
		echo "building $$target..."; \
		cargo build --release --target $$target -p client && \
		mkdir -p dist/$$target && \
		cp target/$$target/release/client dist/$$target/cmp && \
		tar -czf dist/cmp-$$target.tar.gz -C dist/$$target cmp && \
		echo "  -> dist/cmp-$$target.tar.gz"; \
	done
	@for target in $(LINUX_TARGETS); do \
		echo "building $$target (via cross)..."; \
		cross build --release --target $$target -p client && \
		mkdir -p dist/$$target && \
		cp target/$$target/release/client dist/$$target/cmp && \
		tar -czf dist/cmp-$$target.tar.gz -C dist/$$target cmp && \
		echo "  -> dist/cmp-$$target.tar.gz"; \
	done
	@echo "done — all archives in dist/"

release-server:
	@mkdir -p dist
	@for target in $(LINUX_TARGETS); do \
		echo "building server for $$target (via cross)..."; \
		cross build --release --target $$target -p server && \
		mkdir -p dist/$$target && \
		cp target/$$target/release/server dist/$$target/cmp-server && \
		tar -czf dist/cmp-server-$$target.tar.gz -C dist/$$target cmp-server && \
		echo "  -> dist/cmp-server-$$target.tar.gz"; \
	done
	@echo "done — all server archives in dist/"
