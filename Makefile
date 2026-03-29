.PHONY: help fmt fmt-check lint lint-fix test check build-cli build-server run-server release
.DEFAULT_GOAL := help

MAC_TARGETS := aarch64-apple-darwin
LINUX_TARGETS := x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

help:
	@echo "usage: make <target>"
	@echo ""
	@echo "  fmt        format all code"
	@echo "  fmt-check  verify formatting (no changes)"
	@echo "  lint       run clippy (strict)"
	@echo "  lint-fix   auto-fix clippy warnings"
	@echo "  test       run all tests"
	@echo "  check      fmt-check + lint + test"
	@echo "  build-cli    build and install client to ~/.local/bin/"
	@echo "  build-server build and install server to ~/.local/bin/"
	@echo "  run-server   start the server on 127.0.0.1:3000"
	@echo "  release      cross-compile client for mac, linux, arm linux"

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace -- -D warnings

lint-fix:
	cargo clippy --workspace --fix --allow-dirty --allow-staged -- -D warnings

test:
	cargo test --workspace

check: fmt-check lint test

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
