.PHONY: help fmt fmt-check lint lint-fix test check build-cli
.DEFAULT_GOAL := help

help:
	@echo "usage: make <target>"
	@echo ""
	@echo "  fmt        format all code"
	@echo "  fmt-check  verify formatting (no changes)"
	@echo "  lint       run clippy (strict)"
	@echo "  lint-fix   auto-fix clippy warnings"
	@echo "  test       run all tests"
	@echo "  check      fmt-check + lint + test"
	@echo "  build-cli  build and install client + server to ~/.local/bin/"

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

build-cli:
	cargo build --release -p client -p server
	@mkdir -p $(HOME)/.local/bin
	cp target/release/client $(HOME)/.local/bin/cmp
	cp target/release/server $(HOME)/.local/bin/cmp-server
	@echo "installed cmp and cmp-server to ~/.local/bin/"
