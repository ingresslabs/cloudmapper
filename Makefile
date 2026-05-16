SHELL := /usr/bin/env bash

CARGO_ENV ?= CARGO_PROFILE_DEV_DEBUG=0 CARGO_BUILD_JOBS=1
DEMO_OUT ?= infra
K8S_DEMO_OUT ?= infra-k8s
DB ?= $(DEMO_OUT)/map.db
BIND ?= 127.0.0.1:8765

.PHONY: help fmt clippy check build buld test demo demo-k8s ui demo-ui demo-k8s-ui loc clean

help:
	@printf 'cloudmapper Make targets\n\n'
	@printf '  make build       Build the cloudmapper CLI\n'
	@printf '  make test        Run unit tests\n'
	@printf '  make check       Run fmt, check, clippy, tests, and build\n'
	@printf '  make fmt         Check Rust formatting\n'
	@printf '  make clippy      Run Rust lints\n'
	@printf '  make demo        Build a zero-AWS large-org demo infra/ bundle\n'
	@printf '  make demo-k8s    Build a zero-cluster Kubernetes demo bundle\n'
	@printf '  make ui          Serve the local Cytoscape UI\n'
	@printf '  make demo-ui     Build the demo bundle and serve it\n'
	@printf '  make demo-k8s-ui Build the Kubernetes demo bundle and serve it\n'
	@printf '  make loc         Count lines in source files\n'
	@printf '  make clean       Remove Cargo build output\n\n'
	@printf 'Options:\n'
	@printf '  DEMO_OUT=%s\n' '$(DEMO_OUT)'
	@printf '  K8S_DEMO_OUT=%s\n' '$(K8S_DEMO_OUT)'
	@printf '  DB=%s\n' '$(DB)'
	@printf '  BIND=%s\n' '$(BIND)'

fmt:
	$(CARGO_ENV) cargo fmt --check

clippy:
	$(CARGO_ENV) cargo clippy --all-targets

check: fmt
	$(CARGO_ENV) cargo check
	$(CARGO_ENV) cargo clippy --all-targets
	$(CARGO_ENV) cargo test
	$(CARGO_ENV) cargo build

build:
	$(CARGO_ENV) cargo build

buld: build

test:
	$(CARGO_ENV) cargo test

demo:
	$(CARGO_ENV) cargo run -- demo --out "$(DEMO_OUT)"

demo-k8s:
	$(CARGO_ENV) cargo run -- demo --provider k8s --out "$(K8S_DEMO_OUT)"

ui:
	$(CARGO_ENV) cargo run -- ui --db "$(DB)" --bind "$(BIND)"

demo-ui: demo
	$(CARGO_ENV) cargo run -- ui --db "$(DEMO_OUT)/map.db" --bind "$(BIND)"

demo-k8s-ui: demo-k8s
	$(CARGO_ENV) cargo run -- ui --db "$(K8S_DEMO_OUT)/map.db" --bind "$(BIND)"

loc:
	@git ls-files -z -- \
		Makefile \
		Cargo.toml \
		'src/*.rs' \
		'src/ui_assets/*.html' \
		'src/ui_assets/*.css' \
		'src/ui_assets/app.js' \
		| xargs -0 wc -l

clean:
	cargo clean
