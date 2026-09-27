# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Soglia — Makefile
#
# The same entry points as Taskfile.yml, for people who would rather type `make`. Both files drive
# the same commands; neither is generated from the other, so a change to one belongs in the other.
#
# Task names that carry a colon keep the same words with a dash here:
#
#   task check:headers       -> make check-headers
#   task check:phase0-deps   -> make check-phase0-deps
#   task check:supply-chain  -> make check-supply-chain
#   task dev:image           -> make dev-image
#   task test:acceptance     -> make test-acceptance
#   task test:portable       -> make test-portable

SHELL := /bin/bash

.DEFAULT_GOAL := help

PKG     ?=
RELEASE ?=
ARGS    ?=
FILTER  ?=

scope   = $(if $(PKG),-p $(PKG),--workspace)
profile = $(if $(RELEASE),--release)

.PHONY: help build check check-headers check-phase0-deps check-supply-chain dev-image fmt lint test test-acceptance test-portable

help: ## List the targets.
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-20s %s\n", $$1, $$2}'

build: ## Build every component.
	cargo build $(scope) $(profile) $(ARGS)

check: lint check-headers check-phase0-deps check-supply-chain test ## Run every check the pipeline runs.

check-headers: ## Check that every source file carries the licence header.
	./scripts/check-license-headers.sh

check-phase0-deps: ## Check that the binary links no PIC, gRPC, eBPF or TLS crate (T10).
	./scripts/check-phase0-dependencies.sh

check-supply-chain: ## Check advisories, licences, duplicate crates and sources with cargo-deny.
	cargo deny check advisories licenses bans sources

dev-image: ## Build the Linux development and test image.
	docker build -t soglia-dev:local dev/linux

fmt: ## Format the code.
	cargo fmt --all

lint: ## Check formatting and run clippy with warnings denied.
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

test: ## Run the unprivileged test suite.
	cargo test $(scope) --locked $(ARGS) $(FILTER)

test-acceptance: ## Run the privileged Phase-0 suite (T1-T10, H1-H4) in the Linux development environment.
	dev/linux/acceptance.sh

test-portable: ## Run the tests of the crates that build on any system (soglia-core, soglia-proxy).
	cargo clippy -p soglia-core -p soglia-proxy --all-targets --locked -- -D warnings
	cargo test -p soglia-core -p soglia-proxy --locked $(ARGS) $(FILTER)
