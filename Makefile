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
#   task check:notices       -> make check-notices
#   task check:phase0-deps   -> make check-phase0-deps
#   task check:supply-chain  -> make check-supply-chain
#   task check:systems       -> make check-systems
#   task coverage:html       -> make coverage-html
#   task coverage:lcov       -> make coverage-lcov
#   task dev:image           -> make dev-image
#   task spike:b1            -> make spike-b1
#   task spike:b2:diagnostic -> make spike-b2-diagnostic
#   task spike:delete-vms    -> make spike-delete-vms
#   task spike:doctor        -> make spike-doctor
#   task spike:replay        -> make spike-replay
#   task spike:run           -> make spike-run
#   task spike:vms           -> make spike-vms
#   task test:acceptance     -> make test-acceptance
#   task test:portable       -> make test-portable

SHELL := /bin/bash

.DEFAULT_GOAL := help

PKG     ?=
RELEASE ?=
ARGS    ?=
FILTER  ?=
STALE   ?=
ONLY    ?= s0
FROM    ?=
# 1 shows Lima's own prompts instead of answering them (spike-* targets).
INTERACTIVE ?= 0
# Any value skips the confirmation of spike-delete-vms.
YES ?=

scope   = $(if $(PKG),-p $(PKG),--workspace)
profile = $(if $(RELEASE),--release)

.PHONY: help build check check-headers check-notices check-phase0-deps check-supply-chain check-systems clean coverage coverage-html coverage-lcov dev-image fmt lint notices spike-b1 spike-b2 spike-b2-diagnostic spike-b3 spike-b3-diagnostic spike-b4 spike-b4-diagnostic spike-b5 spike-b5-diagnostic spike-b6 spike-b6-diagnostic spike-b7 spike-b7-diagnostic spike-delete-vms spike-doctor spike-qualify spike-replay spike-run spike-vms test test-acceptance test-portable

help: ## List the targets.
	@grep -E '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-20s %s\n", $$1, $$2}'

build: ## Build every component.
	cargo build $(scope) $(profile) $(ARGS)

check: lint check-headers check-notices check-systems check-phase0-deps check-supply-chain test ## Run every check the pipeline runs.

check-headers: ## Check that every source file carries the licence header.
	./scripts/check-license-headers.sh

check-notices: ## Check that THIRD_PARTY_NOTICES.md matches the dependency graph.
	./scripts/third-party-notices.sh --check

check-phase0-deps: ## Check that the binary links no PIC, gRPC, eBPF or TLS crate (T10).
	./scripts/check-phase0-dependencies.sh

check-supply-chain: ## Check advisories, licences, duplicate crates and sources with cargo-deny.
	cargo deny check advisories licenses bans sources

check-systems: ## Check that the Makefile and the Taskfile offer the same commands.
	./scripts/check-build-systems.sh

clean: ## Remove build artifacts. STALE=7 removes only what nothing has touched for 7 days.
	@set -euo pipefail; \
	if [ -n "$(STALE)" ]; then \
		if ! command -v cargo-sweep >/dev/null 2>&1; then \
			echo "cargo-sweep is not installed: cargo install cargo-sweep" >&2; \
			exit 1; \
		fi; \
		cargo sweep --time "$(STALE)"; \
	else \
		cargo clean; \
	fi

coverage: ## Measure test coverage and enforce the 60% per-crate line floor.
	./scripts/check-coverage.sh

coverage-html: ## Measure coverage and open the annotated-source HTML report.
	cargo llvm-cov --workspace --html --open

coverage-lcov: ## Write coverage as lcov.info, for editors and CI uploaders.
	cargo llvm-cov --workspace --lcov --output-path lcov.info

dev-image: ## Build the Linux development and test image.
	docker build -t soglia-dev:local dev/linux

fmt: ## Format the code.
	cargo fmt --all

notices: ## Regenerate THIRD_PARTY_NOTICES.md from the resolved dependency graph.
	./scripts/third-party-notices.sh

lint: ## Check formatting and run clippy with warnings denied.
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

spike-b1: ## Run authoritative production B1 once on a newly created Lima VM.
	./spikes/cgroup-bpf/host/run-b1-fresh.sh

spike-b2: ## Run authoritative production B2 once on a newly created Lima VM.
	./spikes/cgroup-bpf/host/run-b2-fresh.sh

spike-b2-diagnostic: ## Run diagnostic production B2 on the reusable development VM.
	./spikes/cgroup-bpf/host/run-b2-diagnostic.sh

spike-b3: ## Run authoritative production B3 once on a newly created Lima VM.
	./spikes/cgroup-bpf/host/run-b3-fresh.sh

spike-b3-diagnostic: ## Run diagnostic production B3 on the reusable development VM.
	./spikes/cgroup-bpf/host/run-b3-diagnostic.sh

spike-b4: ## Run authoritative production B4 once on a newly created Lima VM.
	./spikes/cgroup-bpf/host/run-b4-fresh.sh

spike-b4-diagnostic: ## Run diagnostic production B4 on the reusable development VM.
	./spikes/cgroup-bpf/host/run-b4-diagnostic.sh

spike-b5: ## Run authoritative production B5 once on a newly created Lima VM.
	./spikes/cgroup-bpf/host/run-b5-fresh.sh

spike-b5-diagnostic: ## Run diagnostic production B5 on the reusable development VM.
	./spikes/cgroup-bpf/host/run-b5-diagnostic.sh

spike-b6: ## Run authoritative production B6 once on a newly created Lima VM.
	./spikes/cgroup-bpf/host/run-b6-fresh.sh

spike-b6-diagnostic: ## Run diagnostic production B6 on the reusable development VM.
	./spikes/cgroup-bpf/host/run-b6-diagnostic.sh

spike-b7: ## Run authoritative production B7 once on a newly created Lima VM.
	./spikes/cgroup-bpf/host/run-b7-fresh.sh

spike-b7-diagnostic: ## Run diagnostic production B7 on the reusable development VM.
	./spikes/cgroup-bpf/host/run-b7-diagnostic.sh

spike-delete-vms: ## Stop and delete every soglia-spike* Lima VM (asks first; YES=1 skips the question).
	./spikes/cgroup-bpf/host/delete-vms.sh $(if $(YES),--yes)

spike-doctor: ## Check the cgroup-BPF spike environment on the development VM (created if missing).
	SOGLIA_SPIKE_INTERACTIVE=$(INTERACTIVE) ./spikes/cgroup-bpf/host/run-dev.sh doctor

spike-qualify: ## Run and verify authoritative B1-B7, each on a fresh VM, stopping on first failure.
	./spikes/cgroup-bpf/host/run-qualification.sh

spike-replay: ## Run the authoritative S0-S14 replay on two newly created VMs, one after the other.
	SOGLIA_SPIKE_INTERACTIVE=$(INTERACTIVE) ./spikes/cgroup-bpf/host/run-fresh.sh

spike-run: ## Run spike tests diagnostically on the development VM (default ONLY=s0; FROM=sN runs from sN on).
	SOGLIA_SPIKE_INTERACTIVE=$(INTERACTIVE) ./spikes/cgroup-bpf/host/run-dev.sh run $(if $(FROM),--from $(FROM),--only $(ONLY))

spike-vms: ## List the Lima VMs of the cgroup-BPF spike.
	limactl list | awk 'NR == 1 || /soglia-spike/'

test: ## Run the unprivileged test suite.
	cargo test $(scope) --locked $(ARGS) $(FILTER)

test-acceptance: ## Run the privileged Phase-0 suite (T1-T10, H1-H4) in the Linux development environment.
	dev/linux/acceptance.sh

test-portable: ## Run the tests of the crates that build on any system (soglia-core, soglia-proxy).
	cargo clippy -p soglia-core -p soglia-proxy --all-targets --locked -- -D warnings
	cargo test -p soglia-core -p soglia-proxy --locked $(ARGS) $(FILTER)
