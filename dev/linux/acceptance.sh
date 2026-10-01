#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Runs the privileged suite: the network and sandbox backends against a real kernel, and the Phase-0
# acceptance suite (T1-T10, H1-H4) against a running `soglia`.
#
# Inside the development environment (the image sets SOGLIA_DEV_CONTAINER=1, and `.devcontainer/`
# has already delegated the cgroup subtree) the suite runs in place. Anywhere else, including a
# Linux host, it runs in a fresh privileged container: the suite creates network namespaces, links
# and nftables tables, and a host is no place to leave them if a test is interrupted.

set -euo pipefail

cd "$(dirname "$0")/../.."

if [ "${SOGLIA_DEV_CONTAINER:-}" = "1" ]; then
    SOGLIA_TEST_AGENT="$(dev/linux/build-test-agent.sh)"
    export SOGLIA_TEST_AGENT
    SOGLIA_TEST_NETWORK_BACKEND=netns-nft \
        cargo test --workspace --locked --no-default-features -- --ignored --test-threads=1
    SOGLIA_TEST_NETWORK_BACKEND=cgroup-bpf \
        cargo test --workspace --locked -- --ignored --test-threads=1
    exit 0
fi

exec dev/linux/run.sh --privileged dev/linux/acceptance.sh
