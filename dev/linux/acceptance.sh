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
    external_root=/sys/fs/bpf/soglia-acceptance-external
    external_loader=/tmp/soglia-acceptance-unnamed-device
    external_program="$external_root/program"
    external_link="$external_root/link"
    external_program_json=/tmp/soglia-acceptance-unnamed-program.json
    cleanup_external() {
        rm -f "$external_link" "$external_program" "$external_loader" "$external_program_json"
        rmdir "$external_root" 2>/dev/null || true
    }
    trap cleanup_external EXIT

    printf 'acceptance_environment=dev/linux privileged=true uid=%s\n' "$(id -u)"
    test "$(id -u)" -eq 0
    test -d /sys/fs/cgroup/soglia
    test ! -e "$external_root"
    mkdir "$external_root"
    cc -O2 -Wall -Wextra -Werror \
        spikes/cgroup-bpf/runner/helpers/b1-unnamed-device.c \
        -o "$external_loader"
    "$external_loader" load 1 /sys/fs/cgroup/soglia "$external_program" "$external_link"
    bpftool -j prog show pinned "$external_program" > "$external_program_json"
    jq -e '
        (if type == "array" then .[0] else . end) as $program
        | $program.type == "cgroup_device"
          and (($program.name // "") == "")
          and ($program.id | type == "number")
          and ($program.tag | type == "string" and length > 0)
    ' "$external_program_json" >/dev/null
    printf 'external_unnamed_bpf_program='
    jq -c '
        (if type == "array" then .[0] else . end)
        | {id,type,tag,name:(.name // "")}
    ' "$external_program_json"

    SOGLIA_TEST_AGENT="$(dev/linux/build-test-agent.sh)"
    export SOGLIA_TEST_AGENT
    SOGLIA_TEST_NETWORK_BACKEND=netns-nft \
        cargo test --workspace --locked --no-default-features -- --ignored --test-threads=1
    SOGLIA_TEST_NETWORK_BACKEND=cgroup-bpf \
        cargo test --workspace --locked -- --ignored --test-threads=1
    cleanup_external
    trap - EXIT
    exit 0
fi

exec dev/linux/run.sh --privileged dev/linux/acceptance.sh
