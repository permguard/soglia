#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$host_dir/common.sh"

require_host
replay_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
config=$(mktemp -t soglia-spike-lima.XXXXXX.yaml)
trap 'rm -f "$config"' EXIT
render_lima "$config"

for replay in 1 2; do
    vm="soglia-spike-replay-${replay_id}-r${replay}"
    echo "VM ............................... $vm"
    if limactl list --json | jq -e --arg name "$vm" 'select(.name == $name)' >/dev/null; then
        echo "fresh replay VM name already exists: $vm" >&2
        exit 13
    fi
    ensure_vm "$vm" "$config"
    provision_and_build "$vm"
    run_guest "$vm" run
done

echo "Two independent fresh-VM replays completed."
echo "Evidence: spikes/cgroup-bpf/evidence/replay/"
