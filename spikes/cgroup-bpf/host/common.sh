#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
spike_dir=$(CDPATH= cd -- "$host_dir/.." && pwd)
repo_dir=$(CDPATH= cd -- "$spike_dir/../.." && pwd)

require_host() {
    [[ "$(uname -s)" == Darwin ]] || {
        echo "the host bootstrap requires macOS" >&2
        exit 13
    }
    command -v limactl >/dev/null 2>&1 || {
        echo "limactl is required" >&2
        exit 13
    }
}

render_lima() {
    local destination=$1 escaped
    escaped=${repo_dir//|/\\|}
    sed "s|__SOGLIA_REPOSITORY__|$escaped|g" "$spike_dir/lima.yaml" > "$destination"
}

# limactl asks for confirmation whenever it has a terminal. By default the bootstrap answers for
# it (`--tty=false`: proceed with the rendered configuration), so an unattended replay never stops
# halfway waiting for a key. SOGLIA_SPIKE_INTERACTIVE=1 brings Lima's own prompts back.
lima_tty() {
    if [[ ${SOGLIA_SPIKE_INTERACTIVE:-0} == 1 ]]; then
        echo "--tty=true"
    else
        echo "--tty=false"
    fi
}

ensure_vm() {
    local vm=$1 config=$2
    if ! limactl list --json | jq -e --arg name "$vm" 'select(.name == $name)' >/dev/null; then
        limactl create "$(lima_tty)" --name="$vm" "$config"
    fi
    limactl start "$(lima_tty)" "$vm"
}

provision_and_build() {
    local vm=$1
    limactl shell "$vm" -- sudo /soglia/spikes/cgroup-bpf/host/provision.sh
    limactl shell "$vm" -- sudo /soglia/spikes/cgroup-bpf/host/build-guest.sh
}

run_guest() {
    local vm=$1
    shift
    limactl shell "$vm" -- sudo /var/tmp/soglia-spike-2/bin/soglia-spike-runner \
        "$@" \
        --repo /soglia \
        --artifacts /var/tmp/soglia-spike-2 \
        --evidence /soglia/spikes/cgroup-bpf/evidence/replay
}
