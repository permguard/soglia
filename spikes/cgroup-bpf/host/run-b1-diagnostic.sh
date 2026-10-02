#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$host_dir/common.sh"

require_host
vm=${SOGLIA_SPIKE_DEV_VM:-soglia-spike-dev}
config=$(mktemp -t soglia-spike-b1-lima.XXXXXX.yaml)
trap 'rm -f "$config"' EXIT
render_lima "$config"
ensure_vm "$vm" "$config"
provision_and_build "$vm"

limactl shell "$vm" -- sudo env \
  CARGO_TARGET_DIR=/var/tmp/soglia-b1-production-target \
  /root/.cargo/bin/cargo +1.97.0 build \
  --manifest-path /soglia/Cargo.toml --locked --release --bin soglia --features cgroup-bpf
limactl shell "$vm" -- sudo bash \
  /soglia/spikes/cgroup-bpf/runner/scripts/b1-qualification.sh \
  /var/tmp/soglia-b1-production-target/release/soglia

echo "B1 diagnostic completed on $vm; no authoritative VM was created."
