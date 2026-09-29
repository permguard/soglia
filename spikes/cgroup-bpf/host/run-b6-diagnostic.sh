#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=spikes/cgroup-bpf/host/common.sh
source "$host_dir/common.sh"

require_host
vm=${SOGLIA_SPIKE_DEV_VM:-soglia-spike-dev}
config=$(mktemp -t soglia-spike-b6-lima.XXXXXX.yaml)
trap 'rm -f "$config"' EXIT
render_lima "$config"
ensure_vm "$vm" "$config"
provision_and_build "$vm"

limactl shell "$vm" -- sudo env CARGO_TARGET_DIR=/var/tmp/b6-production-target \
  /root/.cargo/bin/cargo +1.97.0 build --manifest-path /soglia/Cargo.toml --locked \
  --release --bin soglia --features cgroup-bpf
limactl shell "$vm" -- sudo bash \
  /soglia/spikes/cgroup-bpf/runner/scripts/b6-qualification.sh \
  /var/tmp/b6-production-target/release/soglia \
  /var/tmp/soglia-spike-2/bin/b6-driver \
  /var/tmp/soglia-spike-2/bin/b6-trace \
  /var/tmp/soglia-spike-2/bin/soglia-spike-agent \
  /soglia/spikes/cgroup-bpf/runner/helpers/b6-link-injector.c

echo "B6 diagnostic completed on $vm; no authoritative VM was created."
