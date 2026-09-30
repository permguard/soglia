#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=spikes/cgroup-bpf/host/common.sh
source "$host_dir/common.sh"

require_host
vm=${SOGLIA_SPIKE_DEV_VM:-soglia-spike-dev}
pycache="$repo_dir/spikes/cgroup-bpf/runner/scripts/__pycache__"
rm -rf -- "$pycache"
[[ ! -e $pycache ]]
config=$(mktemp -t soglia-spike-b7-lima.XXXXXX.yaml)
trap 'rm -f "$config"' EXIT
render_lima "$config"
ensure_vm "$vm" "$config"
provision_and_build "$vm"
limactl shell "$vm" -- sudo env CARGO_TARGET_DIR=/var/tmp/b7-production-target \
  /root/.cargo/bin/cargo +1.97.0 build --manifest-path /soglia/Cargo.toml --locked \
  --release --bin soglia --features cgroup-bpf
limactl shell "$vm" -- sudo cc -O2 -Wall -Wextra -Werror \
  /soglia/spikes/cgroup-bpf/runner/helpers/b6-link-injector.c -o /var/tmp/b7-link-injector
limactl shell "$vm" -- sudo cc -O2 -Wall -Wextra -Werror \
  /soglia/spikes/cgroup-bpf/runner/helpers/b7-link-detach.c -o /var/tmp/b7-link-detach
limactl shell "$vm" -- sudo env PYTHONDONTWRITEBYTECODE=1 \
  bash /soglia/spikes/cgroup-bpf/runner/scripts/b7-qualification.sh \
  /var/tmp/b7-production-target/release/soglia \
  /var/tmp/soglia-spike-2/bin/soglia-spike-agent \
  /var/tmp/b7-link-injector /var/tmp/b7-link-detach \
  /var/tmp/soglia-spike-2/bpf/foreign.o

echo "B7 diagnostic completed on $vm; no authoritative VM was created."
