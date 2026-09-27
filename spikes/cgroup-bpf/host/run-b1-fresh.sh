#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$host_dir/common.sh"

require_host
b1_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
vm="soglia-spike-b1-$b1_id"
config=$(mktemp -t soglia-spike-b1-lima.XXXXXX.yaml)
trap 'rm -f "$config"' EXIT
render_lima "$config"

echo "VM ............................... $vm"
if limactl list --json | jq -e --arg name "$vm" 'select(.name == $name)' >/dev/null; then
  echo "fresh B1 VM name already exists: $vm" >&2
  exit 13
fi

ensure_vm "$vm" "$config"
provision_and_build "$vm"
limactl shell "$vm" -- sudo env \
  CARGO_TARGET_DIR=/var/tmp/soglia-b1-production-target \
  /root/.cargo/bin/cargo +1.97.0 build \
  --manifest-path /soglia/Cargo.toml \
  --locked \
  --release \
  --bin soglia \
  --features cgroup-bpf
limactl shell "$vm" -- sudo bash \
  /soglia/spikes/cgroup-bpf/runner/scripts/b1-qualification.sh \
  /var/tmp/soglia-b1-production-target/release/soglia \
  --authoritative

echo "B1 authoritative qualification completed on $vm; B2-B7 were not executed."
