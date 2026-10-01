#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$host_dir/../.." && pwd)
# shellcheck source=spikes/cgroup-bpf/host/common.sh
source "$host_dir/common.sh"

require_host
production_baseline=7dd0840e4d51078c01ab26343c9eebfd315e5e5e
git -C "$repo_dir" cat-file -e "$production_baseline^{commit}"
git -C "$repo_dir" diff --exit-code "$production_baseline" -- crates src Cargo.toml Cargo.lock
if [[ -n $(git -C "$repo_dir" status --short --untracked-files=all) ]]; then
  echo "authoritative B4 requires a clean working tree" >&2
  git -C "$repo_dir" status --short --untracked-files=all >&2
  exit 13
fi

b4_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
vm="soglia-spike-b4-$b4_id"
config=$(mktemp -t soglia-spike-b4-lima.XXXXXX.yaml)
trap 'cleanup_fresh_vm "$vm" "$config"' EXIT
render_lima "$config"
echo "VM ............................... $vm"
limactl list --json | jq -e --arg name "$vm" 'select(.name == $name)' >/dev/null \
  && { echo "fresh B4 VM name already exists: $vm" >&2; exit 13; }
ensure_vm "$vm" "$config"
provision_and_build "$vm"
limactl shell "$vm" -- sudo env \
  CARGO_TARGET_DIR=/var/tmp/soglia-b4-production-target \
  /root/.cargo/bin/cargo +1.97.0 build \
  --manifest-path /soglia/Cargo.toml --locked --release --bin soglia --features cgroup-bpf
limactl shell "$vm" -- sudo env SOGLIA_B4_VM_NAME="$vm" bash \
  /soglia/spikes/cgroup-bpf/runner/scripts/b4-qualification.sh \
  /var/tmp/soglia-b4-production-target/release/soglia \
  /var/tmp/soglia-spike-2/bin/b4-driver \
  /var/tmp/soglia-spike-2/bin/soglia-spike-agent \
  --authoritative

echo "B4 authoritative qualification completed on $vm; B5-B7 were not executed."
