#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$host_dir/../.." && pwd)
# shellcheck source=spikes/cgroup-bpf/host/common.sh
source "$host_dir/common.sh"

require_host
production_baseline=42b6ced25a78a33cce370248af1e8d61d7251731

git -C "$repo_dir" cat-file -e "$production_baseline^{commit}"
git -C "$repo_dir" diff --exit-code "$production_baseline" -- \
  crates src Cargo.toml Cargo.lock
if [[ -n $(git -C "$repo_dir" status --short --untracked-files=all) ]]; then
  echo "authoritative B2 requires a clean working tree" >&2
  git -C "$repo_dir" status --short --untracked-files=all >&2
  exit 13
fi

b2_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
vm="soglia-spike-b2-$b2_id"
config=$(mktemp -t soglia-spike-b2-lima.XXXXXX.yaml)
trap 'rm -f "$config"' EXIT
render_lima "$config"

echo "VM ............................... $vm"
if limactl list --json | jq -e --arg name "$vm" 'select(.name == $name)' >/dev/null; then
  echo "fresh B2 VM name already exists: $vm" >&2
  exit 13
fi

ensure_vm "$vm" "$config"
provision_and_build "$vm"
limactl shell "$vm" -- sudo env \
  CARGO_TARGET_DIR=/var/tmp/soglia-b2-production-target \
  /root/.cargo/bin/cargo +1.97.0 build \
  --manifest-path /soglia/Cargo.toml \
  --locked \
  --release \
  --bin soglia \
  --features cgroup-bpf
limactl shell "$vm" -- sudo env SOGLIA_B2_VM_NAME="$vm" bash \
  /soglia/spikes/cgroup-bpf/runner/scripts/b2-qualification.sh \
  /var/tmp/soglia-b2-production-target/release/soglia \
  /var/tmp/soglia-spike-2/bin/b2-driver \
  /var/tmp/soglia-spike-2/bin/soglia-spike-agent \
  --authoritative

echo "B2 authoritative qualification completed on $vm; B3-B7 were not executed."
