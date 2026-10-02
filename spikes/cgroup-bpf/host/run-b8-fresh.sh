#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$host_dir/../.." && pwd)
# shellcheck source=spikes/cgroup-bpf/host/common.sh
source "$host_dir/common.sh"

require_host
production_baseline=cfb2d375e76de59694e25374ec5df47c2bfb6c6a
pycache="$repo_dir/spikes/cgroup-bpf/runner/scripts/__pycache__"
[[ ! -e $pycache ]]
git -C "$repo_dir" cat-file -e "$production_baseline^{commit}"
git -C "$repo_dir" diff --exit-code "$production_baseline" -- crates src Cargo.toml Cargo.lock
if [[ -n $(git -C "$repo_dir" status --short --untracked-files=all) ]]; then
  echo 'authoritative B8 requires a clean working tree' >&2
  git -C "$repo_dir" status --short --untracked-files=all >&2
  exit 13
fi

b8_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
vm="soglia-spike-b8-$b8_id"
config=$(mktemp -t soglia-spike-b8-lima.XXXXXX.yaml)
trap 'cleanup_fresh_vm "$vm" "$config"' EXIT
render_lima "$config"
echo "VM ............................... $vm"
limactl list --json | jq -e --arg name "$vm" 'select(.name == $name)' >/dev/null \
  && { echo "fresh B8 VM name already exists: $vm" >&2; exit 13; }
ensure_vm "$vm" "$config"
provision_and_build "$vm"
limactl shell "$vm" -- sudo env CARGO_TARGET_DIR=/var/tmp/b8-production-target \
  /root/.cargo/bin/cargo +1.97.0 build --manifest-path /soglia/Cargo.toml --locked \
  --release --bin soglia --features cgroup-bpf
limactl shell "$vm" -- sudo env SOGLIA_QUALIFICATION_GATE=B8 SOGLIA_B8_VM_NAME="$vm" \
  PYTHONDONTWRITEBYTECODE=1 bash \
  /soglia/spikes/cgroup-bpf/runner/scripts/b7-qualification.sh \
  /var/tmp/b8-production-target/release/soglia \
  /var/tmp/soglia-spike-2/bin/soglia-spike-agent \
  /bin/false /bin/false /var/tmp/soglia-spike-2/bpf/foreign.o --authoritative

echo "B8 authoritative qualification completed on $vm."
