#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$host_dir/../.." && pwd)
# shellcheck source=spikes/cgroup-bpf/host/common.sh
source "$host_dir/common.sh"

require_host
production_baseline=36ca2ee52d9ba6e88e729754567f59db3d744bc3
git -C "$repo_dir" cat-file -e "$production_baseline^{commit}"
git -C "$repo_dir" diff --exit-code "$production_baseline" -- crates src Cargo.toml Cargo.lock
if [[ -n $(git -C "$repo_dir" status --short --untracked-files=all) ]]; then
  echo "authoritative B6 requires a clean working tree" >&2
  git -C "$repo_dir" status --short --untracked-files=all >&2
  exit 13
fi

b6_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
vm="soglia-spike-b6-$b6_id"
config=$(mktemp -t soglia-spike-b6-lima.XXXXXX.yaml)
trap 'cleanup_fresh_vm "$vm" "$config"' EXIT
render_lima "$config"
echo "VM ............................... $vm"
limactl list --json | jq -e --arg name "$vm" 'select(.name == $name)' >/dev/null \
  && { echo "fresh B6 VM name already exists: $vm" >&2; exit 13; }
ensure_vm "$vm" "$config"
provision_and_build "$vm"
limactl shell "$vm" -- sudo env CARGO_TARGET_DIR=/var/tmp/b6-production-target \
  /root/.cargo/bin/cargo +1.97.0 build --manifest-path /soglia/Cargo.toml --locked \
  --release --bin soglia --features cgroup-bpf
limactl shell "$vm" -- sudo env SOGLIA_B6_VM_NAME="$vm" bash \
  /soglia/spikes/cgroup-bpf/runner/scripts/b6-qualification.sh \
  /var/tmp/b6-production-target/release/soglia \
  /var/tmp/soglia-spike-2/bin/b6-driver \
  /var/tmp/soglia-spike-2/bin/b6-trace \
  /var/tmp/soglia-spike-2/bin/soglia-spike-agent \
  /soglia/spikes/cgroup-bpf/runner/helpers/b6-link-injector.c --authoritative

echo "B6 authoritative qualification completed on $vm; B7 was not executed."
