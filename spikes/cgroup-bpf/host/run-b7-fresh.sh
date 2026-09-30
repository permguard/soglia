#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$host_dir/../.." && pwd)
# shellcheck source=spikes/cgroup-bpf/host/common.sh
source "$host_dir/common.sh"

require_host
production_baseline=db6e1ac21a957b5fd8de96f5e3a719db1d897723
git -C "$repo_dir" cat-file -e "$production_baseline^{commit}"
git -C "$repo_dir" diff --exit-code "$production_baseline" -- crates src Cargo.toml Cargo.lock
if [[ -n $(git -C "$repo_dir" status --short --untracked-files=all) ]]; then
  echo 'authoritative B7 requires a clean working tree' >&2
  git -C "$repo_dir" status --short --untracked-files=all >&2
  exit 13
fi

b7_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
vm="soglia-spike-b7-$b7_id"
config=$(mktemp -t soglia-spike-b7-lima.XXXXXX.yaml)
trap 'rm -f "$config"' EXIT
render_lima "$config"
echo "VM ............................... $vm"
limactl list --json | jq -e --arg name "$vm" 'select(.name == $name)' >/dev/null \
  && { echo "fresh B7 VM name already exists: $vm" >&2; exit 13; }
ensure_vm "$vm" "$config"
provision_and_build "$vm"
limactl shell "$vm" -- sudo env CARGO_TARGET_DIR=/var/tmp/b7-production-target \
  /root/.cargo/bin/cargo +1.97.0 build --manifest-path /soglia/Cargo.toml --locked \
  --release --bin soglia --features cgroup-bpf
limactl shell "$vm" -- sudo cc -O2 -Wall -Wextra -Werror \
  /soglia/spikes/cgroup-bpf/runner/helpers/b6-link-injector.c -o /var/tmp/b7-link-injector
limactl shell "$vm" -- sudo cc -O2 -Wall -Wextra -Werror \
  /soglia/spikes/cgroup-bpf/runner/helpers/b7-link-detach.c -o /var/tmp/b7-link-detach
limactl shell "$vm" -- sudo env SOGLIA_B7_VM_NAME="$vm" bash \
  /soglia/spikes/cgroup-bpf/runner/scripts/b7-qualification.sh \
  /var/tmp/b7-production-target/release/soglia \
  /var/tmp/soglia-spike-2/bin/soglia-spike-agent \
  /var/tmp/b7-link-injector /var/tmp/b7-link-detach \
  /var/tmp/soglia-spike-2/bpf/foreign.o --authoritative

echo "B7 authoritative qualification completed on $vm."
