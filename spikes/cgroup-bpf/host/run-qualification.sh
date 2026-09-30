#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$host_dir/../.." && pwd)
evidence_root="$repo_dir/spikes/cgroup-bpf/evidence/replay"
verifier="$repo_dir/spikes/cgroup-bpf/runner/scripts/verify_qualification.py"
qualification_id="qualification-$(date -u +%Y%m%dT%H%M%SZ)-$$"
qualification_dir="$evidence_root/$qualification_id"

if [[ -n $(git -C "$repo_dir" status --short --untracked-files=all) ]]; then
  echo 'spike:qualify requires a clean working tree' >&2
  git -C "$repo_dir" status --short --untracked-files=all >&2
  exit 13
fi

mkdir -p "$qualification_dir"

snapshot_vms() {
  limactl list --json | jq -r '.name // empty' | sort
}

for gate in 1 2 3 4 5 6 7; do
  before_vms=$(mktemp -t soglia-qualify-before-vms.XXXXXX)
  after_vms=$(mktemp -t soglia-qualify-after-vms.XXXXXX)
  before_runs=$(mktemp -t soglia-qualify-before-runs.XXXXXX)
  after_runs=$(mktemp -t soglia-qualify-after-runs.XXXXXX)
  snapshot_vms > "$before_vms"
  find "$evidence_root" -mindepth 1 -maxdepth 1 -type d -name "b${gate}-*" -print | sort > "$before_runs"

  set +e
  SOGLIA_SPIKE_CLEANUP_VM=1 PYTHONDONTWRITEBYTECODE=1 "$host_dir/run-b${gate}-fresh.sh"
  gate_status=$?
  set -e

  snapshot_vms > "$after_vms"
  remaining_vms=$(comm -13 "$before_vms" "$after_vms" | awk -v prefix="soglia-spike-b${gate}-" 'index($0,prefix)==1 {print}')
  vm_count=$(printf '%s\n' "$remaining_vms" | awk 'NF {count++} END {print count+0}')
  rm -f "$before_vms" "$after_vms"
  if [[ $vm_count -ne 0 ]]; then
    echo "B${gate}: fresh qualification VM was not deleted: $remaining_vms" >&2
    exit 13
  fi

  if [[ $gate_status -ne 0 ]]; then
    echo "B${gate}: authoritative gate failed with status $gate_status; stopping" >&2
    exit "$gate_status"
  fi
  find "$evidence_root" -mindepth 1 -maxdepth 1 -type d -name "b${gate}-*" -print | sort > "$after_runs"
  run=$(comm -13 "$before_runs" "$after_runs")
  run_count=$(printf '%s\n' "$run" | awk 'NF {count++} END {print count+0}')
  rm -f "$before_runs" "$after_runs"
  if [[ $run_count -ne 1 ]]; then
    echo "B${gate}: expected exactly one new evidence directory, found $run_count" >&2
    exit 13
  fi
  printf '%s\n' "$run" >> "$qualification_dir/runs.txt"
done

runs=()
while IFS= read -r run; do
  runs+=("$run")
done < "$qualification_dir/runs.txt"
PYTHONDONTWRITEBYTECODE=1 python3 "$verifier" \
  --json-output "$qualification_dir/summary.json" "${runs[@]}" \
  | tee "$qualification_dir/summary.txt"

echo "Qualification evidence: $qualification_dir"
