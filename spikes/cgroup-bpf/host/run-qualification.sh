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

gate_specs=(
  'B1|soglia-spike-b1-|b1-*|run-b1-fresh.sh'
  'B2|soglia-spike-b2-|b2-*|run-b2-fresh.sh'
  'B3|soglia-spike-b3-|b3-*|run-b3-fresh.sh'
  'B4|soglia-spike-b4-|b4-*|run-b4-fresh.sh'
  'B5|soglia-spike-b5-|b5-*|run-b5-fresh.sh'
  'B6|soglia-spike-b6-|b6-*|run-b6-fresh.sh'
  'B7|soglia-spike-b7-|b7-*|run-b7-fresh.sh'
  'UNINSTALL|soglia-spike-uninstall-|uninstall-*|run-uninstall-fresh.sh'
)

for spec in "${gate_specs[@]}"; do
  IFS='|' read -r gate vm_prefix run_pattern runner <<< "$spec"
  before_vms=$(mktemp -t soglia-qualify-before-vms.XXXXXX)
  after_vms=$(mktemp -t soglia-qualify-after-vms.XXXXXX)
  before_runs=$(mktemp -t soglia-qualify-before-runs.XXXXXX)
  after_runs=$(mktemp -t soglia-qualify-after-runs.XXXXXX)
  snapshot_vms > "$before_vms"
  find "$evidence_root" -mindepth 1 -maxdepth 1 -type d -name "$run_pattern" -print | sort > "$before_runs"

  set +e
  SOGLIA_SPIKE_CLEANUP_VM=1 PYTHONDONTWRITEBYTECODE=1 "$host_dir/$runner"
  gate_status=$?
  set -e

  snapshot_vms > "$after_vms"
  remaining_vms=$(comm -13 "$before_vms" "$after_vms" | awk -v prefix="$vm_prefix" 'index($0,prefix)==1 {print}')
  vm_count=$(printf '%s\n' "$remaining_vms" | awk 'NF {count++} END {print count+0}')
  rm -f "$before_vms" "$after_vms"
  if [[ $vm_count -ne 0 ]]; then
    echo "$gate: fresh qualification VM was not deleted: $remaining_vms" >&2
    exit 13
  fi

  if [[ $gate_status -ne 0 ]]; then
    echo "$gate: authoritative gate failed with status $gate_status; stopping" >&2
    exit "$gate_status"
  fi
  find "$evidence_root" -mindepth 1 -maxdepth 1 -type d -name "$run_pattern" -print | sort > "$after_runs"
  run=$(comm -13 "$before_runs" "$after_runs")
  run_count=$(printf '%s\n' "$run" | awk 'NF {count++} END {print count+0}')
  rm -f "$before_runs" "$after_runs"
  if [[ $run_count -ne 1 ]]; then
    echo "$gate: expected exactly one new evidence directory, found $run_count" >&2
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
