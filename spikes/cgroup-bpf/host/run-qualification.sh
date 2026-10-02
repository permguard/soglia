#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(git -C "$host_dir" rev-parse --show-toplevel)
evidence_root="$repo_dir/spikes/cgroup-bpf/evidence/replay"
verifier="$repo_dir/spikes/cgroup-bpf/runner/scripts/verify_qualification.py"
config_preflight="$repo_dir/spikes/cgroup-bpf/runner/scripts/preflight_qualification_configs.py"
qualification_id="qualification-$(date -u +%Y%m%dT%H%M%SZ)-$$"
qualification_dir="$evidence_root/$qualification_id"

if [[ -n $(git -C "$repo_dir" status --short --untracked-files=all) ]]; then
  echo 'spike:qualify requires a clean working tree' >&2
  git -C "$repo_dir" status --short --untracked-files=all >&2
  exit 13
fi

mkdir -p "$qualification_dir"
: > "$qualification_dir/runs.txt"

cargo +1.97.0 build --locked \
  --manifest-path "$repo_dir/spikes/cgroup-bpf/runner/config-preflight/Cargo.toml"
config_validator="$repo_dir/spikes/cgroup-bpf/runner/config-preflight/target/debug/soglia-config-preflight"
[[ -x $config_validator ]] || { echo 'qualification config validator was not built' >&2; exit 13; }

snapshot_vms() {
  limactl list --json | jq -r '.name // empty' | sort
}

gate_specs=(
  'B1|soglia-spike-b1-|run-b1-fresh.sh'
  'B2|soglia-spike-b2-|run-b2-fresh.sh'
  'B3|soglia-spike-b3-|run-b3-fresh.sh'
  'B4|soglia-spike-b4-|run-b4-fresh.sh'
  'B5|soglia-spike-b5-|run-b5-fresh.sh'
  'B6|soglia-spike-b6-|run-b6-fresh.sh'
  'B7|soglia-spike-b7-|run-b7-fresh.sh'
  'B8|soglia-spike-b8-|run-b8-fresh.sh'
  'UNINSTALL|soglia-spike-uninstall-|run-uninstall-fresh.sh'
)

preflight_gate() {
  local gate=$1 gate_slug
  gate_slug=$(printf '%s' "$gate" | tr '[:upper:]' '[:lower:]')
  PYTHONDONTWRITEBYTECODE=1 python3 "$config_preflight" \
    --scripts-root "$repo_dir/spikes/cgroup-bpf/runner/scripts" \
    --validator "$config_validator" --gate "$gate" \
    --json-output "$qualification_dir/$gate_slug-config-preflight.json"
}

if [[ ${SOGLIA_SPIKE_PREFLIGHT_ONLY:-0} == 1 ]]; then
  for spec in "${gate_specs[@]}"; do
    IFS='|' read -r gate _ <<< "$spec"
    preflight_gate "$gate" || {
      echo "$gate: INFRA_ERROR: qualification configuration preflight failed before VM launch" >&2
      exit 13
    }
  done
  echo "Qualification config preflight: PASS ($qualification_dir)"
  exit 0
fi

for spec in "${gate_specs[@]}"; do
  IFS='|' read -r gate vm_prefix runner <<< "$spec"
  before_vms=$(mktemp -t soglia-qualify-before-vms.XXXXXX)
  after_vms=$(mktemp -t soglia-qualify-after-vms.XXXXXX)
  gate_slug=$(printf '%s' "$gate" | tr '[:upper:]' '[:lower:]')
  gate_log="$qualification_dir/$gate_slug.log"
  if ! preflight_gate "$gate"; then
    echo "$gate: INFRA_ERROR: qualification configuration preflight failed before VM launch" >&2
    exit 13
  fi
  snapshot_vms > "$before_vms"

  set +e
  SOGLIA_SPIKE_CLEANUP_VM=1 PYTHONDONTWRITEBYTECODE=1 "$host_dir/$runner" 2>&1 \
    | tee "$gate_log"
  gate_status=${PIPESTATUS[0]}
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

  run_id=$(awk -F= '/^RUN_ID=/{id=$2} END{print id}' "$gate_log")
  run="$evidence_root/$run_id"
  if [[ -z $run_id || ! -d $run ]]; then
    echo "$gate: authoritative runner did not report an existing evidence directory" >&2
    exit 13
  fi
  if ! jq -e --arg gate "$gate" \
    '.authoritative == true and .verdict == "PASS" and .gate == $gate' \
    "$run/summary.json" >/dev/null; then
    echo "$gate: reported evidence is not an authoritative PASS for this gate: $run" >&2
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
