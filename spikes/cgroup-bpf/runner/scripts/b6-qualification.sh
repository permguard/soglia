#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Production Candidate-A B6 loss, recovery and readiness qualification.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
inventory_classifier="$scripts/bpf_inventory_classifier.py"
# shellcheck source=spikes/cgroup-bpf/runner/scripts/bpf-inventory-common.sh
source "$scripts/bpf-inventory-common.sh"

usage='usage: b6-qualification.sh <soglia> <b6-driver> <b6-trace> <agent> <link-injector-source> [--authoritative]'
if [[ $# -ne 5 && $# -ne 6 ]]; then echo "$usage" >&2; exit 13; fi
binary=$1
driver=$2
tracer=$3
agent=$4
injector_source=$5
authoritative=false
if [[ $# -eq 6 ]]; then
  [[ $6 == --authoritative ]] || { echo "unknown B6 flag: $6" >&2; exit 13; }
  authoritative=true
fi

# Updated after the production recovery follow-up is committed.
production_baseline=2ce2b1a95f1504de142ee58d0289146d1675a6a2
vm_name=${SOGLIA_B6_VM_NAME:-}
if [[ "$authoritative" == true && "$vm_name" != soglia-spike-b6-* ]]; then
  echo "authoritative B6 requires a recorded soglia-spike-b6-* VM name" >&2
  exit 13
fi
if [[ "$authoritative" == true ]]; then run_prefix=b6; else run_prefix=b6-diagnostic; fi
run_id="$run_prefix-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
injector=/var/tmp/soglia-b6-link-injector
current_phase=INITIALIZING
last_case=none
cleanup_status=NOT_RUN
program_classification=NOT_RUN
links_classification=NOT_RUN
maps_classification=NOT_RUN
unit_cleanup_failed=false
production_source_matches=false

mkdir -p "$evidence/final"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

persist_state() {
  jq -n --arg run_id "$run_id" --arg phase "$current_phase" --arg last_case "$last_case" \
    --argjson authoritative "$authoritative" \
    '{schema:1,run_id:$run_id,gate:"B6",authoritative:$authoritative,
      current_phase:$phase,last_case:$last_case}' > "$evidence/state.json"
}

write_summary() {
  local verdict=$1
  local passed
  passed=$(find "$evidence/cases" -name verdict.txt -type f -print0 2>/dev/null \
    | sort -z | xargs -0 -r grep -l -x PASS | wc -l | tr -d ' ')
  jq -n --arg run_id "$run_id" --arg verdict "$verdict" --arg cleanup "$cleanup_status" \
    --arg programs "$program_classification" --arg links "$links_classification" \
    --arg maps "$maps_classification" --arg baseline "$production_baseline" \
    --arg vm_name "$vm_name" --argjson passed "${passed:-0}" \
    --argjson authoritative "$authoritative" \
    --argjson production_source_matches "$production_source_matches" \
    '{schema:1,run_id:$run_id,gate:"B6",authoritative:$authoritative,verdict:$verdict,
      cases_with_pass_verdict:$passed,
      cleanup:{verdict:$cleanup,programs:$programs,links:$links,maps:$maps},
      production_source_baseline:{commit:$baseline,matches:$production_source_matches},
      scope:{
        admission_before_ready:"PERFORMED with deterministic ptrace listen boundary",
        host_s13_boundaries:"PERFORMED: 4 of 4",
        execution_s13_boundaries:"PERFORMED: 9 of 9",
        recovery_interrupted:"PERFORMED",
        process_loss:"PERFORMED: Enforcer, Supervisor, Sandbox and Resolve watchdog",
        sandbox_staged_lifecycle:"PERFORMED: one frozen Execution and one runc-created-not-started Execution",
        typed_refusal_matrix:"PERFORMED: 4 Incompatible and 9 Unknown single-fault cases",
        target_released_negative:"PERFORMED: live link, mixed links, non-empty target, target outside unit",
        repeated_systemd_refusal:"PERFORMED with Restart=on-failure",
        cgroup_id_reuse:"NOT_PERFORMED: B3 records that the environment cannot force 64-bit cgroup-ID reuse",
        authoritative_fresh_vm:(if $authoritative then "PERFORMED" else "NOT_PERFORMED: diagnostic phase" end),
        production_code_change:"NOT_PERFORMED by qualification harness"
      },
      authoritative_vm:(if $authoritative then {name:$vm_name} else null end),
      remaining_gates:{B7:"NOT_EXECUTED"}}' > "$evidence/summary.json"
  printf '%s\n' "$verdict" > "$evidence/verdict.txt"
}

cleanup() {
  set +e
  bpf_inventory_stop_watcher
  current_phase=CLEANUP
  persist_state
  rm -f "$injector"
  for unit in $(systemctl list-units --all --plain --no-legend 'soglia-b6-*.service' \
    | awk '{print $1}'); do
    unit_slug=${unit%.service}
    stop_and_prune_unit_cgroup "$unit" "$evidence/final/unit-stops/$unit_slug" \
      || unit_cleanup_failed=true
    systemctl reset-failed "$unit" >/dev/null 2>&1
  done
  : > "$evidence/final/program-settle.jsonl"
  for attempt in $(seq 0 720); do
    bpf_inventory_classify_current "$evidence" /sys/fs/bpf/soglia-b6 \
      /sys/fs/cgroup/system.slice/soglia-b6.service "$inventory_classifier"
    program_classification=$BPF_PROGRAM_CLASSIFICATION
    jq -cn --argjson attempt "$attempt" --arg classification "$program_classification" \
      --argjson programs "$(jq 'length' "$evidence/final/programs.json")" \
      '{attempt:$attempt,classification:$classification,program_count:$programs}' \
      >> "$evidence/final/program-settle.jsonl"
    bpf_inventory_is_clean "$program_classification" && break
    sleep 0.25
  done
  bpftool -j map show > "$evidence/final/maps.json"
  jq -S 'sort_by(.id)' "$evidence/baseline-links.json" > "$evidence/final/links-before.normalized.json"
  jq -S 'sort_by(.id)' "$evidence/final/links.json" > "$evidence/final/links-after.normalized.json"
  jq -S 'sort_by(.id)' "$evidence/baseline-maps.json" > "$evidence/final/maps-before.normalized.json"
  jq -S 'sort_by(.id)' "$evidence/final/maps.json" > "$evidence/final/maps-after.normalized.json"
  cleanup_status=PASS
  [[ $unit_cleanup_failed == false ]] || cleanup_status=CLEANUP_FAIL
  bpf_inventory_is_clean "$program_classification" || cleanup_status=CLEANUP_FAIL
  cmp -s "$evidence/final/links-before.normalized.json" "$evidence/final/links-after.normalized.json" \
    && links_classification=MATCH || links_classification=FAIL
  cmp -s "$evidence/final/maps-before.normalized.json" "$evidence/final/maps-after.normalized.json" \
    && maps_classification=MATCH || maps_classification=FAIL
  [[ "$links_classification" == MATCH && "$maps_classification" == MATCH ]] \
    || cleanup_status=CLEANUP_FAIL
  jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
    "$evidence/final/programs.json" >/dev/null && cleanup_status=CLEANUP_FAIL
  find /run /sys/fs/bpf /sys/fs/cgroup/system.slice /var/tmp -maxdepth 1 \
    -name 'soglia-b6-*' -print > "$evidence/final/owned-path-residue.txt" 2>/dev/null
  [[ ! -s "$evidence/final/owned-path-residue.txt" ]] || cleanup_status=CLEANUP_FAIL
  ip netns list | grep '^soglia-' > "$evidence/final/netns-residue.txt" || true
  ip -o link show | grep -E 'sgh-|soglia0' > "$evidence/final/link-residue.txt" || true
  nft list tables | grep 'soglia' > "$evidence/final/nft-residue.txt" || true
  [[ ! -s "$evidence/final/netns-residue.txt" && ! -s "$evidence/final/link-residue.txt" \
    && ! -s "$evidence/final/nft-residue.txt" ]] || cleanup_status=CLEANUP_FAIL
  printf '%s\n' "$program_classification" > "$evidence/final/program-classification.txt"
  printf '%s\n' "$cleanup_status" > "$evidence/final/cleanup-verdict.txt"
  set -e
}

on_exit() {
  status=$?
  cleanup
  if [[ $status -eq 0 && $cleanup_status == PASS ]]; then
    current_phase=COMPLETE; last_case=complete; persist_state; write_summary PASS
  elif [[ $cleanup_status == CLEANUP_FAIL ]]; then
    current_phase=FAILED; persist_state; write_summary CLEANUP_FAIL
  else
    current_phase=FAILED; persist_state; write_summary FAIL
  fi
  (cd "$evidence" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS)
  printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
  cat "$evidence/summary.json"
  trap - EXIT
  [[ $(cat "$evidence/verdict.txt") == PASS ]] || exit 20
}
trap on_exit EXIT
persist_state

jq -n --arg run_id "$run_id" --arg vm_name "$vm_name" --argjson authoritative "$authoritative" \
  '{schema:1,run_id:$run_id,gate:"B6",authoritative:$authoritative,
    vm_name:$vm_name,started_at:(now|todateiso8601)}' > "$evidence/run.json"
{
  date -u +%FT%T.%NZ; uname -a; cat /etc/os-release; systemd --version | head -1
  bpftool version; nft --version; ip -V; runc --version
  /root/.cargo/bin/rustc +1.97.0 --version --verbose; hostname; cat /etc/machine-id
  cat /proc/sys/kernel/random/boot_id; cat /proc/sys/kernel/yama/ptrace_scope; mount; ulimit -a
} > "$evidence/environment.txt"
{
  git -C /soglia rev-parse HEAD
  git -C /soglia status --short --untracked-files=all
  git -C /soglia diff --binary -- . ':!spikes/cgroup-bpf/evidence' | sha256sum
  cd /soglia
  find Cargo.toml Cargo.lock src crates spikes/cgroup-bpf/agent spikes/cgroup-bpf/runner \
    -type f ! -path '*/target/*' ! -path '*/evidence/*' -print0 | sort -z | xargs -0 sha256sum
} > "$evidence/source-fingerprint.txt"
git -C /soglia cat-file -e "$production_baseline^{commit}"
git -C /soglia diff --exit-code "$production_baseline" -- crates src Cargo.toml Cargo.lock
[[ -z $(git -C /soglia status --short --untracked-files=all -- crates src Cargo.toml Cargo.lock) ]]
production_source_matches=true
cc -O2 -Wall -Wextra -Werror -o "$injector" "$injector_source"
sha256sum "$binary" "$driver" "$tracer" "$agent" "$injector" > "$evidence/binary-sha256.txt"
bpf_inventory_begin "$evidence" /sys/fs/bpf/soglia-b6
jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
  "$evidence/baseline-programs.json" >/dev/null && { echo 'pre-existing B6 BPF object' >&2; exit 30; }

mkdir -p "$evidence/cases"
run_case() {
  last_case=$1
  current_phase=RUNNING
  persist_state
  shift
  "$@"
}

run_case admission_before_ready bash "$scripts/b6-admission-before-ready.sh" \
  "$binary" "$tracer" "$agent" "$evidence/cases/admission_before_ready"
run_case systemd_boundaries bash "$scripts/b6-systemd-boundaries.sh" \
  "$binary" "$driver" "$tracer" "$agent" "$evidence/cases/systemd_boundaries"
run_case recovery_interrupted bash "$scripts/b6-recovery-interrupted.sh" \
  "$binary" "$driver" "$tracer" "$agent" "$evidence/cases/recovery_interrupted"

for loss in enforcer_sigkill supervisor_sigkill sandbox_sigkill resolve_channel_watchdog; do
  if [[ $loss == sandbox_sigkill ]]; then
    run_case "$loss" env B6_TARGET_OFFLINE_PAGE_CACHE_MB=512 \
      bash "$scripts/b6-systemd-loss.sh" \
      "$binary" "$agent" "$loss" "$evidence/cases/$loss"
  else
    run_case "$loss" bash "$scripts/b6-systemd-loss.sh" \
      "$binary" "$agent" "$loss" "$evidence/cases/$loss"
  fi
done

run_case refusal_matrix bash "$scripts/b6-refusal-matrix.sh" \
  "$binary" "$agent" "$evidence/cases/refusal_matrix"

for negative in link_still_attached mixed_links nonempty_target target_outside_unit; do
  run_case "target_released_$negative" bash "$scripts/b6-target-released-negative.sh" \
    "$binary" "$agent" "$injector" "$driver" "$negative" \
    "$evidence/cases/target_released_$negative"
done

current_phase=VERIFYING
last_case=complete
persist_state
find "$evidence/cases" -name verdict.txt -type f -print0 | xargs -0 -r -n1 grep -H -x PASS \
  > "$evidence/case-verdicts.txt"
