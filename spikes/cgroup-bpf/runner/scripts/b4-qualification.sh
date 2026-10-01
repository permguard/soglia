#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Production Candidate-A B4 capacity and publication qualification.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
inventory_classifier="$scripts/bpf_inventory_classifier.py"
# shellcheck source=spikes/cgroup-bpf/runner/scripts/bpf-inventory-common.sh
source "$scripts/bpf-inventory-common.sh"

usage='usage: b4-qualification.sh <soglia> <b4-driver> <agent> [--authoritative]'
if [[ $# -ne 3 && $# -ne 4 ]]; then
  echo "$usage" >&2
  exit 13
fi
binary=$1
driver=$2
agent=$3
authoritative=false
if [[ $# -eq 4 ]]; then
  [[ $4 == --authoritative ]] || { echo "unknown B4 flag: $4" >&2; exit 13; }
  authoritative=true
fi

production_baseline=db6e1ac21a957b5fd8de96f5e3a719db1d897723
vm_name=${SOGLIA_B4_VM_NAME:-}
if [[ "$authoritative" == true && "$vm_name" != soglia-spike-b4-* ]]; then
  echo "authoritative B4 requires a recorded soglia-spike-b4-* VM name" >&2
  exit 13
fi
if [[ "$authoritative" == true ]]; then run_prefix=b4; else run_prefix=b4-diagnostic; fi
run_id="$run_prefix-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
runtime=/run/soglia-b4
state="$runtime/cgroup-bpf/state.json"
pin_parent=/sys/fs/bpf/soglia-b4
rootfs=/var/tmp/soglia-b4-rootfs
unit=soglia-b4
cgroup="/sys/fs/cgroup/system.slice/$unit.service"
config="$evidence/config.yaml"
current_phase=INITIALIZING
last_case=none
driver_status=255
cleanup_status=NOT_RUN
program_classification=NOT_RUN
links_classification=NOT_RUN
maps_classification=NOT_RUN
production_source_matches=false
unit_cleanup_failed=false

mkdir -p "$evidence/final"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

persist_state() {
  jq -n --arg run_id "$run_id" --arg phase "$current_phase" --arg last_case "$last_case" \
    --argjson authoritative "$authoritative" \
    '{schema:1,run_id:$run_id,gate:"B4",authoritative:$authoritative,
      current_phase:$phase,last_case:$last_case}' > "$evidence/state.json"
}

write_summary() {
  local verdict=$1 cases='[]'
  if [[ -d "$evidence/driver/cases" ]]; then
    cases=$(find "$evidence/driver/cases" -mindepth 1 -maxdepth 1 -type d -print0 \
      | sort -z | xargs -0 -r -n1 basename \
      | jq -Rsc 'split("\n") | map(select(length > 0))')
  fi
  jq -n \
    --arg run_id "$run_id" --arg verdict "$verdict" --arg cleanup "$cleanup_status" \
    --arg programs "$program_classification" --arg links "$links_classification" \
    --arg maps "$maps_classification" --arg baseline "$production_baseline" \
    --arg vm_name "$vm_name" --argjson cases "$cases" \
    --argjson authoritative "$authoritative" --argjson driver_status "$driver_status" \
    --argjson production_source_matches "$production_source_matches" \
    '{schema:1,run_id:$run_id,gate:"B4",authoritative:$authoritative,verdict:$verdict,
      driver_status:$driver_status,cases:$cases,
      cleanup:{verdict:$cleanup,programs:$programs,links:$links,maps:$maps},
      production_source_baseline:{commit:$baseline,matches:$production_source_matches},
      capacity_contract:{max_tracked_sockets:4,policy_capacity:3,ring_buffer_bytes:4096,
        max_concurrency:2,max_queue:0,resolve_timeout_ms:2000},
      scope:{
        production_bpf_object:"PERFORMED: unchanged embedded production object",
        capacity_and_publication_fail_closed:"PERFORMED",
        event_ring_overflow:"PERFORMED without production modification",
        supported_platform:"the exact recorded environment fingerprint",
        authoritative_fresh_vm:(if $authoritative then "PERFORMED" else "NOT_PERFORMED: diagnostic phase" end),
        production_code_change:"NOT_PERFORMED: qualification harness only"
      },
      authoritative_vm:(if $authoritative then {name:$vm_name} else null end),
      remaining_gates:{B5:"NOT_EXECUTED",B6:"NOT_EXECUTED",B7:"NOT_EXECUTED"}}' \
    > "$evidence/summary.json"
  printf '%s\n' "$verdict" > "$evidence/verdict.txt"
}

cleanup() {
  set +e
  bpf_inventory_stop_watcher
  current_phase=CLEANUP
  persist_state
  stop_and_prune_unit_cgroup "$unit" "$evidence/final/unit-stop" || unit_cleanup_failed=true
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  ip link delete b4-upstream >/dev/null 2>&1

  if [[ -f "$state" ]] && jq -e '.pin_root and .links and .maps' "$state" >/dev/null 2>&1; then
    while IFS= read -r pin; do
      case "$pin" in
        "$pin_parent"/*) [[ ! -e "$pin" ]] || rm "$pin" ;;
        *) printf 'refusing unexpected B4 pin %s\n' "$pin" >> "$evidence/final/cleanup-errors.txt" ;;
      esac
    done < <(jq -r '.links[].pin, .maps[].pin' "$state")
    owned_root=$(jq -r .pin_root "$state")
    case "$owned_root" in
      "$pin_parent"/*) rmdir "$owned_root/links" "$owned_root/maps" "$owned_root" 2>/dev/null ;;
      *) printf 'refusing unexpected B4 root %s\n' "$owned_root" >> "$evidence/final/cleanup-errors.txt" ;;
    esac
  fi
  rm -f "$state" "$runtime/cgroup-bpf/.state.json.tmp"
  if [[ -f "$runtime/net/host.json" ]] \
    && [[ $(jq -r .dummy "$runtime/net/host.json" 2>/dev/null) == soglia0 ]] \
    && [[ $(jq -r .proxy_address "$runtime/net/host.json" 2>/dev/null) == 10.200.255.1 ]]; then
    nft delete table inet soglia_host >/dev/null 2>&1
    ip link delete soglia0 >/dev/null 2>&1
    rm -f "$runtime/net/host.json"
  fi
  rm -f "$runtime/lock"
  find "$runtime" -depth -type d -empty -delete 2>/dev/null
  rmdir "$pin_parent" 2>/dev/null
  if [[ -d "$rootfs" ]]; then
    find "$rootfs" -depth -mindepth 1 -delete 2>/dev/null
    rmdir "$rootfs" 2>/dev/null
  fi

  : > "$evidence/final/program-settle.jsonl"
  for attempt in $(seq 0 720); do
    bpf_inventory_classify_current "$evidence" "$pin_parent" "$cgroup" "$inventory_classifier"
    program_classification=$BPF_PROGRAM_CLASSIFICATION
    jq -cn --argjson attempt "$attempt" --arg classification "$program_classification" \
      --argjson programs "$(jq 'length' "$evidence/final/programs.json")" \
      '{attempt:$attempt,classification:$classification,program_count:$programs}' \
      >> "$evidence/final/program-settle.jsonl"
    if bpf_inventory_is_clean "$program_classification"; then
      break
    fi
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
  [[ "$links_classification" == MATCH ]] || cleanup_status=CLEANUP_FAIL
  [[ "$maps_classification" == MATCH ]] || cleanup_status=CLEANUP_FAIL
  jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' "$evidence/final/programs.json" >/dev/null \
    && cleanup_status=CLEANUP_FAIL
  jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' "$evidence/final/maps.json" >/dev/null \
    && cleanup_status=CLEANUP_FAIL
  [[ ! -e "$runtime" && ! -e "$pin_parent" && ! -e "$cgroup" ]] || cleanup_status=CLEANUP_FAIL
  [[ ! -e /sys/class/net/soglia0 && ! -e /sys/class/net/b4-upstream ]] || cleanup_status=CLEANUP_FAIL
  nft list table inet soglia_host >/dev/null 2>&1 && cleanup_status=CLEANUP_FAIL
  printf '%s\n' "$program_classification" > "$evidence/final/program-classification.txt"
  printf '%s\n' "$cleanup_status" > "$evidence/final/cleanup-verdict.txt"
  set -e
}

on_exit() {
  local status=$?
  if [[ -f "$evidence/driver/current-case.txt" ]]; then
    last_case=$(tr -d '\n' < "$evidence/driver/current-case.txt")
  fi
  cleanup
  if [[ $driver_status -eq 0 && $cleanup_status == PASS && $status -eq 0 ]]; then
    current_phase=COMPLETE; last_case=complete; persist_state; write_summary PASS
  elif [[ $cleanup_status == CLEANUP_FAIL ]]; then
    current_phase=FAILED; persist_state; write_summary CLEANUP_FAIL
  else
    current_phase=FAILED; persist_state; write_summary FAIL
  fi
  (
    cd "$evidence"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  )
  printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
  cat "$evidence/summary.json"
  trap - EXIT
  [[ $(cat "$evidence/verdict.txt") == PASS ]] || exit 20
}
trap on_exit EXIT
persist_state

jq -n --arg run_id "$run_id" --arg vm_name "$vm_name" --argjson authoritative "$authoritative" \
  '{schema:1,run_id:$run_id,gate:"B4",authoritative:$authoritative,vm_name:$vm_name,
    started_at:(now|todateiso8601)}' > "$evidence/run.json"
{
  date -u +%FT%T.%NZ
  uname -a
  cat /etc/os-release
  systemd --version | head -1
  bpftool version
  nft --version
  ip -V
  runc --version
  /root/.cargo/bin/rustc +1.97.0 --version --verbose
  hostname
  cat /etc/machine-id
  cat /proc/sys/kernel/random/boot_id
  mount
  ulimit -a
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
sha256sum "$binary" "$driver" "$agent" > "$evidence/binary-sha256.txt"
bpf_inventory_begin "$evidence" "$pin_parent"
jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' "$evidence/baseline-programs.json" >/dev/null \
  && { echo "pre-existing Soglia BPF program in B4 baseline" >&2; exit 30; }

install -d -m 0755 "$rootfs/proc" "$rootfs/dev" "$rootfs/sys" "$rootfs/tmp"
install -m 0755 "$agent" "$rootfs/agent"
cat > "$config" <<YAML
runtime:
  uid: 65534
  gid: 65534
  state_dir: $runtime
  max_concurrency: 2
  max_queue: 0
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 5000
  runc: /usr/sbin/runc
  nft: /usr/sbin/nft
  ip: /usr/sbin/ip
  bpftool: /usr/sbin/bpftool
ingress:
  listen: 127.0.0.1:18094
network:
  backend: cgroup-bpf
  execution_pool: 10.201.0.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
egress:
  connect_timeout_ms: 1000
  idle_timeout_ms: 2000
  allow:
    - { host: allowed.test, ports: [443] }
    - { host: 11.0.0.1, ports: [443] }
cgroup:
  root: $cgroup
cgroup_bpf:
  max_tracked_sockets: 4
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 4096
  pin_root: $pin_parent
agents:
  admission:
    rootfs: $rootfs
    command: ["/agent", "serve"]
    env: { AGENT_PORT: "8080" }
    timeout_ms: 10000
  control:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 47000 close /tmp/b4-report.jsonl 2 1"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  cookie-capacity:
    rootfs: $rootfs
    command: ["/agent", "proxy-capacity-report allowed.test:443 40000 4 /tmp/b4-capacity.jsonl 30"]
    env: {}
    timeout_ms: 40000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  duplicate-cookie:
    rootfs: $rootfs
    command: ["/agent", "proxy-preconnect-report allowed.test:443 41000 /tmp/b4-preconnect.jsonl 30"]
    env: {}
    timeout_ms: 40000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  tuple-full:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 42000 close /tmp/b4-report.jsonl 4 1"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  duplicate-tuple:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 42001 close /tmp/b4-report.jsonl 4 1"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  delayed:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 42002 close /tmp/b4-report.jsonl 4 1"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  missing:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 42003 close /tmp/b4-report.jsonl 4 1"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  queue:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-many-report allowed.test:443 43000 3 /tmp/b4-report.jsonl 4"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  ring:
    rootfs: $rootfs
    command: ["/agent", "direct-flood-report 10.200.255.1:15002 256 /tmp/b4-ring.json 5"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
YAML

current_phase=RUNNING_CASES
persist_state
set +e
systemd-run --unit="$unit" --property=Delegate=yes --property=Type=exec --pipe --wait --collect \
  /soglia/spikes/cgroup-bpf/runner/scripts/b4-driver-guard.sh \
  "$driver" "$binary" "$config" "$evidence/driver" "$evidence/final/production-recovery" \
  > "$evidence/driver-stdout.txt" 2> "$evidence/driver-stderr.txt"
driver_status=$?
set -e
printf '%s\n' "$driver_status" > "$evidence/driver-status.txt"
[[ $driver_status -eq 0 ]]
grep -Fx PASS "$evidence/driver/verdict.txt" >/dev/null
