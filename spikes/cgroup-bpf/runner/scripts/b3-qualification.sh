#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Production Candidate-A B3 qualification. Diagnostic and authoritative runs share the exact
# driver; only the fresh-VM provenance gate differs.

set -euo pipefail

usage='usage: b3-qualification.sh <soglia> <b3-driver> <agent> [--authoritative]'
if [[ $# -ne 3 && $# -ne 4 ]]; then
  echo "$usage" >&2
  exit 13
fi
binary=$1
driver=$2
agent=$3
authoritative=false
if [[ $# -eq 4 ]]; then
  [[ $4 == --authoritative ]] || { echo "unknown B3 flag: $4" >&2; exit 13; }
  authoritative=true
fi

production_baseline=d2a61480f1f771358fd8579ddd4d63191c552f10
vm_name=${SOGLIA_B3_VM_NAME:-}
if [[ "$authoritative" == true && "$vm_name" != soglia-spike-b3-* ]]; then
  echo "authoritative B3 requires a recorded soglia-spike-b3-* VM name" >&2
  exit 13
fi
if [[ "$authoritative" == true ]]; then run_prefix=b3; else run_prefix=b3-diagnostic; fi
run_id="$run_prefix-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
runtime=/run/soglia-b3
state="$runtime/cgroup-bpf/state.json"
pin_parent=/sys/fs/bpf/soglia-b3
rootfs=/var/tmp/soglia-b3-rootfs
unit=soglia-b3
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

mkdir -p "$evidence/final"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

persist_state() {
  jq -n --arg run_id "$run_id" --arg phase "$current_phase" --arg last_case "$last_case" \
    --argjson authoritative "$authoritative" \
    '{schema:1,run_id:$run_id,gate:"B3",authoritative:$authoritative,
      current_phase:$phase,last_case:$last_case}' > "$evidence/state.json"
}

write_summary() {
  local verdict=$1 reuse_scope=NOT_REACHED reuse_reason="driver stopped before reuse scope"
  local synthetic_scope="NOT_REACHED: binding_mismatch_matrix did not complete"
  if [[ -f "$evidence/driver/cases/execution_generation/cgroup-id-reuse-scope.json" ]]; then
    reuse_scope=$(jq -r .actual_reuse "$evidence/driver/cases/execution_generation/cgroup-id-reuse-scope.json")
    reuse_reason=$(jq -r .reason_if_not_performed "$evidence/driver/cases/execution_generation/cgroup-id-reuse-scope.json")
  fi
  if [[ -f "$evidence/driver/cases/binding_mismatch_matrix/verdict.txt" ]] \
    && grep -Fx PASS "$evidence/driver/cases/binding_mismatch_matrix/verdict.txt" >/dev/null; then
    synthetic_scope="PERFORMED in binding_mismatch_matrix"
  fi
  jq -n \
    --arg run_id "$run_id" --arg verdict "$verdict" --arg cleanup "$cleanup_status" \
    --arg programs "$program_classification" --arg links "$links_classification" \
    --arg maps "$maps_classification" --arg baseline "$production_baseline" \
    --arg vm_name "$vm_name" --arg reuse_scope "$reuse_scope" --arg reuse_reason "$reuse_reason" \
    --arg synthetic_scope "$synthetic_scope" \
    --argjson authoritative "$authoritative" --argjson driver_status "$driver_status" \
    --argjson production_source_matches "$production_source_matches" \
    '{schema:1,run_id:$run_id,gate:"B3",authoritative:$authoritative,verdict:$verdict,
      driver_status:$driver_status,
      cleanup:{verdict:$cleanup,programs:$programs,links:$links,maps:$maps},
      production_source_baseline:{commit:$baseline,matches:$production_source_matches},
      scope:{
        actual_cgroup_id_reuse:$reuse_scope,
        actual_cgroup_id_reuse_reason:$reuse_reason,
        synthetic_same_cgroup_stale_nonce:$synthetic_scope,
        supported_platform:"the exact recorded environment fingerprint",
        authoritative_fresh_vm:(if $authoritative then "PERFORMED" else "NOT_PERFORMED: diagnostic phase" end),
        production_code_change:"NOT_PERFORMED: qualification harness only"
      },
      authoritative_vm:(if $authoritative then {name:$vm_name} else null end),
      remaining_gates:{B4:"NOT_EXECUTED",B5:"NOT_EXECUTED",B6:"NOT_EXECUTED",B7:"NOT_EXECUTED"}}' \
    > "$evidence/summary.json"
  printf '%s\n' "$verdict" > "$evidence/verdict.txt"
}

cleanup() {
  set +e
  current_phase=CLEANUP
  persist_state
  systemctl stop "$unit.service" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  ip link delete b3-upstream >/dev/null 2>&1

  # If the driver stopped between lifecycle operations, use the production recovery order and
  # exact durable ownership records to sweep the partial Execution before inspecting residue.
  if find "$runtime/sandbox" -maxdepth 1 -type f -name '*.json' -print -quit 2>/dev/null \
    | grep -q .; then
    systemd-run --unit="$unit" --property=Delegate=yes --property=Type=exec --pipe --wait --collect \
      "$driver" "$binary" "$config" "$evidence/final/production-recovery" --cleanup-recovery \
      > "$evidence/final/production-recovery-stdout.txt" \
      2> "$evidence/final/production-recovery-stderr.txt"
    recovery_status=$?
    printf '%s\n' "$recovery_status" > "$evidence/final/production-recovery-status.txt"
    if [[ $recovery_status -ne 0 ]]; then
      printf 'production cleanup recovery exited %s\n' "$recovery_status" \
        >> "$evidence/final/cleanup-errors.txt"
    fi
  fi
  if [[ -f "$state" ]] && jq -e '.pin_root and .links and .maps' "$state" >/dev/null 2>&1; then
    while IFS= read -r pin; do
      case "$pin" in
        "$pin_parent"/*) [[ ! -e "$pin" ]] || rm "$pin" ;;
        *) printf 'refusing unexpected B3 pin %s\n' "$pin" >> "$evidence/final/cleanup-errors.txt" ;;
      esac
    done < <(jq -r '.links[].pin, .maps[].pin' "$state")
    owned_root=$(jq -r .pin_root "$state")
    case "$owned_root" in
      "$pin_parent"/*) rmdir "$owned_root/links" "$owned_root/maps" "$owned_root" 2>/dev/null ;;
      *) printf 'refusing unexpected B3 root %s\n' "$owned_root" >> "$evidence/final/cleanup-errors.txt" ;;
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
  bpftool -j prog show > "$evidence/final/programs.json"
  bpftool -j link show > "$evidence/final/links.json"
  bpftool -j map show > "$evidence/final/maps.json"
  program_classification=$(jq -nr \
    --slurpfile before "$evidence/baseline-programs.json" \
    --slurpfile after "$evidence/final/programs.json" '
      def inventory($xs): $xs | map({id,name,type,tag}) | sort_by(.name,.type,.tag,.id);
      def signatures($xs): $xs | map({name,type,tag}) | sort_by(.name,.type,.tag);
      def external($xs): $xs | map(select((.name | startswith("sd_")) | not) | {id,name,type,tag})
        | sort_by(.name,.type,.tag,.id);
      if inventory($before[0]) == inventory($after[0]) then "MATCH"
      elif signatures($before[0]) == signatures($after[0]) and external($before[0]) == external($after[0])
      then "EXTERNAL_CHURN" else "FAIL" end')
  jq -S 'sort_by(.id)' "$evidence/baseline-links.json" > "$evidence/final/links-before.normalized.json"
  jq -S 'sort_by(.id)' "$evidence/final/links.json" > "$evidence/final/links-after.normalized.json"
  jq -S 'sort_by(.id)' "$evidence/baseline-maps.json" > "$evidence/final/maps-before.normalized.json"
  jq -S 'sort_by(.id)' "$evidence/final/maps.json" > "$evidence/final/maps-after.normalized.json"
  cleanup_status=PASS
  [[ "$program_classification" == MATCH || "$program_classification" == EXTERNAL_CHURN ]] || cleanup_status=CLEANUP_FAIL
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
  [[ ! -e /sys/class/net/soglia0 && ! -e /sys/class/net/b3-upstream ]] || cleanup_status=CLEANUP_FAIL
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
    # shellcheck disable=SC2094 # SHA256SUMS does not exist until the redirection opens it.
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
  '{schema:1,run_id:$run_id,gate:"B3",authoritative:$authoritative,vm_name:$vm_name,
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
bpftool -j prog show > "$evidence/baseline-programs.json"
bpftool -j link show > "$evidence/baseline-links.json"
bpftool -j map show > "$evidence/baseline-maps.json"
jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' "$evidence/baseline-programs.json" >/dev/null \
  && { echo "pre-existing Soglia BPF program in B3 baseline" >&2; exit 30; }

install -d -m 0755 "$rootfs/proc" "$rootfs/dev" "$rootfs/sys" "$rootfs/tmp"
install -m 0755 "$agent" "$rootfs/agent"
cat > "$config" <<YAML
runtime:
  uid: 65534
  gid: 65534
  state_dir: $runtime
  max_concurrency: 2
  max_queue: 4
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 5000
  runc: /usr/sbin/runc
  nft: /usr/sbin/nft
  ip: /usr/sbin/ip
  bpftool: /usr/sbin/bpftool
ingress:
  listen: 127.0.0.1:18093
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
cgroup:
  root: $cgroup
cgroup_bpf:
  max_tracked_sockets: 128
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: $pin_parent
agents:
  probe:
    rootfs: $rootfs
    command: ["/agent", "netns-cookie"]
    env: {}
    timeout_ms: 10000
  concurrent-0:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-many-report allowed.test:443 40000 4 /tmp/b3-report.jsonl 10"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  concurrent-1:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-many-report allowed.test:443 40000 4 /tmp/b3-report.jsonl 10"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  successful-close:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 41000 close /tmp/b3-report.jsonl 2 1"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  fin:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 41001 fin /tmp/b3-report.jsonl 2 1"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  rst:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 41002 rst /tmp/b3-report.jsonl 2 1"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  connect-failure:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 41003 close /tmp/b3-report.jsonl 2 1"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  agent-kill:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 41004 hold /tmp/b3-report.jsonl 30 1"]
    env: {}
    timeout_ms: 35000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  frozen-teardown:
    rootfs: $rootfs
    command: ["/agent", "sleep 30000"]
    env: {}
    timeout_ms: 35000
  source-reuse:
    rootfs: $rootfs
    command: ["/agent", "proxy-reuse-report allowed.test:443 40000 /tmp/b3-reuse.jsonl 30"]
    env: {}
    timeout_ms: 35000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  execution-generation:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 42000 close /tmp/b3-report.jsonl 2 1"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  binding-matrix:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 43000 close /tmp/b3-report.jsonl 2 1"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  race:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 44000 hold /tmp/b3-report.jsonl 10 1"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  tunnel-revocation:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 45000 hold /tmp/b3-report.jsonl 10 1"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  backend-generation:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 46000 close /tmp/b3-report.jsonl 2 1"]
    env: {}
    timeout_ms: 15000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
YAML

current_phase=RUNNING_CASES
persist_state
set +e
systemd-run --unit="$unit" --property=Delegate=yes --property=Type=exec --pipe --wait --collect \
  "$driver" "$binary" "$config" "$evidence/driver" \
  > "$evidence/driver-stdout.txt" 2> "$evidence/driver-stderr.txt"
driver_status=$?
set -e
printf '%s\n' "$driver_status" > "$evidence/driver-status.txt"
[[ $driver_status -eq 0 ]]
grep -Fx PASS "$evidence/driver/verdict.txt" >/dev/null
