#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Production Candidate-A B5 enforcement-layer and foreign-composition qualification.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
inventory_classifier="$scripts/bpf_inventory_classifier.py"
# shellcheck source=spikes/cgroup-bpf/runner/scripts/bpf-inventory-common.sh
source "$scripts/bpf-inventory-common.sh"

usage='usage: b5-qualification.sh <soglia> <b5-driver> <agent> <attach-diag> <production-object> [--authoritative]'
if [[ $# -ne 5 && $# -ne 6 ]]; then echo "$usage" >&2; exit 13; fi
binary=$1
driver=$2
agent=$3
attach_diag=$4
production_object=$5
authoritative=false
if [[ $# -eq 6 ]]; then
  [[ $6 == --authoritative ]] || { echo "unknown B5 flag: $6" >&2; exit 13; }
  authoritative=true
fi

production_baseline=7dd0840e4d51078c01ab26343c9eebfd315e5e5e
vm_name=${SOGLIA_B5_VM_NAME:-}
if [[ "$authoritative" == true && "$vm_name" != soglia-spike-b5-* ]]; then
  echo "authoritative B5 requires a recorded soglia-spike-b5-* VM name" >&2
  exit 13
fi
if [[ "$authoritative" == true ]]; then run_prefix=b5; else run_prefix=b5-diagnostic; fi
run_id="$run_prefix-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
runtime=/run/soglia-b5
state="$runtime/cgroup-bpf/state.json"
pin_parent=/sys/fs/bpf/soglia-b5
rootfs=/var/tmp/soglia-b5-rootfs
root_unit=soglia-b5-root
driver_unit=soglia-b5-driver
root_cgroup="/sys/fs/cgroup/system.slice/$root_unit.service"
executions="$root_cgroup/executions"
config="$evidence/config.yaml"
current_phase=INITIALIZING
last_case=none
driver_status=255
cleanup_status=NOT_RUN
program_classification=NOT_RUN
links_classification=NOT_RUN
maps_classification=NOT_RUN
unit_cleanup_failed=false
production_source_matches=false
legacy_attached=0
legacy_root=/sys/fs/bpf/soglia-b5-unexpected-legacy
link_pid=
link_stop="$runtime/direct-link.stop"

mkdir -p "$evidence/final" "$runtime"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

persist_state() {
  jq -n --arg run_id "$run_id" --arg phase "$current_phase" --arg last_case "$last_case" \
    --argjson authoritative "$authoritative" \
    '{schema:1,run_id:$run_id,gate:"B5",authoritative:$authoritative,current_phase:$phase,last_case:$last_case}' \
    > "$evidence/state.json"
}

write_summary() {
  local verdict=$1 cases='[]'
  if [[ -d "$evidence/driver/cases" ]]; then
    cases=$(find "$evidence/driver/cases" -mindepth 1 -maxdepth 1 -type d -print0 \
      | sort -z | xargs -0 -r -n1 basename | jq -Rsc 'split("\n") | map(select(length > 0))')
  fi
  jq -n --arg run_id "$run_id" --arg verdict "$verdict" --arg cleanup "$cleanup_status" \
    --arg programs "$program_classification" --arg links "$links_classification" \
    --arg maps "$maps_classification" --arg baseline "$production_baseline" \
    --arg vm_name "$vm_name" --argjson cases "$cases" \
    --argjson authoritative "$authoritative" --argjson driver_status "$driver_status" \
    --argjson production_source_matches "$production_source_matches" \
    '{schema:1,run_id:$run_id,gate:"B5",authoritative:$authoritative,verdict:$verdict,
      driver_status:$driver_status,cases:$cases,
      cleanup:{verdict:$cleanup,programs:$programs,links:$links,maps:$maps},
      production_source_baseline:{commit:$baseline,matches:$production_source_matches},
      scope:{
        proxy_path:"PERFORMED",
        proxy_steering_outside_bpf:"PERFORMED: static production-source audit of candidate_a.c and runtime destination correlation",
        ipv6_stream_sock_create:"PERFORMED",
        ipv4_datagram_sock_create:"PERFORMED",
        ipv6_datagram_sock_create:"PERFORMED",
        connect6_runtime:"NOT_PERFORMED: unreachable by construction because sock_create admits only IPv4/TCP and the socket cgroup is fixed at creation",
        sendmsg4_runtime:"NOT_PERFORMED: unreachable by construction because sock_create admits only IPv4/TCP and the socket cgroup is fixed at creation",
        sendmsg6_runtime:"NOT_PERFORMED: unreachable by construction because sock_create admits only IPv4/TCP and the socket cgroup is fixed at creation",
        direct_ipv4_early_deny:"PERFORMED",
        exact_nft_relaxation:"PERFORMED with trap-backed cleanup",
        no_inherited_sockets:"PERFORMED",
        foreign_ancestor_allow:"PERFORMED",
        foreign_ancestor_rewrite:"PERFORMED without ordering claim",
        unexpected_direct_program_and_link:"PERFORMED and preserved until test-owned release",
        tcp_fastopen_direct:"NOT_PERFORMED: optional B5 extension",
        authoritative_fresh_vm:(if $authoritative then "PERFORMED" else "NOT_PERFORMED: diagnostic phase" end),
        production_code_change:"NOT_PERFORMED: qualification harness only"
      },
      authoritative_vm:(if $authoritative then {name:$vm_name} else null end),
      remaining_gates:{B6:"NOT_EXECUTED",B7:"NOT_EXECUTED"}}' > "$evidence/summary.json"
  printf '%s\n' "$verdict" > "$evidence/verdict.txt"
}

remove_runtime_objects() {
  set +e
  stop_and_prune_unit_cgroup "$driver_unit" "$evidence/final/driver-unit-stop" \
    || unit_cleanup_failed=true
  systemctl reset-failed "$driver_unit.service" >/dev/null 2>&1
  ip link delete b3-upstream >/dev/null 2>&1
  if [[ -f "$state" ]] && jq -e '.pin_root and .links and .maps' "$state" >/dev/null 2>&1; then
    while IFS= read -r pin; do
      case "$pin" in "$pin_parent"/*) [[ ! -e "$pin" ]] || rm "$pin" ;; esac
    done < <(jq -r '.links[].pin, .maps[].pin' "$state")
    owned_root=$(jq -r .pin_root "$state")
    case "$owned_root" in "$pin_parent"/*) rmdir "$owned_root/links" "$owned_root/maps" "$owned_root" 2>/dev/null ;; esac
  fi
  rm -f "$state" "$runtime/cgroup-bpf/.state.json.tmp"
  if [[ -f "$runtime/net/host.json" ]] \
    && [[ $(jq -r .dummy "$runtime/net/host.json" 2>/dev/null) == soglia0 ]]; then
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
  # The caller is the EXIT trap and must finish evidence persistence even when a best-effort
  # deletion above observes that an object is already absent.
  set +e
}

cleanup() {
  set +e
  bpf_inventory_stop_watcher
  current_phase=CLEANUP
  persist_state
  [[ -z "$link_pid" ]] || { touch "$link_stop"; wait "$link_pid" 2>/dev/null; }
  if [[ "$legacy_attached" == 1 ]]; then
    bpftool cgroup detach "$executions" cgroup_inet4_connect pinned "$legacy_root/foreign_allow" >/dev/null 2>&1
  fi
  for pair in \
    /sys/fs/bpf/soglia-b5-foreign-allow/foreign_allow \
    /sys/fs/bpf/soglia-b5-foreign-rewrite/foreign_rewrite; do
    [[ ! -e "$pair" ]] || bpftool cgroup detach "$root_cgroup" cgroup_inet4_connect pinned "$pair" \
      >/dev/null 2>&1
  done
  for root in "$legacy_root" /sys/fs/bpf/soglia-b5-foreign-allow /sys/fs/bpf/soglia-b5-foreign-rewrite; do
    [[ ! -d "$root" ]] || find "$root" -type f -delete 2>/dev/null
    rmdir "$root" 2>/dev/null
  done
  remove_runtime_objects
  stop_and_prune_unit_cgroup "$root_unit" "$evidence/final/root-unit-stop" \
    || unit_cleanup_failed=true
  systemctl reset-failed "$root_unit.service" >/dev/null 2>&1
  : > "$evidence/final/program-settle.jsonl"
  for attempt in $(seq 0 720); do
    bpf_inventory_classify_current "$evidence" "$pin_parent" "$executions" "$inventory_classifier"
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
  [[ "$links_classification" == MATCH && "$maps_classification" == MATCH ]] || cleanup_status=CLEANUP_FAIL
  jq -e 'any(.[]; (.name // "") | startswith("soglia_") or startswith("foreign_"))' \
    "$evidence/final/programs.json" >/dev/null && cleanup_status=CLEANUP_FAIL
  [[ ! -e "$runtime" && ! -e "$pin_parent" && ! -e "$root_cgroup" ]] || cleanup_status=CLEANUP_FAIL
  [[ ! -e /sys/class/net/soglia0 && ! -e /sys/class/net/b3-upstream ]] || cleanup_status=CLEANUP_FAIL
  nft list table inet soglia_host >/dev/null 2>&1 && cleanup_status=CLEANUP_FAIL
  printf '%s\n' "$program_classification" > "$evidence/final/program-classification.txt"
  printf '%s\n' "$cleanup_status" > "$evidence/final/cleanup-verdict.txt"
  set -e
}

on_exit() {
  local status=$?
  [[ ! -f "$evidence/driver/current-case.txt" ]] || last_case=$(tr -d '\n' < "$evidence/driver/current-case.txt")
  cleanup
  if [[ $driver_status -eq 0 && $cleanup_status == PASS && $status -eq 0 ]]; then
    current_phase=COMPLETE; last_case=complete; persist_state; write_summary PASS
  elif [[ $cleanup_status == CLEANUP_FAIL ]]; then
    current_phase=FAILED; persist_state; write_summary CLEANUP_FAIL
  else
    current_phase=FAILED; persist_state; write_summary FAIL
  fi
  (cd "$evidence" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
  cat "$evidence/summary.json"
  trap - EXIT
  [[ $(cat "$evidence/verdict.txt") == PASS ]] || exit 20
}
trap on_exit EXIT
persist_state

jq -n --arg run_id "$run_id" --arg vm_name "$vm_name" --argjson authoritative "$authoritative" \
  '{schema:1,run_id:$run_id,gate:"B5",authoritative:$authoritative,vm_name:$vm_name,started_at:(now|todateiso8601)}' \
  > "$evidence/run.json"
{
  date -u +%FT%T.%NZ; uname -a; cat /etc/os-release; systemd --version | head -1
  bpftool version; nft --version; ip -V; tcpdump --version | head -1; runc --version
  /root/.cargo/bin/rustc +1.97.0 --version --verbose; hostname; cat /etc/machine-id
  cat /proc/sys/kernel/random/boot_id; mount; ulimit -a
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
sha256sum "$binary" "$driver" "$agent" "$attach_diag" "$production_object" > "$evidence/binary-sha256.txt"
bpf_inventory_begin "$evidence" "$pin_parent"
jq -e 'any(.[]; (.name // "") | startswith("soglia_") or startswith("foreign_"))' \
  "$evidence/baseline-programs.json" >/dev/null && { echo "pre-existing B5 BPF object" >&2; exit 30; }

install -d -m 0755 "$rootfs/proc" "$rootfs/dev" "$rootfs/sys" "$rootfs/tmp"
install -m 0755 "$agent" "$rootfs/agent"
systemd-run --unit="$root_unit" --property=Delegate=yes --property=Type=simple sleep infinity \
  > "$evidence/root-systemd-run.txt"
for _ in $(seq 1 200); do [[ -d "$root_cgroup" ]] && break; sleep 0.025; done
mkdir "$executions"

cat > "$config" <<YAML
runtime:
  uid: 65534
  gid: 65534
  state_dir: $runtime
  max_concurrency: 4
  max_queue: 4
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 5000
  runc: /usr/sbin/runc
  nft: /usr/sbin/nft
  ip: /usr/sbin/ip
  bpftool: /usr/sbin/bpftool
ingress:
  listen: 127.0.0.1:18095
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
  root: $root_cgroup
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
  successful-close:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 40000 close /tmp/b3-report.jsonl 2 1"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  fin:
    rootfs: $rootfs
    command: ["/agent", "proxy-connect-report allowed.test:443 40001 fin /tmp/b3-report.jsonl 2 1"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  b5-fd-table:
    rootfs: $rootfs
    command: ["/agent", "b5-probe-report fd_table /tmp/b5-report.json 5"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  b5-ipv6-stream:
    rootfs: $rootfs
    command: ["/agent", "b5-probe-report ipv6_stream /tmp/b5-report.json 5"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  b5-ipv4-datagram:
    rootfs: $rootfs
    command: ["/agent", "b5-probe-report ipv4_datagram /tmp/b5-report.json 5"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  b5-ipv6-datagram:
    rootfs: $rootfs
    command: ["/agent", "b5-probe-report ipv6_datagram /tmp/b5-report.json 5"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  b5-direct-ipv4:
    rootfs: $rootfs
    command: ["/agent", "b5-probe-report direct_ipv4 /tmp/b5-report.json 5"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
  b5-foreign-rewrite:
    rootfs: $rootfs
    command: ["/agent", "b5-probe-report foreign_rewrite /tmp/b5-report.json 5"]
    env: {}
    timeout_ms: 10000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
YAML

# Unexpected legacy direct attachment: startup refuses and preserves the foreign object exactly.
last_case=unexpected_direct_legacy
persist_state
mkdir -p "$evidence/preflight/unexpected-direct-legacy" "$legacy_root"
bpftool prog loadall /var/tmp/soglia-spike-2/bpf/foreign.o "$legacy_root"
bpftool cgroup attach "$executions" cgroup_inet4_connect pinned "$legacy_root/foreign_allow" multi
legacy_attached=1
bpftool -j cgroup show "$executions" > "$evidence/preflight/unexpected-direct-legacy/before.json"
set +e
systemd-run --unit=soglia-b5-unexpected-legacy --property=Type=exec --wait --collect \
  "$binary" run -f "$config" > "$evidence/preflight/unexpected-direct-legacy/systemd-run.txt" 2>&1
legacy_status=$?
set -e
printf '%s\n' "$legacy_status" > "$evidence/preflight/unexpected-direct-legacy/status.txt"
journalctl -u soglia-b5-unexpected-legacy.service --no-pager \
  > "$evidence/preflight/unexpected-direct-legacy/journal.txt"
grep -F 'unrecorded direct BPF attachment(s)' "$evidence/preflight/unexpected-direct-legacy/journal.txt" \
  > "$evidence/preflight/unexpected-direct-legacy/typed-refusal.txt"
bpftool -j cgroup show "$executions" > "$evidence/preflight/unexpected-direct-legacy/after.json"
cmp "$evidence/preflight/unexpected-direct-legacy/before.json" "$evidence/preflight/unexpected-direct-legacy/after.json"
bpftool cgroup detach "$executions" cgroup_inet4_connect pinned "$legacy_root/foreign_allow"
legacy_attached=0
find "$legacy_root" -type f -delete; rmdir "$legacy_root"
systemctl reset-failed soglia-b5-unexpected-legacy.service >/dev/null 2>&1 || true
rm -f "$runtime/lock"
find "$runtime" -depth -type d -empty -delete 2>/dev/null || true
[[ ! -e "$state" && ! -e "$pin_parent" && ! -e /sys/class/net/soglia0 ]]
nft list table inet soglia_host >/dev/null 2>&1 && exit 31
printf '%s\n' PASS > "$evidence/preflight/unexpected-direct-legacy/verdict.txt"

# Unexpected BPF link: the same refusal occurs and the live external link remains until its owner exits.
last_case=unexpected_direct_link
persist_state
link_dir="$evidence/preflight/unexpected-direct-link"
mkdir -p "$link_dir" "$runtime"
link_ready="$runtime/direct-link.ready"
"$attach_diag" "$production_object" "$executions" "$runtime/unused.pin" \
  soglia_connect4 single "$link_ready" "$link_stop" > "$link_dir/loader.stdout" 2> "$link_dir/loader.stderr" &
link_pid=$!
for _ in $(seq 1 400); do [[ -s "$link_ready" ]] && break; sleep 0.025; done
if [[ ! -s "$link_ready" ]]; then
  printf '%s\n' 'attach diagnostic did not publish readiness' > "$link_dir/failure.txt"
  exit 33
fi
jq -e '.status == "ATTACHED"' "$link_ready"
bpftool -j cgroup show "$executions" > "$link_dir/before.json"
bpftool -j link show > "$link_dir/links-before.json"
set +e
systemd-run --unit=soglia-b5-unexpected-link --property=Type=exec --wait --collect \
  "$binary" run -f "$config" > "$link_dir/systemd-run.txt" 2>&1
link_status=$?
set -e
printf '%s\n' "$link_status" > "$link_dir/status.txt"
journalctl -u soglia-b5-unexpected-link.service --no-pager > "$link_dir/journal.txt"
grep -F 'unrecorded direct BPF attachment(s)' "$link_dir/journal.txt" > "$link_dir/typed-refusal.txt"
bpftool -j cgroup show "$executions" > "$link_dir/after.json"
bpftool -j link show > "$link_dir/links-after.json"
cmp "$link_dir/before.json" "$link_dir/after.json"
cmp "$link_dir/links-before.json" "$link_dir/links-after.json"
touch "$link_stop"; wait "$link_pid"; link_pid=
systemctl reset-failed soglia-b5-unexpected-link.service >/dev/null 2>&1 || true
rm -f "$runtime/lock"
find "$runtime" -depth -type d -empty -delete 2>/dev/null || true
[[ ! -e "$state" && ! -e "$pin_parent" && ! -e /sys/class/net/soglia0 ]]
nft list table inet soglia_host >/dev/null 2>&1 && exit 32
printf '%s\n' PASS > "$link_dir/verdict.txt"

current_phase=RUNNING_CASES
last_case=driver
persist_state
set +e
systemd-run --unit="$driver_unit" --property=Type=exec --pipe --wait --collect \
  "$scripts/b5-driver-guard.sh" "$driver" "$binary" "$config" "$evidence/driver" \
  "$evidence/final/production-recovery" > "$evidence/driver-stdout.txt" 2> "$evidence/driver-stderr.txt"
driver_status=$?
set -e
printf '%s\n' "$driver_status" > "$evidence/driver-status.txt"
[[ $driver_status -eq 0 ]]
grep -Fx PASS "$evidence/driver/verdict.txt" >/dev/null
