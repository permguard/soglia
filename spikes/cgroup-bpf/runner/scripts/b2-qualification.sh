#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Diagnostic B2 qualification, with a focused production-cleanup probe mode used before rerunning
# B1. It deliberately refuses an authoritative mode: the harness must be reviewed and committed
# before a fresh-VM authoritative B2 run exists.

set -euo pipefail

binary="${1:?usage: b2-qualification.sh <soglia> <b2-driver> <agent>}"
driver="${2:?usage: b2-qualification.sh <soglia> <b2-driver> <agent>}"
agent="${3:?usage: b2-qualification.sh <soglia> <b2-driver> <agent>}"
if [[ $# -ne 3 ]]; then
  echo "B2 diagnostic accepts no authoritative flag" >&2
  exit 13
fi

mode=${SOGLIA_B2_MODE:-b2}
case "$mode" in
  b2)
    gate=B2
    run_prefix=b2-diagnostic
    driver_extra=()
    ;;
  cleanup-probe)
    gate=CGROUP_BPF_CLEANUP_PROBE
    run_prefix=cgroup-bpf-cleanup-probe
    driver_extra=(--cleanup-probe)
    ;;
  *)
    echo "unknown B2 diagnostic mode: $mode" >&2
    exit 13
    ;;
esac

run_id="$run_prefix-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
runtime=/run/soglia-b2
state="$runtime/cgroup-bpf/state.json"
pin_parent=/sys/fs/bpf/soglia-b2
rootfs=/var/tmp/soglia-b2-rootfs
unit=soglia-b2
cgroup="/sys/fs/cgroup/system.slice/$unit.service"
config="$evidence/config.yaml"
current_phase=INITIALIZING
last_case=none
driver_status=255
cleanup_status=NOT_RUN
program_classification=NOT_RUN
links_classification=NOT_RUN
maps_classification=NOT_RUN

mkdir -p "$evidence/final"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

persist_state() {
  jq -n --arg run_id "$run_id" --arg phase "$current_phase" --arg last_case "$last_case" \
    --arg gate "$gate" \
    '{schema:1,run_id:$run_id,gate:$gate,authoritative:false,current_phase:$phase,last_case:$last_case}' \
    > "$evidence/state.json"
}

write_summary() {
  local verdict=$1
  jq -n \
    --arg run_id "$run_id" \
    --arg gate "$gate" \
    --arg verdict "$verdict" \
    --arg cleanup "$cleanup_status" \
    --arg programs "$program_classification" \
    --arg links "$links_classification" \
    --arg maps "$maps_classification" \
    --argjson driver_status "$driver_status" \
    '{schema:1,run_id:$run_id,gate:$gate,authoritative:false,verdict:$verdict,
      driver_status:$driver_status,
      cleanup:{verdict:$cleanup,programs:$programs,links:$links,maps:$maps},
      scope:{
        supported_platform:"the exact recorded diagnostic environment fingerprint",
        authoritative_fresh_vm:"NOT_PERFORMED: diagnostic phase only",
        production_code_change:"NOT_PERFORMED: qualification harness only",
        helper_loss_cancellation:"NOT_PERFORMED: belongs to B6",
        concurrency_and_identity_reuse:"NOT_PERFORMED: belongs to B3",
        capacity_exhaustion:"NOT_PERFORMED: belongs to B4",
        tuple_disappears_during_sweep:
          "NOT_PERFORMED: deterministic privileged race injection is unavailable; ENOENT classification is unit-tested"
      },
      remaining_gates:{B3:"NOT_EXECUTED",B4:"NOT_EXECUTED",B5:"NOT_EXECUTED",
        B6:"NOT_EXECUTED",B7:"NOT_EXECUTED"}}' > "$evidence/summary.json"
  printf '%s\n' "$verdict" > "$evidence/verdict.txt"
}

cleanup() {
  set +e
  current_phase=CLEANUP
  persist_state
  systemctl stop "$unit.service" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  ip link delete b2-upstream >/dev/null 2>&1

  if [[ -f "$state" ]] && jq -e '.pin_root and .links and .maps' "$state" >/dev/null 2>&1; then
    while IFS= read -r pin; do
      case "$pin" in
        "$pin_parent"/*) [[ ! -e "$pin" ]] || rm "$pin" ;;
        *) printf 'refusing unexpected B2 pin %s\n' "$pin" >> "$evidence/final/cleanup-errors.txt" ;;
      esac
    done < <(jq -r '.links[].pin, .maps[].pin' "$state")
    owned_root=$(jq -r .pin_root "$state")
    case "$owned_root" in
      "$pin_parent"/*) rmdir "$owned_root/links" "$owned_root/maps" "$owned_root" 2>/dev/null ;;
      *) printf 'refusing unexpected B2 root %s\n' "$owned_root" >> "$evidence/final/cleanup-errors.txt" ;;
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
    def inventory($xs):
      $xs | map({id,name,type,tag}) | sort_by(.name,.type,.tag,.id);
    def signatures($xs):
      $xs | map({name,type,tag}) | sort_by(.name,.type,.tag);
    def non_systemd($xs):
      $xs | map(select((.name | startswith("sd_")) | not) | {id,name,type,tag})
          | sort_by(.name,.type,.tag,.id);
    if inventory($before[0]) == inventory($after[0]) then "MATCH"
    elif signatures($before[0]) == signatures($after[0])
      and non_systemd($before[0]) == non_systemd($after[0])
    then "EXTERNAL_CHURN"
    else "FAIL"
    end')
  printf '%s\n' "$program_classification" > "$evidence/final/program-classification.txt"
  jq -S 'sort_by(.id)' "$evidence/baseline-links.json" \
    > "$evidence/final/links-before.normalized.json"
  jq -S 'sort_by(.id)' "$evidence/final/links.json" \
    > "$evidence/final/links-after.normalized.json"
  jq -S 'sort_by(.id)' "$evidence/baseline-maps.json" \
    > "$evidence/final/maps-before.normalized.json"
  jq -S 'sort_by(.id)' "$evidence/final/maps.json" \
    > "$evidence/final/maps-after.normalized.json"

  cleanup_status=PASS
  [[ "$program_classification" == MATCH || "$program_classification" == EXTERNAL_CHURN ]] \
    || cleanup_status=CLEANUP_FAIL
  cmp -s "$evidence/final/links-before.normalized.json" \
    "$evidence/final/links-after.normalized.json" \
    && links_classification=MATCH || links_classification=FAIL
  cmp -s "$evidence/final/maps-before.normalized.json" \
    "$evidence/final/maps-after.normalized.json" \
    && maps_classification=MATCH || maps_classification=FAIL
  [[ "$links_classification" == MATCH ]] || cleanup_status=CLEANUP_FAIL
  [[ "$maps_classification" == MATCH ]] || cleanup_status=CLEANUP_FAIL
  jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
    "$evidence/final/programs.json" >/dev/null && cleanup_status=CLEANUP_FAIL
  jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
    "$evidence/final/maps.json" >/dev/null && cleanup_status=CLEANUP_FAIL
  [[ ! -e "$runtime" ]] || cleanup_status=CLEANUP_FAIL
  [[ ! -e "$pin_parent" ]] || cleanup_status=CLEANUP_FAIL
  [[ ! -e "$cgroup" ]] || cleanup_status=CLEANUP_FAIL
  [[ ! -e /sys/class/net/soglia0 ]] || cleanup_status=CLEANUP_FAIL
  [[ ! -e /sys/class/net/b2-upstream ]] || cleanup_status=CLEANUP_FAIL
  nft list table inet soglia_host >/dev/null 2>&1 && cleanup_status=CLEANUP_FAIL
  printf '%s\n' "$cleanup_status" > "$evidence/final/cleanup-verdict.txt"
  set -e
}

on_exit() {
  local status=$?
  if [[ -f "$evidence/driver/current-case.txt" ]]; then
    last_case=$(tr -d '\n' < "$evidence/driver/current-case.txt")
  fi
  cleanup
  if [[ "$driver_status" -eq 0 && "$cleanup_status" == PASS && "$status" -eq 0 ]]; then
    current_phase=COMPLETE
    last_case=complete
    persist_state
    write_summary PASS
  else
    current_phase=FAILED
    persist_state
    if [[ "$cleanup_status" == CLEANUP_FAIL ]]; then write_summary CLEANUP_FAIL; else write_summary FAIL; fi
  fi
  (
    cd "$evidence"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  )
  printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
  cat "$evidence/summary.json"
  trap - EXIT
  if [[ $(cat "$evidence/verdict.txt") != PASS ]]; then exit 20; fi
}
trap on_exit EXIT
persist_state

jq -n --arg run_id "$run_id" \
  --arg gate "$gate" \
  '{schema:1,run_id:$run_id,gate:$gate,authoritative:false,started_at:(now|todateiso8601)}' \
  > "$evidence/run.json"
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
  mount
  ulimit -a
} > "$evidence/environment.txt"
{
  git -C /soglia rev-parse HEAD
  git -C /soglia status --short --untracked-files=all
  git -C /soglia diff --binary -- . ':!spikes/cgroup-bpf/evidence' | sha256sum
  cd /soglia
  find Cargo.toml Cargo.lock src crates spikes/cgroup-bpf/agent spikes/cgroup-bpf/runner \
    -type f ! -path '*/target/*' ! -path '*/evidence/*' -print0 \
    | sort -z | xargs -0 sha256sum
} > "$evidence/source-fingerprint.txt"
sha256sum "$binary" "$driver" "$agent" > "$evidence/binary-sha256.txt"
bpftool -j prog show > "$evidence/baseline-programs.json"
bpftool -j link show > "$evidence/baseline-links.json"
bpftool -j map show > "$evidence/baseline-maps.json"
if jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
  "$evidence/baseline-programs.json" >/dev/null; then
  echo "pre-existing Soglia BPF program in diagnostic baseline" >&2
  exit 30
fi

install -d -m 0755 "$rootfs/proc" "$rootfs/dev" "$rootfs/sys" "$rootfs/tmp"
install -m 0755 "$agent" "$rootfs/agent"

cat > "$config" <<YAML
runtime:
  uid: 65534
  gid: 65534
  state_dir: $runtime
  max_concurrency: 2
  max_queue: 2
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 5000
  runc: /usr/sbin/runc
  nft: /usr/sbin/nft
  ip: /usr/sbin/ip
  bpftool: /usr/sbin/bpftool
ingress:
  listen: 127.0.0.1:18092
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
  max_tracked_sockets: 64
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: $pin_parent
agents:
  probe:
    rootfs: $rootfs
    command: ["/agent", "proxy-http allowed.test:443"]
    env: {}
    timeout_ms: 10000
YAML

current_phase=RUNNING_CASES
persist_state
set +e
systemd-run --unit="$unit" --property=Delegate=yes --property=Type=exec --pipe --wait --collect \
  "$driver" "$binary" "$config" "$evidence/driver" "${driver_extra[@]}" \
  > "$evidence/driver-stdout.txt" 2> "$evidence/driver-stderr.txt"
driver_status=$?
set -e
printf '%s\n' "$driver_status" > "$evidence/driver-status.txt"
[[ "$driver_status" -eq 0 ]]
grep -Fx PASS "$evidence/driver/verdict.txt" >/dev/null
