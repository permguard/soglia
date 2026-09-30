#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# B2 qualification, with separate diagnostic and authoritative modes plus a focused
# production-cleanup probe mode used before rerunning B1.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
inventory_classifier="$scripts/bpf_inventory_classifier.py"
# shellcheck source=spikes/cgroup-bpf/runner/scripts/bpf-inventory-common.sh
source "$scripts/bpf-inventory-common.sh"

usage='usage: b2-qualification.sh <soglia> <b2-driver> <agent> [--authoritative]'
if [[ $# -ne 3 && $# -ne 4 ]]; then
  echo "$usage" >&2
  exit 13
fi
binary=$1
driver=$2
agent=$3
authoritative=false
if [[ $# -eq 4 ]]; then
  if [[ $4 != --authoritative ]]; then
    echo "unknown B2 qualification flag: $4" >&2
    exit 13
  fi
  authoritative=true
fi

production_baseline=db6e1ac21a957b5fd8de96f5e3a719db1d897723
production_source_matches=false
vm_name=${SOGLIA_B2_VM_NAME:-}
if [[ "$authoritative" == true && "$vm_name" != soglia-spike-b2-* ]]; then
  echo "authoritative B2 requires a recorded soglia-spike-b2-* VM name" >&2
  exit 13
fi

mode=${SOGLIA_B2_MODE:-b2}
case "$mode" in
  b2)
    gate=B2
    if [[ "$authoritative" == true ]]; then
      run_prefix="b2"
      supported_platform_scope="the exact recorded authoritative fresh-VM environment fingerprint"
      authoritative_fresh_vm_scope="PERFORMED: the host wrapper created a never-used VM"
    else
      run_prefix="b2-diagnostic"
      supported_platform_scope="the exact recorded diagnostic environment fingerprint"
      authoritative_fresh_vm_scope="NOT_PERFORMED: diagnostic phase only"
    fi
    driver_extra=()
    ;;
  cleanup-probe)
    if [[ "$authoritative" == true ]]; then
      echo "cleanup probe cannot be authoritative" >&2
      exit 13
    fi
    gate=CGROUP_BPF_CLEANUP_PROBE
    run_prefix="cgroup-bpf-cleanup-probe"
    supported_platform_scope="the exact recorded diagnostic environment fingerprint"
    authoritative_fresh_vm_scope="NOT_PERFORMED: diagnostic phase only"
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
    --arg gate "$gate" --argjson authoritative "$authoritative" \
    '{schema:1,run_id:$run_id,gate:$gate,authoritative:$authoritative,
      current_phase:$phase,last_case:$last_case}' \
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
    --arg baseline "$production_baseline" \
    --arg supported_platform "$supported_platform_scope" \
    --arg authoritative_fresh_vm "$authoritative_fresh_vm_scope" \
    --arg vm_name "$vm_name" \
    --argjson authoritative "$authoritative" \
    --argjson production_source_matches "$production_source_matches" \
    --argjson driver_status "$driver_status" \
    '({schema:1,run_id:$run_id,gate:$gate,authoritative:$authoritative,verdict:$verdict,
      driver_status:$driver_status,
      cleanup:{verdict:$cleanup,programs:$programs,links:$links,maps:$maps},
      scope:{
        supported_platform:$supported_platform,
        authoritative_fresh_vm:$authoritative_fresh_vm,
        production_code_change:"NOT_PERFORMED: qualification harness only",
        helper_loss_cancellation:"NOT_PERFORMED: belongs to B6",
        concurrency_and_identity_reuse:"NOT_PERFORMED: belongs to B3",
        capacity_exhaustion:"NOT_PERFORMED: belongs to B4",
        tuple_disappears_during_sweep:
          "NOT_PERFORMED: deterministic privileged race injection is unavailable; ENOENT classification is unit-tested"
      },
      remaining_gates:{B3:"NOT_EXECUTED",B4:"NOT_EXECUTED",B5:"NOT_EXECUTED",
        B6:"NOT_EXECUTED",B7:"NOT_EXECUTED"}})
      + if $authoritative then
          {production_source_baseline:{commit:$baseline,matches:$production_source_matches},
           authoritative_vm:{name:$vm_name,fresh_name_verified_by_host_wrapper:true}}
        else {} end' > "$evidence/summary.json"
  printf '%s\n' "$verdict" > "$evidence/verdict.txt"
}

cleanup() {
  set +e
  bpf_inventory_stop_watcher
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

  bpf_inventory_classify_current "$evidence" "$pin_parent" "$cgroup" "$inventory_classifier"
  program_classification=$BPF_PROGRAM_CLASSIFICATION
  bpftool -j map show > "$evidence/final/maps.json"
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
  bpf_inventory_is_clean "$program_classification" || cleanup_status=CLEANUP_FAIL
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
    # shellcheck disable=SC2094 # SHA256SUMS does not exist until the redirection opens it.
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
  --arg gate "$gate" --arg vm_name "$vm_name" --argjson authoritative "$authoritative" \
  '({schema:1,run_id:$run_id,gate:$gate,authoritative:$authoritative,
    started_at:(now|todateiso8601)})
    + if $authoritative then {authoritative_vm:$vm_name} else {} end' \
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
  if [[ "$authoritative" == true ]]; then
    hostname
    cat /etc/machine-id
    cat /proc/sys/kernel/random/boot_id
  fi
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
if [[ "$authoritative" == true ]]; then
  production_status=$(git -C /soglia status --short --untracked-files=all -- \
    crates src Cargo.toml Cargo.lock)
  {
    printf 'baseline_commit=%s\n' "$production_baseline"
    printf 'current_commit=%s\n' "$(git -C /soglia rev-parse HEAD)"
    printf 'command=git diff --exit-code %s -- crates src Cargo.toml Cargo.lock\n' \
      "$production_baseline"
    git -C /soglia cat-file -e "$production_baseline^{commit}"
    git -C /soglia diff --exit-code "$production_baseline" -- \
      crates src Cargo.toml Cargo.lock
    printf 'diff_exit=0\n'
    for production_path in crates src Cargo.toml Cargo.lock; do
      printf 'object %s baseline=%s current=%s\n' \
        "$production_path" \
        "$(git -C /soglia rev-parse "$production_baseline:$production_path")" \
        "$(git -C /soglia rev-parse "HEAD:$production_path")"
    done
    printf 'production_status=%s\n' "${production_status:-CLEAN}"
    [[ -z "$production_status" ]]
  } > "$evidence/production-source-baseline.txt"
  production_source_matches=true
fi
sha256sum "$binary" "$driver" "$agent" > "$evidence/binary-sha256.txt"
bpf_inventory_begin "$evidence" "$pin_parent"
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
    # 40000 == 0x9c40 and byte-swaps to 16540 == 0x409c. Keeping this
    # deterministic prevents the tuple-byte-order case from receiving a
    # byte-symmetric ephemeral source port.
    command: ["/agent", "proxy-http allowed.test:443 40000"]
    env: {}
    timeout_ms: 10000
  concurrent:
    rootfs: $rootfs
    # Four non-byte-symmetric source ports. The agent records every connect outcome in a tmpfs
    # while remaining alive long enough for the trusted driver to copy the evidence through /proc.
    command: ["/agent", "proxy-fixed-report 40000 4 /tmp/client-outcomes.jsonl 10"]
    env: {}
    timeout_ms: 15000
    tmpfs:
      - { path: /tmp, size_bytes: 1048576 }
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
