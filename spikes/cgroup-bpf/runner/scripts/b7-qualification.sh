#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Production Candidate-A B7 resource or B8 parallel-load qualification.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
inventory_classifier="$scripts/bpf_inventory_classifier.py"
# shellcheck source=spikes/cgroup-bpf/runner/scripts/bpf-inventory-common.sh
source "$scripts/bpf-inventory-common.sh"

usage='usage: b7-qualification.sh <soglia> <agent> <link-injector> <link-detacher> <foreign.o> [--authoritative]'
if [[ $# -ne 5 && $# -ne 6 ]]; then echo "$usage" >&2; exit 13; fi
binary=$1
agent=$2
injector=$3
detacher=$4
foreign_object=$5
authoritative=false
if [[ $# -eq 6 ]]; then [[ $6 == --authoritative ]] || { echo "$usage" >&2; exit 13; }; authoritative=true; fi

production_baseline=cfb2d375e76de59694e25374ec5df47c2bfb6c6a
gate=${SOGLIA_QUALIFICATION_GATE:-B7}
[[ $gate == B7 || $gate == B8 ]] || { echo "unsupported qualification gate: $gate" >&2; exit 13; }
gate_slug=${gate,,}
if [[ $gate == B8 ]]; then
  vm_name=${SOGLIA_B8_VM_NAME:-}
else
  vm_name=${SOGLIA_B7_VM_NAME:-}
fi
if [[ $authoritative == true && $vm_name != soglia-spike-$gate_slug-* ]]; then
  echo "authoritative $gate requires a recorded fresh soglia-spike-$gate_slug-* VM" >&2
  exit 13
fi
prefix=$gate_slug-diagnostic
[[ $authoritative == true ]] && prefix=$gate_slug
run_id="$prefix-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
pin_parent="/sys/fs/bpf/soglia-$gate_slug"
runtime_parent="/run/soglia-$gate_slug"
rootfs="/var/tmp/soglia-$gate_slug-rootfs"
current_phase=INITIALIZING
last_case=none
cleanup_status=NOT_RUN
program_classification=NOT_RUN
links_classification=NOT_RUN
maps_classification=NOT_RUN
production_source_matches=false
teardown_blocked=false
unit_cleanup_failed=false
effect_observer_created=false

mkdir -p "$evidence/final" "$evidence/profiles" "$evidence/drift" "$pin_parent" "$runtime_parent"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

persist_state() {
  jq -n --arg run_id "$run_id" --arg phase "$current_phase" --arg last_case "$last_case" \
    --argjson authoritative "$authoritative" \
    --arg gate "$gate" \
    '{schema:1,run_id:$run_id,gate:$gate,authoritative:$authoritative,current_phase:$phase,last_case:$last_case}' \
    > "$evidence/state.json"
}

write_summary() {
  local verdict=$1
  if [[ $gate == B8 ]]; then
    local p99_us=0 achieved=0 ramp=0
    if [[ -f $evidence/profiles/B8/result.json ]]; then
      p99_us=$(jq '.rates[0].measurement.p99_us // 0' "$evidence/profiles/B8/result.json")
      achieved=$(jq '.rates[0].measurement.achieved_rate_per_second // 0' "$evidence/profiles/B8/result.json")
    fi
    [[ ! -f $evidence/profiles/B8/b8-characterization.json ]] \
      || ramp=$(jq '.ramp.maximum_sustained_rate_per_second // 0' "$evidence/profiles/B8/b8-characterization.json")
    jq -n --arg run_id "$run_id" --arg verdict "$verdict" --arg cleanup "$cleanup_status" \
      --arg programs "$program_classification" --arg links "$links_classification" \
      --arg maps "$maps_classification" --arg baseline "$production_baseline" \
      --arg vm_name "$vm_name" --argjson authoritative "$authoritative" \
      --argjson source_matches "$production_source_matches" --argjson p99_us "$p99_us" \
      --argjson achieved "$achieved" --argjson ramp "$ramp" \
      '{schema:1,run_id:$run_id,gate:"B8",authoritative:$authoritative,verdict:$verdict,
        production_source_baseline:{commit:$baseline,matches:$source_matches},
        profile:{max_pending_resolves:64,resolve_workers:4,target_rate_per_second:500,
          duration_seconds:60,p99_limit_us:20000,p99_us:$p99_us,
          achieved_rate_per_second:$achieved},
        qualified:{parallel_load:true,correct_correlation:true,within_profile_outcomes_clean:true,
          return_to_baseline:true,burst_queue_full:true,mixed_workload_bounds:true,
          fault_injection:true,client_and_supervisor_latency:true},
        characterization:{maximum_sustained_rate_per_second:$ramp,pass_criterion:false},
        cleanup:{verdict:$cleanup,programs:$programs,links:$links,maps:$maps},
        authoritative_vm:(if $authoritative then {name:$vm_name} else null end)}' \
      > "$evidence/summary.json"
    printf '%s\n' "$verdict" > "$evidence/verdict.txt"
    return
  fi
  jq -n --arg run_id "$run_id" --arg verdict "$verdict" --arg cleanup "$cleanup_status" \
    --arg programs "$program_classification" --arg links "$links_classification" \
    --arg maps "$maps_classification" --arg baseline "$production_baseline" \
    --arg vm_name "$vm_name" --argjson authoritative "$authoritative" \
    --argjson source_matches "$production_source_matches" \
    '{schema:1,run_id:$run_id,gate:"B7",authoritative:$authoritative,verdict:$verdict,
      production_source_baseline:{commit:$baseline,matches:$source_matches},
      matrix:["M0","M1","M2","M3"],
      qualified:{declared_matrix:true,constant_shared_topology:true,production_events:true,
        independent_bpftool_comparison:true,rate_floor_percent:95,
        within_envelope_resolve_outcomes_clean:true,
        burst_queue_full_characterization:true,
        bounded_ingress_connections:true,bounded_proxy_connections:true,
        bounded_pending_resolves:true,bounded_resolve_workers:true,
        foreign_direct_link_fail_closed:true,owned_link_detach_fail_closed:true},
      cleanup:{verdict:$cleanup,programs:$programs,links:$links,maps:$maps},
      scope:{simultaneous_live_sockets_proved:512,
        simultaneous_new_connection_admissions_proved:32,
        burst_256:"OUTSIDE_SUPPORTED_ENVELOPE_REFUSAL_CHARACTERIZATION",
        map_capacity_configured:4096,
        nofile_limit_not_tuned:true,latency_objective:"configured Resolve deadline only",
        production_code_change:"NOT_PERFORMED: qualification harness only"},
      remaining_gates:{B8:"NOT_EXECUTED"},
      authoritative_vm:(if $authoritative then {name:$vm_name} else null end)}' \
    > "$evidence/summary.json"
  printf '%s\n' "$verdict" > "$evidence/verdict.txt"
}

stop_test_units() {
  set +e
  local units=(soglia-b7-m0 soglia-b7-m1 soglia-b7-m2 soglia-b7-m3 \
    soglia-b7-foreign-link soglia-b7-owned-link-detach soglia-b8-profile)
  for unit in "${units[@]}"; do
    stop_and_prune_unit_cgroup "$unit" "$evidence/final/unit-stops/$unit" \
      || unit_cleanup_failed=true
    systemctl reset-failed "$unit.service" >/dev/null 2>&1
  done
  set -e
}

remove_global_harness_resources() {
  [[ $teardown_blocked == false ]] || return 1
  [[ -z $(find "$pin_parent" -mindepth 1 -print -quit) ]] || return 1
  [[ -z $(find "$runtime_parent" -mindepth 1 -print -quit) ]] || return 1
  rmdir "$pin_parent" "$runtime_parent" || return 1
  ip link delete b7-upstream || return 1
  rm -- "$rootfs/agent" || return 1
  rmdir "$rootfs/proc" "$rootfs/dev" "$rootfs/sys" "$rootfs/tmp" "$rootfs" || return 1
}

remove_effect_observer() {
  [[ $effect_observer_created == true ]] || return 0
  nft delete table inet soglia_b7_observe || return 1
  effect_observer_created=false
}

final_cleanup() {
  set +e
  bpf_inventory_stop_watcher
  stop_test_units
  remove_effect_observer || teardown_blocked=true
  remove_global_harness_resources || teardown_blocked=true
  : > "$evidence/final/program-settle.jsonl"
  for attempt in $(seq 0 720); do
    bpf_inventory_classify_current "$evidence" "$pin_parent" \
      /sys/fs/cgroup/system.slice/soglia-b7-m0.service "$inventory_classifier"
    program_classification=$BPF_PROGRAM_CLASSIFICATION
    jq -cn --argjson attempt "$attempt" --arg classification "$program_classification" \
      '{attempt:$attempt,classification:$classification}' >> "$evidence/final/program-settle.jsonl"
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
  [[ $links_classification == MATCH && $maps_classification == MATCH ]] || cleanup_status=CLEANUP_FAIL
  [[ $teardown_blocked == false ]] || cleanup_status=CLEANUP_FAIL
  [[ ! -e $pin_parent && ! -e $runtime_parent && ! -e $rootfs ]] || cleanup_status=CLEANUP_FAIL
  [[ ! -e /sys/class/net/soglia0 && ! -e /sys/class/net/b7-upstream ]] || cleanup_status=CLEANUP_FAIL
  nft list table inet soglia_host >/dev/null 2>&1 && cleanup_status=CLEANUP_FAIL
  nft list table inet soglia_b7_observe >/dev/null 2>&1 && cleanup_status=CLEANUP_FAIL
  printf '%s\n' "$program_classification" > "$evidence/final/program-classification.txt"
  printf '%s\n' "$cleanup_status" > "$evidence/final/cleanup-verdict.txt"
  set -e
}

on_exit() {
  local status=$?
  current_phase=CLEANUP; persist_state
  final_cleanup
  if [[ $status -eq 0 && $cleanup_status == PASS ]]; then
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

jq -n --arg run_id "$run_id" --arg gate "$gate" --arg vm_name "$vm_name" --argjson authoritative "$authoritative" \
  '{schema:1,run_id:$run_id,gate:$gate,authoritative:$authoritative,vm_name:$vm_name,started_at:(now|todateiso8601)}' \
  > "$evidence/run.json"
{
  date -u +%FT%T.%NZ; uname -a; cat /etc/os-release; systemd --version | head -1
  bpftool version; nft --version; ip -V; runc --version
  /root/.cargo/bin/rustc +1.97.0 --version --verbose
  hostname; cat /etc/machine-id; cat /proc/sys/kernel/random/boot_id; mount; ulimit -a
} > "$evidence/environment.txt"
[[ -z $(find /soglia/spikes/cgroup-bpf/runner/scripts -type d -name __pycache__ -print -quit) ]]
[[ -z $(find /soglia/spikes/cgroup-bpf/runner/scripts -type f -name '*.pyc' -print -quit) ]]
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
sha256sum "$binary" "$agent" "$injector" "$detacher" "$foreign_object" > "$evidence/binary-sha256.txt"
bpf_inventory_begin "$evidence" "$pin_parent"
jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' "$evidence/baseline-programs.json" >/dev/null \
  && { echo 'pre-existing Soglia BPF program in B7 baseline' >&2; exit 30; }

install -d -m 0755 "$rootfs"/{proc,dev,sys,tmp}
install -m 0755 "$agent" "$rootfs/agent"
ip link add b7-upstream type dummy
ip addr add 11.0.0.1/32 dev b7-upstream
ip link set b7-upstream up
nft list table inet soglia_b7_observe >/dev/null 2>&1 \
  && { echo 'pre-existing B7 effect-observer table' >&2; exit 30; }
nft add table inet soglia_b7_observe
effect_observer_created=true
nft 'add chain inet soglia_b7_observe output { type filter hook output priority 200; policy accept; }'
nft add rule inet soglia_b7_observe output udp dport 53 \
  counter comment b7_dns_udp
nft add rule inet soglia_b7_observe output tcp dport 53 \
  counter comment b7_dns_tcp
nft -j list table inet soglia_b7_observe > "$evidence/effects-observer-baseline.json"

wait_ready() {
  local port=$1
  for _ in $(seq 1 300); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1 && { exec 3>&-; return 0; }
    sleep 0.05
  done
  return 1
}

write_config() {
  local profile=$1 concurrency=$2 sockets=$3 port=$4 unit=$5
  local max_proxy_connections=512 max_pending_resolves=64 resolve_workers=4
  (( sockets < max_proxy_connections )) && max_proxy_connections=$sockets
  (( max_proxy_connections < max_pending_resolves )) && max_pending_resolves=$max_proxy_connections
  (( max_pending_resolves < resolve_workers )) && resolve_workers=$max_pending_resolves
  local config="$evidence/profiles/$profile/config.yaml"
  mkdir -p "$(dirname "$config")"
  cat > "$config" <<YAML
runtime:
  uid: 65534
  gid: 65534
  state_dir: $runtime_parent/$profile
  max_concurrency: $concurrency
  max_queue: $concurrency
  max_ingress_connections: $((concurrency * 2))
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 10000
  runc: /usr/sbin/runc
  nft: /usr/sbin/nft
  ip: /usr/sbin/ip
  bpftool: /usr/sbin/bpftool
ingress:
  listen: 127.0.0.1:$port
network:
  backend: cgroup-bpf
  execution_pool: 10.201.0.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
  max_proxy_connections: $max_proxy_connections
egress:
  connect_timeout_ms: 1000
  idle_timeout_ms: 65000
  allow:
    - { host: allowed.test, ports: [443] }
    - { host: 11.0.0.1, ports: [443] }
cgroup:
  root: /sys/fs/cgroup/system.slice/$unit.service
cgroup_bpf:
  max_tracked_sockets: $sockets
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  max_pending_resolves: $max_pending_resolves
  resolve_workers: $resolve_workers
  pin_root: $pin_parent/$profile
agents:
  workload:
    rootfs: $rootfs
    command: ["/agent", "serve"]
    env: { AGENT_PORT: "8080" }
    timeout_ms: 600000
    tmpfs: [{ path: /tmp, size_bytes: 16777216 }]
YAML
  printf '%s\n' "$config"
}

start_unit() {
  local unit=$1 config=$2 output=$3
  mkdir -p "$(dirname "$output")"
  systemd-run --unit="$unit" --property=Delegate=yes --property=Type=exec --collect \
    "$binary" run -f "$config" > "$output"
}

stop_and_verify_row() {
  local unit=$1 profile=$2 case_evidence=$3 drift_result=${4:-}
  local state="$runtime_parent/$profile/cgroup-bpf/state.json"
  local measurement="$case_evidence/persistent-generation.json"
  local teardown="$case_evidence/harness-teardown.json"
  cp -- "$state" "$case_evidence/registered-state-before-stop.json"
  stop_and_prune_unit_cgroup "$unit" "$case_evidence/unit-stop"
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  [[ ! -e "/sys/fs/cgroup/system.slice/$unit.service" ]]
  cmp -s "$case_evidence/registered-state-before-stop.json" "$state"
  local verify_args=(verify --state "$state" --runtime-parent "$runtime_parent"
    --pin-parent "$pin_parent" --configured-pin-root "$pin_parent/$profile"
    --output "$measurement")
  [[ -z $drift_result ]] || verify_args+=(--drift-result "$drift_result")
  if ! python3 "$scripts/b7-residue.py" "${verify_args[@]}"; then
    teardown_blocked=true
    return 1
  fi
  python3 "$scripts/b7-residue.py" teardown --state "$state" \
    --runtime-parent "$runtime_parent" --pin-parent "$pin_parent" \
    --configured-pin-root "$pin_parent/$profile" --measurement "$measurement" \
    --output "$teardown"
  jq -n --arg profile "$profile" --arg active "$case_evidence/active-residue" \
    --arg persistent "$measurement" --arg teardown "$teardown" \
    '{profile:$profile,cleanup:"PASS",measurements:{execution_residue:$active,
      persistent_generation:$persistent,harness_teardown:$teardown},wildcard_deletion:false}' \
    > "$case_evidence/cleanup.json"
}

run_profile() {
  local profile=$1 concurrency=$2 sockets=$3 checkpoints=$4 live=$5 churn=$6 rates=$7 burst=$8 port=$9
  local unit="soglia-b7-${profile,,}" config
  [[ $gate == B7 ]] || unit=soglia-b8-profile
  last_case=$profile; current_phase="PROFILE_$profile"; persist_state
  config=$(write_config "$profile" "$concurrency" "$sockets" "$port" "$unit")
  start_unit "$unit" "$config" "$evidence/profiles/$profile/systemd-run.txt"
  wait_ready "$port"
  python3 "$scripts/b7-profile.py" --profile "$profile" --unit "$unit" \
    --state "$runtime_parent/$profile/cgroup-bpf/state.json" \
    --evidence "$evidence/profiles/$profile" --ingress-port "$port" \
    --checkpoints "$checkpoints" --live "$live" --churn "$churn" --rates "$rates" \
    --burst "$burst" --deadline-ms 2000
  if [[ $gate == B8 ]]; then
    python3 "$scripts/b8-characterize.py" --unit "$unit" --port "$port" \
      --state "$runtime_parent/$profile/cgroup-bpf/state.json" \
      --evidence "$evidence/profiles/$profile" --production-root /soglia
  fi
  grep -Fx PASS "$evidence/profiles/$profile/verdict.txt" >/dev/null
  stop_and_verify_row "$unit" "$profile" "$evidence/profiles/$profile"
}

if [[ $gate == B7 ]]; then
  run_profile M0 1 64 0,1 48 64 1x30 0 18100
  run_profile M1 4 512 0,1,2,4 384 1024 50x30 0 18101
  run_profile M2 4 4096 0,1,2,4 512 8192 100x30,250x30 0 18102
  run_profile M3 32 4096 0,1,8,16,32 32 8192 250x30 256 18103
else
  run_profile B8 4 4096 0,1,2,4 64 1024 500x60 256 18108
fi

run_drift() {
  local mode=$1 port=$2 profile=$3 unit config
  unit="soglia-b7-${mode//_/-}"
  local case_evidence="$evidence/drift/$mode"
  last_case=$mode; current_phase="DRIFT_${mode^^}"; persist_state
  config=$(write_config "$profile" 1 64 "$port" "$unit")
  start_unit "$unit" "$config" "$case_evidence/systemd-run.txt"
  wait_ready "$port"
  python3 "$scripts/b7-drift.py" --mode "$mode" --unit "$unit" --port "$port" \
    --state "$runtime_parent/$profile/cgroup-bpf/state.json" \
    --evidence "$case_evidence" --injector "$injector" --detacher "$detacher" \
    --foreign-object "$foreign_object"
  grep -Fx PASS "$case_evidence/verdict.txt" >/dev/null
  stop_and_prune_unit_cgroup "$unit" "$case_evidence/pre-recovery-unit-stop"
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  [[ ! -e "/sys/fs/cgroup/system.slice/$unit.service" ]]
  [[ $(systemctl show "$unit.service" -p LoadState --value 2>/dev/null) == not-found ]]
  start_unit "$unit" "$config" "$case_evidence/recovery-systemd-run.txt"
  wait_ready "$port"
  cp -- "$runtime_parent/$profile/cgroup-bpf/state.json" "$case_evidence/recovery-state.json"
  local expected_generation
  expected_generation=$(jq '.active_state_before_mutation.generation + 1' "$case_evidence/result.json")
  jq -e --argjson generation "$expected_generation" \
    '.phase == "READY" and .generation == $generation and (.executions | length) == 0' \
    "$case_evidence/recovery-state.json" >/dev/null
  journalctl -u "$unit.service" -o cat --no-pager > "$case_evidence/recovery-events.txt"
  stop_and_verify_row "$unit" "$profile" "$case_evidence"
}

if [[ $gate == B7 ]]; then
  run_drift foreign_link 18104 drift-foreign-link
  run_drift owned_link_detach 18105 drift-owned-link-detach
fi

current_phase=FINAL_CLEANUP
last_case=final_cleanup
persist_state
