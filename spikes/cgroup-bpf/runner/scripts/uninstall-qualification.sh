#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Diagnostic qualification for the production verified-uninstall command.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
inventory_classifier="$scripts/bpf_inventory_classifier.py"
# shellcheck source=spikes/cgroup-bpf/runner/scripts/bpf-inventory-common.sh
source "$scripts/bpf-inventory-common.sh"

if [[ $# -ne 4 ]]; then
  echo 'usage: uninstall-qualification.sh <soglia> <b6-trace> <agent> <foreign.o>' >&2
  exit 13
fi
binary=$1
tracer=$2
agent=$3
foreign_object=$4
production_baseline=0ef4bd9c16200efd29cbcb76dcf7ac53a06825fb
run_id="uninstall-diagnostic-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
registry="$evidence/harness-owned.tsv"
foreign_root="/sys/fs/bpf/soglia-uninstall-foreign-$run_id"
current_case=initializing
cleanup_status=NOT_RUN
program_classification=NOT_RUN
links_classification=NOT_RUN
maps_classification=NOT_RUN
production_source_matches=false
failure_detail=

mkdir -p "$evidence/cases" "$evidence/final"
: > "$registry"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

persist_state() {
  jq -n --arg run_id "$run_id" --arg current_case "$current_case" \
    '{schema:1,run_id:$run_id,gate:"UNINSTALL",authoritative:false,current_case:$current_case}' \
    > "$evidence/state.json"
}

record_case() {
  local name=$1 verdict=$2 detail=${3:-}
  jq -n --arg case "$name" --arg verdict "$verdict" --arg detail "$detail" \
    '{schema:1,case:$case,verdict:$verdict,detail:$detail}' \
    > "$evidence/cases/$name/result.json"
  printf '%s\n' "$verdict" > "$evidence/cases/$name/verdict.txt"
}

case_scope() {
  local name=$1
  if [[ -f $evidence/cases/$name/verdict.txt ]]; then
    cat "$evidence/cases/$name/verdict.txt"
  else
    printf '%s\n' NOT_EXECUTED
  fi
}

on_error() {
  local status=$1 line=$2
  failure_detail="line $line exited with status $status"
  if [[ $current_case != cleanup && $current_case != initializing \
    && ! -f $evidence/cases/$current_case/result.json ]]; then
    record_case "$current_case" FAIL "$failure_detail"
  fi
}

case_paths() {
  local name=$1 cgroup_override=${2:-} slug
  slug=${name//_/-}
  case_dir="$evidence/cases/$name"
  runtime="/run/soglia-uninstall-$run_id-$slug"
  pin_root="/sys/fs/bpf/soglia-uninstall-$run_id-$slug"
  cgroup_root="/sys/fs/cgroup/soglia-uninstall-$run_id-$slug"
  if [[ -n $cgroup_override ]]; then cgroup_root=$cgroup_override; fi
  rootfs="/var/tmp/soglia-uninstall-$run_id-$slug-rootfs"
  config="$case_dir/config.yaml"
  state="$runtime/cgroup-bpf/state.json"
  uninstall_intent="$runtime/cgroup-bpf/uninstall.json"
  mkdir -p "$case_dir" "$rootfs"/{proc,dev,sys,tmp}
  install -m 0755 "$agent" "$rootfs/agent"
  printf '%s\t%s\t%s\t%s\n' "$runtime" "$pin_root" "$cgroup_root" "$rootfs" >> "$registry"
}

write_config() {
  local backend=${1:-cgroup-bpf}
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
ingress: { listen: "127.0.0.1:0" }
network:
  backend: $backend
  execution_pool: 10.238.0.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
egress:
  connect_timeout_ms: 1000
  idle_timeout_ms: 30000
  allow: [{ host: allowed.test, ports: [443] }]
cgroup: { root: "$cgroup_root" }
cgroup_bpf:
  max_tracked_sockets: 64
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: $pin_root
agents:
  uninstall-hold:
    rootfs: $rootfs
    command: ["/agent", "serve"]
    env: {}
    timeout_ms: 20000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
YAML
}

create_cgroup_root() {
  mkdir "$cgroup_root"
}

start_generation() {
  create_cgroup_root
  "$binary" run -f "$config" > "$case_dir/run.stdout" 2> "$case_dir/run.stderr" &
  runtime_pid=$!
  printf '%s\n' "$runtime_pid" > "$case_dir/runtime.pid"
  for _ in $(seq 1 1000); do
    if [[ -f $state ]] && jq -e '.phase == "READY" and (.programs|length)==6 and
      (.links|length)==6 and (.maps|length)==7' "$state" >/dev/null 2>&1; then
      cp "$state" "$case_dir/state-ready.json"
      return 0
    fi
    kill -0 "$runtime_pid" 2>/dev/null || {
      echo 'runtime exited before READY' >&2
      return 1
    }
    sleep 0.01
  done
  echo 'timed out waiting for READY' >&2
  return 1
}

stop_generation() {
  kill -TERM "$runtime_pid"
  wait "$runtime_pid"
  runtime_pid=
  [[ -f $state ]]
  jq -e '.phase == "READY"' "$state" >/dev/null
}

snapshot_owned() {
  local destination=$1
  {
    for parent in "$runtime" "$pin_root"; do
      if [[ -e $parent ]]; then
        find "$parent" -xdev -printf '%y %m %u %g %p\n' | sort
        find "$parent" -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum
      else
        printf 'ABSENT %s\n' "$parent"
      fi
    done
    bpftool -j prog show | jq -Sc 'sort_by(.id)'
    bpftool -j link show | jq -Sc 'sort_by(.id)'
    bpftool -j map show | jq -Sc 'sort_by(.id)'
    ip -j netns list | jq -Sc 'sort_by(.name)'
    ip -j link show | jq -Sc 'sort_by(.ifindex)'
    nft -j list tables | jq -Sc .
  } > "$destination"
}

run_uninstall() {
  local output=$1 error=$2
  shift 2
  set +e
  "$binary" uninstall "$@" -f "$config" > "$output" 2> "$error"
  command_status=$?
  set -e
}

expect_refusal() {
  local expected=$1 name=$2
  shift 2
  snapshot_owned "$case_dir/$name-before.txt"
  run_uninstall "$case_dir/$name.stdout" "$case_dir/$name.stderr" "$@"
  [[ $command_status -eq $expected ]]
  snapshot_owned "$case_dir/$name-after.txt"
  cmp "$case_dir/$name-before.txt" "$case_dir/$name-after.txt"
  jq -n --argjson expected "$expected" --argjson observed "$command_status" \
    --arg snapshot_sha256 "$(sha256sum "$case_dir/$name-before.txt" | awk '{print $1}')" \
    '{expected_exit:$expected,observed_exit:$observed,mutation:false,
      before_after_snapshot_sha256:$snapshot_sha256}' > "$case_dir/$name.json"
}

assert_no_owned_residue() {
  local output=$1
  bpftool -j prog show > "$case_dir/post-programs.json"
  bpftool -j link show > "$case_dir/post-links.json"
  bpftool -j map show > "$case_dir/post-maps.json"
  local residue=false
  [[ ! -e $runtime && ! -e $pin_root ]] || residue=true
  jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' "$case_dir/post-programs.json" \
    >/dev/null && residue=true
  jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' "$case_dir/post-maps.json" \
    >/dev/null && residue=true
  ip netns list | grep -q '^soglia-' && residue=true
  ip -o link show | grep -Eq 'sgh-|soglia0' && residue=true
  nft list tables | grep -q 'soglia' && residue=true
  jq -n --argjson owned_residue "$residue" \
    '{measured_before_harness_teardown:true,owned_residue:$owned_residue}' > "$output"
  [[ $residue == false ]]
}

remove_case_root() {
  rmdir "$cgroup_root/runtime" "$cgroup_root/executions" "$cgroup_root" 2>/dev/null || true
  rm -rf "$rootfs"
}

complete_real_uninstall() {
  local label=$1
  run_uninstall "$case_dir/$label.stdout" "$case_dir/$label.stderr"
  [[ $command_status -eq 0 ]]
  jq -e '.verdict == "PASS" and .dry_run == false and
    .enforcer.absence_verified == true' "$case_dir/$label.stdout" >/dev/null
  assert_no_owned_residue "$case_dir/residue-before-harness-teardown.json"
  remove_case_root
}

cleanup() {
  local status=$?
  local stopped_case=$current_case
  set +e
  current_case=cleanup
  persist_state
  if [[ -n ${runtime_pid:-} ]]; then kill -TERM "$runtime_pid" >/dev/null 2>&1; wait "$runtime_pid" 2>/dev/null; fi
  if [[ -n ${active_unit:-} ]]; then
    systemctl stop "$active_unit" >/dev/null 2>&1
    systemctl reset-failed "$active_unit" >/dev/null 2>&1
  fi
  if [[ -d $foreign_root ]]; then
    rm -f "$foreign_root/foreign_allow" "$foreign_root/foreign_rewrite"
    rmdir "$foreign_root"
  fi
  while IFS=$'\t' read -r owned_runtime owned_pin owned_cgroup owned_rootfs; do
    for manifest in "$owned_runtime/cgroup-bpf/uninstall.json" "$owned_runtime/cgroup-bpf/state.json"; do
      if [[ -f $manifest ]]; then
        jq -r '(.state // .) | .links[].pin, .maps[].pin' "$manifest" 2>/dev/null \
          | while read -r pin; do case "$pin" in "$owned_pin"/*) rm -f "$pin" ;; esac; done
      fi
    done
    if [[ -f $owned_runtime/net/host.json ]] \
      && [[ $(jq -r '.dummy // empty' "$owned_runtime/net/host.json" 2>/dev/null) == soglia0 ]]; then
      nft delete table inet soglia_host >/dev/null 2>&1
      ip link delete soglia0 >/dev/null 2>&1
    fi
    rm -rf "$owned_runtime" "$owned_rootfs"
    rmdir "$owned_pin"/links "$owned_pin"/maps "$owned_pin" 2>/dev/null
    if [[ -d $owned_cgroup ]]; then
      find "$owned_cgroup" -depth -type d -exec rmdir {} \; 2>/dev/null
    fi
  done < "$registry"

  : > "$evidence/final/program-settle.jsonl"
  for attempt in $(seq 0 400); do
    bpf_inventory_classify_current "$evidence" /sys/fs/bpf/soglia-uninstall-none \
      /sys/fs/cgroup/soglia-uninstall-none "$inventory_classifier"
    program_classification=$BPF_PROGRAM_CLASSIFICATION
    bpf_inventory_is_clean "$program_classification" && break
    sleep 0.025
  done
  bpftool -j map show > "$evidence/final/maps.json"
  jq -S 'sort_by(.id)' "$evidence/baseline-links.json" > "$evidence/final/links-before.json"
  jq -S 'sort_by(.id)' "$evidence/final/links.json" > "$evidence/final/links-after.json"
  jq -S 'sort_by(.id)' "$evidence/baseline-maps.json" > "$evidence/final/maps-before.json"
  jq -S 'sort_by(.id)' "$evidence/final/maps.json" > "$evidence/final/maps-after.json"
  cleanup_status=PASS
  bpf_inventory_is_clean "$program_classification" || cleanup_status=CLEANUP_FAIL
  cmp -s "$evidence/final/links-before.json" "$evidence/final/links-after.json" \
    && links_classification=MATCH || links_classification=FAIL
  cmp -s "$evidence/final/maps-before.json" "$evidence/final/maps-after.json" \
    && maps_classification=MATCH || maps_classification=FAIL
  [[ $links_classification == MATCH && $maps_classification == MATCH ]] \
    || cleanup_status=CLEANUP_FAIL
  [[ ! -e /sys/class/net/soglia0 ]] || cleanup_status=CLEANUP_FAIL
  nft list table inet soglia_host >/dev/null 2>&1 && cleanup_status=CLEANUP_FAIL

  local verdict=FAIL
  if [[ $status -eq 0 && $cleanup_status == PASS ]]; then verdict=PASS; fi
  jq -n --arg run_id "$run_id" --arg verdict "$verdict" --arg cleanup "$cleanup_status" \
    --arg programs "$program_classification" --arg links "$links_classification" \
    --arg maps "$maps_classification" --arg baseline "$production_baseline" \
    --arg stopped_case "$stopped_case" --arg failure_detail "$failure_detail" \
    --arg fresh "$(case_scope fresh_host)" \
    --arg stopped "$(case_scope normal_service_stop)" \
    --arg known "$(case_scope known_compatible)" \
    --arg live "$(case_scope live_runtime_refusal)" \
    --arg incompatible "$(case_scope incompatible_refusal)" \
    --arg unknown "$(case_scope unknown_refusal)" \
    --arg unsupported "$(case_scope unsupported_refusal)" \
    --arg nonempty "$(case_scope nonempty_refusal)" \
    --arg interrupted "$(case_scope interrupted_resume)" \
    --arg released "$(case_scope target_released)" \
    --argjson production_source_matches "$production_source_matches" \
    '{schema:1,run_id:$run_id,gate:"UNINSTALL",authoritative:false,verdict:$verdict,
      stopped_at_case:$stopped_case,failure_detail:$failure_detail,
      cleanup:{verdict:$cleanup,programs:$programs,links:$links,maps:$maps},
      production_source_baseline:{commit:$baseline,matches:$production_source_matches},
      cases:{fresh_host:$fresh,normal_service_stop:$stopped,
        known_compatible:$known,live_runtime_refusal:$live,
        incompatible_refusal:$incompatible,unknown_refusal:$unknown,
        unsupported_refusal:$unsupported,nonempty_refusal:$nonempty,
        interrupted_resume:$interrupted,target_released:$released},
      scope:{dry_run_equivalence:(if $known == "PASS" then "PERFORMED" else "NOT_EXECUTED" end),
        typed_refusals_before_mutation:(if $live == "PASS" and $incompatible == "PASS" and
          $unknown == "PASS" and $unsupported == "PASS" and $nonempty == "PASS"
          then "PERFORMED" else "NOT_EXECUTED" end),
        interrupted_resume:(if $interrupted == "PASS" then
          "PERFORMED: durable uninstall INTENT boundary" else "NOT_EXECUTED" end),
        non_owned_state_preservation:(if $known == "PASS" then "PERFORMED" else "NOT_EXECUTED" end),
        uninstall_after_normal_service_stop:(if $stopped == "PASS" then
          "PERFORMED: stopped systemd unit removed executions/ before verified uninstall"
          else "NOT_EXECUTED" end),
        target_released:(if $released == "PASS" then "PERFORMED" else "NOT_EXECUTED" end),
        every_detach_unlink_boundary:"NOT_PERFORMED in first diagnostic; blocked if an earlier production defect is found",
        previous_release_compatibility:"NOT_PERFORMED: no released predecessor exists"}}' \
    > "$evidence/summary.json"
  printf '%s\n' "$verdict" > "$evidence/verdict.txt"
  (cd "$evidence" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS)
  printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
  cat "$evidence/summary.json"
  trap - EXIT
  [[ $verdict == PASS ]] || exit 20
}
trap 'on_error "$?" "$LINENO"' ERR
trap cleanup EXIT
persist_state

jq -n --arg run_id "$run_id" \
  '{schema:1,run_id:$run_id,gate:"UNINSTALL",authoritative:false,started_at:(now|todateiso8601)}' \
  > "$evidence/run.json"
{
  date -u +%FT%T.%NZ; uname -a; cat /etc/os-release; systemd --version | head -1
  bpftool version; nft --version; ip -V; runc --version
  /root/.cargo/bin/rustc +1.97.0 --version --verbose; cat /proc/sys/kernel/random/boot_id
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
production_source_matches=true
sha256sum "$binary" "$tracer" "$agent" "$foreign_object" > "$evidence/binary-sha256.txt"
bpf_inventory_begin "$evidence" /sys/fs/bpf/soglia-uninstall-none

current_case=fresh_host; persist_state; case_paths fresh_host; write_config; create_cgroup_root
run_uninstall "$case_dir/dry-run.json" "$case_dir/dry-run.stderr" --dry-run
if [[ $command_status -ne 0 ]]; then
  failure_detail="fresh-host dry-run expected exit 0, observed $command_status"
  record_case fresh_host FAIL "$failure_detail"
  exit 20
fi
jq -e '.verdict == "PASS" and .dry_run and .enforcer.classification == "FRESH"' \
  "$case_dir/dry-run.json" >/dev/null
run_uninstall "$case_dir/uninstall.json" "$case_dir/uninstall.stderr"
[[ $command_status -eq 0 ]]
jq -e '.verdict == "PASS" and (.dry_run|not) and .enforcer.classification == "FRESH"' \
  "$case_dir/uninstall.json" >/dev/null
assert_no_owned_residue "$case_dir/residue-before-harness-teardown.json"
remove_case_root
record_case fresh_host PASS

current_case=normal_service_stop; persist_state
active_unit="soglia-uninstall-normal-$run_id"
case_paths normal_service_stop "/sys/fs/cgroup/system.slice/$active_unit.service"
write_config
systemd-run --unit="$active_unit" --property=Type=simple --property=Delegate=yes \
  --property=KillMode=mixed --property=Restart=no --collect -- \
  "$binary" run -f "$config" > "$case_dir/systemd-run.txt"
for _ in $(seq 1 1000); do
  if [[ -f $state ]] && jq -e '.phase == "READY" and (.programs|length)==6 and
    (.links|length)==6 and (.maps|length)==7' "$state" >/dev/null 2>&1; then
    cp "$state" "$case_dir/state-ready.json"
    break
  fi
  [[ $(systemctl show -p ActiveState --value "$active_unit") != failed ]]
  sleep 0.01
done
[[ -f $case_dir/state-ready.json ]]
systemctl show "$active_unit" > "$case_dir/unit-before-stop.txt"
systemctl stop "$active_unit"
systemctl reset-failed "$active_unit" >/dev/null 2>&1 || true
for _ in $(seq 1 500); do
  [[ ! -e $cgroup_root ]] && break
  sleep 0.01
done
[[ ! -e $cgroup_root ]]
systemctl show "$active_unit" > "$case_dir/unit-after-stop.txt" 2>&1 || true
active_unit=
run_uninstall "$case_dir/uninstall.stdout" "$case_dir/uninstall.stderr"
[[ $command_status -eq 0 ]]
jq -e '.verdict == "PASS" and (.dry_run|not) and
  .enforcer.classification == "TARGET_RELEASED" and
  .enforcer.absence_verified == true' "$case_dir/uninstall.stdout" >/dev/null
assert_no_owned_residue "$case_dir/residue-before-harness-teardown.json"
remove_case_root
record_case normal_service_stop PASS

current_case=known_compatible; persist_state; case_paths known_compatible; write_config
start_generation; stop_generation
mkdir "$foreign_root"
bpftool prog loadall "$foreign_object" "$foreign_root"
bpftool -j prog show pinned "$foreign_root/foreign_allow" > "$case_dir/foreign-before.json"
snapshot_owned "$case_dir/before-dry-run.txt"
run_uninstall "$case_dir/dry-run.json" "$case_dir/dry-run.stderr" --dry-run
[[ $command_status -eq 0 ]]
snapshot_owned "$case_dir/after-dry-run.txt"
cmp "$case_dir/before-dry-run.txt" "$case_dir/after-dry-run.txt"
complete_real_uninstall uninstall
jq -e --slurpfile before "$case_dir/foreign-before.json" '
  .id == $before[0].id and .tag == $before[0].tag and .type == $before[0].type' \
  < <(bpftool -j prog show pinned "$foreign_root/foreign_allow") >/dev/null
jq -e --slurpfile real "$case_dir/uninstall.stdout" '
  .sandbox_operations == $real[0].sandbox_operations and
  .enforcer.operations == $real[0].enforcer.operations' "$case_dir/dry-run.json" >/dev/null
rm "$foreign_root/foreign_allow" "$foreign_root/foreign_rewrite"; rmdir "$foreign_root"
record_case known_compatible PASS

current_case=live_runtime_refusal; persist_state; case_paths live_runtime_refusal; write_config
start_generation
expect_refusal 23 live-runtime
kill -TERM "$runtime_pid"; wait "$runtime_pid"; runtime_pid=
complete_real_uninstall cleanup-after-refusal
record_case live_runtime_refusal PASS

current_case=incompatible_refusal; persist_state; case_paths incompatible_refusal; write_config
start_generation; stop_generation
cp "$state" "$case_dir/state-valid.json"
jq '.schema = 999' "$state" > "$case_dir/state-incompatible.json"
install -m 0600 "$case_dir/state-incompatible.json" "$state"
expect_refusal 20 incompatible
install -m 0600 "$case_dir/state-valid.json" "$state"
complete_real_uninstall cleanup-after-refusal
record_case incompatible_refusal PASS

current_case=unknown_refusal; persist_state; case_paths unknown_refusal; write_config
start_generation; stop_generation
bpftool map create "$pin_root/maps/unrecorded" type array key 4 value 4 entries 1 \
  name uninstall_unknown
expect_refusal 21 unknown
rm "$pin_root/maps/unrecorded"
complete_real_uninstall cleanup-after-refusal
record_case unknown_refusal PASS

current_case=unsupported_refusal; persist_state; case_paths unsupported_refusal
write_config netns-nft; create_cgroup_root
expect_refusal 22 unsupported
remove_case_root
record_case unsupported_refusal PASS

current_case=nonempty_refusal; persist_state; case_paths nonempty_refusal; write_config
start_generation; stop_generation
sleep 300 & occupant=$!
printf '%s\n' "$occupant" > "$cgroup_root/runtime/cgroup.procs"
expect_refusal 23 nonempty-runtime
kill "$occupant"; wait "$occupant" 2>/dev/null || true
complete_real_uninstall cleanup-after-refusal
record_case nonempty_refusal PASS

current_case=interrupted_resume; persist_state; case_paths interrupted_resume; write_config
start_generation; stop_generation
run_uninstall "$case_dir/dry-run.json" "$case_dir/dry-run.stderr" --dry-run
[[ $command_status -eq 0 ]]
bash -c 'kill -STOP $$; exec "$@"' bash "$binary" uninstall -f "$config" \
  > "$case_dir/interrupted.stdout" 2> "$case_dir/interrupted.stderr" &
interrupted_pid=$!
printf '%s\n' "$interrupted_pid" > "$case_dir/interrupted.pid"
"$tracer" "$interrupted_pid" "$uninstall_intent" /usr/sbin/bpftool uninstall_intent \
  "$case_dir/tracer-ready.json" "$case_dir/uninstall-intent-boundary.json"
set +e; wait "$interrupted_pid"; interrupted_status=$?; set -e
[[ $interrupted_status -eq 137 && -f $uninstall_intent ]]
run_uninstall "$case_dir/startup-after-interruption.stdout" \
  "$case_dir/startup-after-interruption.stderr"
[[ $command_status -eq 0 ]]
jq -e --slurpfile dry "$case_dir/dry-run.json" '
  .sandbox_operations == $dry[0].sandbox_operations and
  .enforcer.operations == $dry[0].enforcer.operations and
  .enforcer.absence_verified == true' "$case_dir/startup-after-interruption.stdout" >/dev/null
assert_no_owned_residue "$case_dir/residue-before-harness-teardown.json"
remove_case_root
record_case interrupted_resume PASS

current_case=target_released; persist_state; case_paths target_released; write_config
start_generation; stop_generation
cp "$state" "$case_dir/state-before-release.json"
rmdir "$cgroup_root/executions" "$cgroup_root/runtime" "$cgroup_root"
create_cgroup_root
printf '+cpu +memory +pids\n' > "$cgroup_root/cgroup.subtree_control"
mkdir "$cgroup_root/runtime" "$cgroup_root/executions"
printf '+cpu +memory +pids\n' > "$cgroup_root/executions/cgroup.subtree_control"
run_uninstall "$case_dir/uninstall.stdout" "$case_dir/uninstall.stderr"
if [[ $command_status -ne 0 ]]; then
  record_case target_released FAIL "production uninstall refused released target with exit $command_status"
  exit 20
fi
jq -e '.enforcer.classification == "TARGET_RELEASED" and .enforcer.absence_verified == true' \
  "$case_dir/uninstall.stdout" >/dev/null
assert_no_owned_residue "$case_dir/residue-before-harness-teardown.json"
remove_case_root
record_case target_released PASS

current_case=complete; persist_state
