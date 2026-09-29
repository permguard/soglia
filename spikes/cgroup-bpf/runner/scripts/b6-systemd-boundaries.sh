#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Exercise every durable host and per-Execution crash boundary through the real production
# systemd topology. The first driver incarnation is killed at the exact ptrace boundary and exits
# unsuccessfully; Restart=on-failure creates a new delegated target and the second incarnation
# must recover it through TargetReleased.

set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo 'usage: b6-systemd-boundaries.sh <soglia> <driver> <trace> <agent> <evidence>' >&2
  exit 13
fi
binary=$1
driver=$2
tracer=$3
agent=$4
evidence=$5
active_unit=
active_runtime=
active_pin_parent=
active_rootfs=

host_boundaries=(host_intent host_maps_pinned host_kernel_validated host_ready)
execution_boundaries=(
  01-reserved
  02-record-without-policy
  03-prepared
  04-created-paused
  05-policy-active-before-record
  06-active
  07-policy-frozen-before-record
  08-sandbox-destroyed
  09-policy-removed-before-record
)

wait_for() {
  local description=$1 predicate=$2
  for _ in $(seq 1 3000); do
    eval "$predicate" && return 0
    sleep 0.01
  done
  echo "timed out waiting for $description" >&2
  return 1
}

remove_case_resources() {
  local unit=$1 runtime=$2 pin_parent=$3 rootfs=$4
  local state="$runtime/cgroup-bpf/state.json"
  set +e
  systemctl stop "$unit.service" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  if [[ -f "$state" ]] && jq -e '.pin_root and .links and .maps' "$state" >/dev/null 2>&1; then
    while IFS= read -r pin; do
      case "$pin" in "$pin_parent"/*) [[ ! -e "$pin" ]] || rm -f "$pin" ;; esac
    done < <(jq -r '.links[].pin,.maps[].pin' "$state")
    owned_root=$(jq -r .pin_root "$state")
    case "$owned_root" in "$pin_parent"/*)
      rmdir "$owned_root/links" "$owned_root/maps" "$owned_root" 2>/dev/null
      ;;
    esac
  fi
  if [[ -f "$runtime/net/host.json" ]] \
    && [[ $(jq -r .dummy "$runtime/net/host.json" 2>/dev/null) == soglia0 ]]; then
    nft delete table inet soglia_host >/dev/null 2>&1
    ip link delete soglia0 >/dev/null 2>&1
  fi
  find "$runtime" -depth -mindepth 1 -delete 2>/dev/null
  rmdir "$runtime" "$pin_parent" 2>/dev/null
  find "$rootfs" -depth -mindepth 1 -delete 2>/dev/null
  rmdir "$rootfs" 2>/dev/null
  set -e
}

cleanup_on_exit() {
  local status=$?
  if [[ -n "$active_unit" ]]; then
    remove_case_resources "$active_unit" "$active_runtime" "$active_pin_parent" "$active_rootfs"
  fi
  exit "$status"
}
trap cleanup_on_exit EXIT

run_case() {
  local family=$1 boundary=$2 ordinal=$3
  local safe=${boundary//_/-}
  local unit="soglia-b6-${family}-${ordinal}"
  local case_evidence="$evidence/${family}-${boundary}"
  local runtime="/run/$unit"
  local pin_parent="/sys/fs/bpf/$unit"
  local rootfs="/var/tmp/$unit-rootfs"
  local unit_cgroup="/sys/fs/cgroup/system.slice/$unit.service"
  local config="$case_evidence/config.yaml"
  local mode="systemd-$family-boundary"
  active_unit=$unit
  active_runtime=$runtime
  active_pin_parent=$pin_parent
  active_rootfs=$rootfs
  remove_case_resources "$unit" "$runtime" "$pin_parent" "$rootfs"
  mkdir -p "$case_evidence" "$rootfs"/{proc,dev,sys,tmp}
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
  listen: 127.0.0.1:$((18200 + ordinal))
network:
  backend: cgroup-bpf
  execution_pool: 10.207.$ordinal.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
egress:
  connect_timeout_ms: 1000
  idle_timeout_ms: 30000
  allow:
    - { host: allowed.test, ports: [443] }
cgroup:
  root: $unit_cgroup
cgroup_bpf:
  max_tracked_sockets: 64
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: $pin_parent
agents:
  b6-hold:
    rootfs: $rootfs
    command: ["/agent", "serve"]
    env: {}
    timeout_ms: 40000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
YAML

  date +%s > "$case_evidence/started-at.txt"
  systemd-run --unit="$unit" --property=Type=exec --property=Delegate=yes \
    --property=KillMode=mixed --property=Restart=on-failure --property=RestartSec=100ms \
    --property=TimeoutStopSec=2s -- "$driver" "$binary" "$config" "$case_evidence" \
    "$tracer" "$mode" "$boundary" > "$case_evidence/systemd-run.txt"
  systemctl show "$unit.service" -p Delegate -p KillMode -p Restart -p RestartUSec \
    -p NRestarts -p ControlGroup > "$case_evidence/unit-properties.txt"
  grep -Fx 'Delegate=yes' "$case_evidence/unit-properties.txt"
  grep -Fx 'KillMode=mixed' "$case_evidence/unit-properties.txt"
  grep -Fx 'Restart=on-failure' "$case_evidence/unit-properties.txt"
  wait_for "$family $boundary recovery" "[[ -f '$case_evidence/verdict.txt' ]] && grep -qx PASS '$case_evidence/verdict.txt'"
  systemctl show "$unit.service" -p NRestarts --value > "$case_evidence/nrestarts.txt"
  [[ $(cat "$case_evidence/nrestarts.txt") -eq 1 ]]
  journalctl -u "$unit.service" --since "@$(cat "$case_evidence/started-at.txt")" --no-pager \
    -o json > "$case_evidence/journal.jsonl"
  journalctl -u "$unit.service" --since "@$(cat "$case_evidence/started-at.txt")" --no-pager \
    -o short-monotonic > "$case_evidence/journal.txt"
  grep -q 'event.name=cgroup_bpf.target_released result=PASS' "$case_evidence/journal.jsonl"
  observed_links=$(grep -c 'event.name=cgroup_bpf.target_released_link_observation' \
    "$case_evidence/journal.jsonl" || true)
  if [[ "$family" == host && "$boundary" != host_ready ]]; then
    [[ "$observed_links" -eq 0 ]]
  else
    [[ "$observed_links" -ge 6 ]]
  fi
  jq -e '.verdict == "PASS" and .new_generation > .old_generation and
    .old_kernel_ids_absent and .policy_entries == 0 and .cookie_entries == 0 and
    .tuple_entries == 0 and .ready_manifest' "$case_evidence/recovery.json"
  jq -n --arg family "$family" --arg boundary "$boundary" \
    --argjson restarts "$(cat "$case_evidence/nrestarts.txt")" \
    '{family:$family,boundary:$boundary,restarts:$restarts,target_released:true,
      fixed_detach_timeout_ms:5000,fixed_poll_interval_ms:10,verdict:"PASS"}' \
    > "$case_evidence/result.json"
  touch "$case_evidence/inspection-complete"
  wait_for "$family $boundary clean exit" \
    "[[ \$(systemctl show '$unit.service' -p ActiveState --value) != active ]]"
  remove_case_resources "$unit" "$runtime" "$pin_parent" "$rootfs"
  active_unit=
  active_runtime=
  active_pin_parent=
  active_rootfs=
}

mkdir -p "$evidence"
ordinal=1
for boundary in "${host_boundaries[@]}"; do
  run_case host "$boundary" "$ordinal"
  ordinal=$((ordinal + 1))
done
for boundary in "${execution_boundaries[@]}"; do
  run_case execution "$boundary" "$ordinal"
  ordinal=$((ordinal + 1))
done
printf '%s\n' PASS > "$evidence/verdict.txt"
trap - EXIT
