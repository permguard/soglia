#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Kill the Enforcer during exact old-generation pin removal, then prove that the next recovery
# completes from the durable INTENT subset without prefix deletion or inherited authority.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
# shellcheck source=spikes/cgroup-bpf/runner/scripts/systemd-cgroup-common.sh
source "$scripts/systemd-cgroup-common.sh"

if [[ $# -ne 5 ]]; then
  echo 'usage: b6-recovery-interrupted.sh <soglia> <driver> <trace> <agent> <evidence>' >&2
  exit 13
fi
binary=$1
driver=$2
tracer=$3
agent=$4
evidence=$5
unit=soglia-b6-recovery-interrupted
runtime=/run/$unit
pin_parent=/sys/fs/bpf/$unit
rootfs=/var/tmp/$unit-rootfs
unit_cgroup=/sys/fs/cgroup/system.slice/$unit.service
config=$evidence/config.yaml

wait_for() {
  local description=$1 predicate=$2
  for _ in $(seq 1 6000); do
    eval "$predicate" && return 0
    sleep 0.01
  done
  echo "timed out waiting for $description" >&2
  return 1
}

cleanup() {
  local status=$?
  set +e
  stop_and_prune_unit_cgroup "$unit" "$evidence/abort-unit-stop" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  if [[ -f $runtime/cgroup-bpf/state.json ]]; then
    jq -r '.links[].pin,.maps[].pin' "$runtime/cgroup-bpf/state.json" | while read -r owned; do
      case "$owned" in "$pin_parent"/*) rm -f "$owned" ;; esac
    done
    owned_root=$(jq -r .pin_root "$runtime/cgroup-bpf/state.json")
    case "$owned_root" in "$pin_parent"/*)
      rmdir "$owned_root/links" "$owned_root/maps" "$owned_root" 2>/dev/null
      ;;
    esac
  fi
  if [[ -f $runtime/net/host.json ]] \
    && [[ $(jq -r .dummy "$runtime/net/host.json" 2>/dev/null) == soglia0 ]]; then
    nft delete table inet soglia_host >/dev/null 2>&1
    ip link delete soglia0 >/dev/null 2>&1
  fi
  find "$runtime" -depth -mindepth 1 -delete 2>/dev/null
  rmdir "$runtime" "$pin_parent" 2>/dev/null
  find "$rootfs" -depth -mindepth 1 -delete 2>/dev/null
  rmdir "$rootfs" 2>/dev/null
  exit "$status"
}
trap cleanup EXIT

mkdir -p "$evidence" "$rootfs"/{proc,dev,sys,tmp}
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
ingress: { listen: "127.0.0.1:18126" }
network:
  backend: cgroup-bpf
  execution_pool: 10.226.0.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
  max_proxy_connections: 64
egress:
  connect_timeout_ms: 1000
  idle_timeout_ms: 30000
  allow: [{ host: allowed.test, ports: [443] }]
cgroup: { root: "$unit_cgroup" }
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

journal_cursor=$(journalctl -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
systemd-run --unit="$unit" --property=Type=exec --property=Delegate=yes \
  --property=KillMode=mixed --property=Restart=no --property=TimeoutStopSec=2s \
  -- "$driver" "$binary" "$config" "$evidence" "$tracer" recovery-interrupted \
  > "$evidence/systemd-run.txt"
systemctl show "$unit.service" -p Delegate -p KillMode -p Restart -p ControlGroup \
  > "$evidence/unit-properties.txt"
grep -Fx 'Delegate=yes' "$evidence/unit-properties.txt"
grep -Fx 'KillMode=mixed' "$evidence/unit-properties.txt"
grep -Fx 'Restart=no' "$evidence/unit-properties.txt"
wait_for driver-exit "[[ \$(systemctl show '$unit.service' -p ActiveState --value) != active ]]"
systemctl show "$unit.service" -p ExecMainStatus -p Result > "$evidence/unit-result.txt"
grep -Fx 'ExecMainStatus=0' "$evidence/unit-result.txt"
grep -Fx 'Result=success' "$evidence/unit-result.txt"
grep -qx PASS "$evidence/verdict.txt"
jq -e '.verdict == "PASS" and .new_generation > .old_generation and
  .old_kernel_ids_absent and .policy_entries == 0 and .cookie_entries == 0 and
  .tuple_entries == 0 and .ready_manifest' "$evidence/recovery.json"
journalctl -u "$unit.service" --after-cursor "$journal_cursor" -o json --no-pager \
  > "$evidence/journal.jsonl"
journalctl -u "$unit.service" --after-cursor "$journal_cursor" -o short-monotonic --no-pager \
  > "$evidence/journal.txt"
jq -n '{restart_deviation:"Restart=no: required to interrupt and inspect recovery twice",
  exact_boundary:"durable INTENT with a strict nonempty subset of recorded pins",
  verdict:"PASS"}' > "$evidence/result.json"
