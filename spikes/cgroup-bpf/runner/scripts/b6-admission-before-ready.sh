#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Stops the production main thread at the successful ingress listen syscall and proves that the
# already-bound listener refuses admission until the READY gate is opened.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
# shellcheck source=spikes/cgroup-bpf/runner/scripts/systemd-cgroup-common.sh
source "$scripts/systemd-cgroup-common.sh"

if [[ $# -ne 4 ]]; then
  echo 'usage: b6-admission-before-ready.sh <soglia> <trace> <agent> <evidence>' >&2
  exit 13
fi
binary=$1
tracer=$2
agent=$3
evidence=$4
unit=soglia-b6-admission-before-ready
runtime=/run/$unit
pin_parent=/sys/fs/bpf/$unit
rootfs=/var/tmp/$unit-rootfs
unit_cgroup=/sys/fs/cgroup/system.slice/$unit.service
port=18116
config=$evidence/config.yaml
trace_ready=$evidence/trace-ready.json
observation=$evidence/listener-observation.json
release=$evidence/listener-observation.release
trace_pid=

wait_for() {
  local description=$1 predicate=$2
  for _ in $(seq 1 3000); do
    eval "$predicate" && return 0
    sleep 0.01
  done
  echo "timed out waiting for $description" >&2
  return 1
}

cleanup() {
  local status=$?
  set +e
  [[ -z "$trace_pid" ]] || kill "$trace_pid" >/dev/null 2>&1
  [[ -z "$trace_pid" ]] || wait "$trace_pid" >/dev/null 2>&1
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
ingress:
  listen: 127.0.0.1:$port
network:
  backend: cgroup-bpf
  execution_pool: 10.216.0.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
  max_proxy_connections: 64
egress:
  connect_timeout_ms: 1000
  idle_timeout_ms: 30000
  allow: [{ host: allowed.test, ports: [443] }]
cgroup:
  root: $unit_cgroup
cgroup_bpf:
  max_tracked_sockets: 64
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: $pin_parent
agents:
  probe:
    rootfs: $rootfs
    command: ["/agent", "serve"]
    env: {}
    timeout_ms: 40000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
YAML

journal_cursor=$(journalctl -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
[[ -n "$journal_cursor" ]]
systemd-run --unit="$unit" --property=Type=simple --property=Delegate=yes \
  --property=KillMode=mixed --property=Restart=no --property=TimeoutStopSec=2s \
  -- /bin/bash -c 'kill -STOP 0; exec "$@"' bash "$binary" run -f "$config" \
  > "$evidence/systemd-run.txt"
systemctl show "$unit.service" -p Delegate -p KillMode -p Restart -p ControlGroup \
  > "$evidence/unit-properties.txt"
grep -Fx 'Delegate=yes' "$evidence/unit-properties.txt"
grep -Fx 'KillMode=mixed' "$evidence/unit-properties.txt"
grep -Fx 'Restart=no' "$evidence/unit-properties.txt"
wait_for main-pid "[[ \$(systemctl show '$unit.service' -p MainPID --value) -gt 0 ]]"
main_pid=$(systemctl show "$unit.service" -p MainPID --value)
"$tracer" "$main_pid" "$runtime/cgroup-bpf/state.json" /usr/sbin/bpftool \
  "startup_listener_bound:$port" "$trace_ready" "$observation" \
  > "$evidence/trace.stdout" 2> "$evidence/trace.stderr" &
trace_pid=$!
wait_for tracer-seized "[[ -f '$trace_ready' ]]"
kill -CONT "$main_pid"
wait_for listener-boundary "[[ -f '$observation' ]]"
ss -H -ltn "sport = :$port" > "$evidence/listener-before-ready.txt"
grep -q . "$evidence/listener-before-ready.txt"
journalctl -u "$unit.service" --after-cursor "$journal_cursor" -o short-monotonic --no-pager \
  > "$evidence/journal-before-ready.txt"
! grep -q 'event.name="startup.ready"' "$evidence/journal-before-ready.txt"
before_code=$(jq -r .response_status "$observation")
[[ "$before_code" == 503 ]]
jq -r .response_head "$observation" > "$evidence/before-ready-response.txt"
find "$unit_cgroup/executions" -mindepth 1 -maxdepth 1 -type d \
  > "$evidence/executions-before-ready.txt"
[[ ! -s "$evidence/executions-before-ready.txt" ]]

touch "$release"
wait "$trace_pid"
trace_pid=
wait_for startup-ready "journalctl -u '$unit.service' --after-cursor '$journal_cursor' -o cat --no-pager | grep -q 'soglia is ready'"
after_code=$(curl --silent --show-error --max-time 10 -o "$evidence/after-ready-response.json" \
  -w '%{http_code}' -X POST --data-binary 'sleep 1' "http://127.0.0.1:$port/v1/execute/probe")
[[ "$after_code" == 200 ]]
journalctl -u "$unit.service" --after-cursor "$journal_cursor" -o json --no-pager \
  > "$evidence/journal.jsonl"
journalctl -u "$unit.service" --after-cursor "$journal_cursor" -o short-monotonic --no-pager \
  > "$evidence/journal.txt"
jq -e '.verdict == "MATCHED" and .listener_port == 18116 and .response_status == 503' \
  "$observation"
jq -n --argjson main_pid "$main_pid" --argjson before_code "$before_code" \
  --argjson after_code "$after_code" \
  '{main_pid:$main_pid,listener_bound_before_ready:true,before_ready_status:$before_code,
    execution_created_before_ready:false,after_ready_status:$after_code,
    restart_deviation:"Restart=no: required to hold and inspect the pre-READY process",
    verdict:"PASS"}' > "$evidence/result.json"
printf '%s\n' PASS > "$evidence/verdict.txt"
