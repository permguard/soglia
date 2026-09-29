#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# One production-systemd B6 loss case. The caller supplies an otherwise idle host.

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo 'usage: b6-systemd-loss.sh <soglia> <agent> <case> <evidence>' >&2
  exit 13
fi
binary=$1
agent=$2
case_name=$3
evidence=$4
case "$case_name" in
  enforcer_sigkill|supervisor_sigkill|sandbox_sigkill|resolve_channel_watchdog) ;;
  *) echo "unknown B6 loss case: $case_name" >&2; exit 13 ;;
esac

suffix=${case_name//_/-}
unit="soglia-b6-$suffix"
runtime="/run/$unit"
pin_parent="/sys/fs/bpf/$unit"
rootfs="/var/tmp/$unit-rootfs"
config="$evidence/config.yaml"
unit_cgroup="/sys/fs/cgroup/system.slice/$unit.service"
mkdir -p "$evidence" "$rootfs"/{proc,dev,sys,tmp}
install -m 0755 "$agent" "$rootfs/agent"

boot_now() { awk '{print $1}' /proc/uptime; }
proc_alive() { [[ -d /proc/$1 ]]; }
main_pid() { systemctl show "$unit.service" -p MainPID --value; }
nrestarts() { systemctl show "$unit.service" -p NRestarts --value; }
helper_pid() {
  local parent=$1 role=$2 child cmd
  for child in $(find "/proc/$parent/task" -mindepth 2 -maxdepth 2 -name children -type f -exec cat {} + 2>/dev/null); do
    [[ -r /proc/$child/cmdline ]] || continue
    cmd=$(tr '\0' ' ' < "/proc/$child/cmdline")
    [[ "$cmd" == *"$role"* ]] && { echo "$child"; return 0; }
  done
  return 1
}
wait_for() {
  local description=$1 predicate=$2
  for _ in $(seq 1 1200); do
    eval "$predicate" && return 0
    sleep 0.01
  done
  echo "timed out waiting for $description" >&2
  return 1
}

cleanup() {
  local status=$?
  set +e
  systemctl stop "$unit.service" >/dev/null 2>&1
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
  if [[ -f $runtime/net/host.json ]] && [[ $(jq -r .dummy "$runtime/net/host.json" 2>/dev/null) == soglia0 ]]; then
    nft delete table inet soglia_host >/dev/null 2>&1
    ip link delete soglia0 >/dev/null 2>&1
  fi
  rm -rf "$runtime" "$rootfs"
  rmdir "$pin_parent" 2>/dev/null
  nft delete table inet soglia_b6_observe >/dev/null 2>&1
  exit "$status"
}
trap cleanup EXIT

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
  listen: 127.0.0.1:18106
network:
  backend: cgroup-bpf
  execution_pool: 10.206.0.0/24
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
  probe:
    rootfs: $rootfs
    command: ["/agent", "serve"]
    env: {}
    timeout_ms: 40000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
YAML

# These counters observe effects independently of the proxy's own logs.
nft add table inet soglia_b6_observe
nft 'add chain inet soglia_b6_observe output { type filter hook output priority 200; policy accept; }'
nft add rule inet soglia_b6_observe output meta skuid 65534 udp dport 53 counter comment b6_dns
nft add rule inet soglia_b6_observe output meta skuid 65534 tcp dport 53 counter comment b6_dns_tcp
nft add rule inet soglia_b6_observe output meta skuid 65534 ip daddr != 10.200.255.1 counter comment b6_outbound
nft -j list table inet soglia_b6_observe > "$evidence/effects-before.json"

started=$(boot_now)
systemd-run --unit="$unit" --property=Type=simple --property=Delegate=yes \
  --property=KillMode=mixed --property=Restart=on-failure --property=RestartSec=100ms \
  --property=TimeoutStopSec=2s -- "$binary" run -f "$config" > "$evidence/systemd-run.txt"
systemctl show "$unit.service" -p Delegate -p KillMode -p Restart -p RestartUSec -p NRestarts \
  -p ControlGroup > "$evidence/unit-properties.txt"
grep -Fx 'Delegate=yes' "$evidence/unit-properties.txt"
grep -Fx 'KillMode=mixed' "$evidence/unit-properties.txt"
grep -Fx 'Restart=on-failure' "$evidence/unit-properties.txt"
wait_for startup-ready "ss -H -ltn 'sport = :18106' | grep -q ."
old_main=$(main_pid)
old_restarts=$(nrestarts)
wait_for helpers "helper_pid '$old_main' __enforcer >/dev/null && helper_pid '$old_main' __sandboxd >/dev/null"
enforcer=$(helper_pid "$old_main" __enforcer)
sandbox=$(helper_pid "$old_main" __sandboxd)

curl --silent --show-error --max-time 45 -X POST --data-binary 'sleep 30000' \
  http://127.0.0.1:18106/v1/execute/probe > "$evidence/sleep-client.txt" 2>&1 &
sleep_client=$!
wait_for first-execution "find '$unit_cgroup/executions' -mindepth 1 -maxdepth 1 -type d | grep -q ."

if [[ "$case_name" == resolve_channel_watchdog ]]; then
  kill -STOP "$enforcer"
fi
curl --silent --show-error --max-time 45 -X POST \
  --data-binary 'proxy-fixed-report 40000 1 /tmp/b6-unresolved.jsonl 30' \
  http://127.0.0.1:18106/v1/execute/probe > "$evidence/proxy-client.txt" 2>&1 &
proxy_client=$!
wait_for two-executions "[[ \$(find '$unit_cgroup/executions' -mindepth 1 -maxdepth 1 -type d | wc -l) -ge 2 ]]"

mapfile -t execution_cgroups < <(find "$unit_cgroup/executions" -mindepth 1 -maxdepth 1 -type d | sort)
old_agents=()
event_fds=()
for cgroup in "${execution_cgroups[@]}"; do
  while read -r pid; do [[ -n "$pid" ]] && old_agents+=("$pid"); done < "$cgroup/cgroup.procs"
  exec {event_fd}< "$cgroup/cgroup.events"
  event_fds+=("$event_fd")
done
printf '%s\n' "${old_agents[@]}" > "$evidence/old-agent-pids.txt"
ss -H -n -t -a > "$evidence/sockets-before-loss.txt"
nft -j list table inet soglia_b6_observe > "$evidence/effects-at-loss.json"

loss_at=$(boot_now)
case "$case_name" in
  enforcer_sigkill) kill -KILL "$enforcer" ;;
  supervisor_sigkill) kill -KILL "$old_main" ;;
  sandbox_sigkill) kill -KILL "$sandbox" ;;
  resolve_channel_watchdog) : ;;
esac

: > "$evidence/timeline.jsonl"
agents_gone_before_restart=false
for _ in $(seq 1 1500); do
  now=$(boot_now)
  current_main=$(main_pid 2>/dev/null || echo 0)
  current_restarts=$(nrestarts 2>/dev/null || echo 0)
  alive=0
  for pid in "${old_agents[@]}"; do proc_alive "$pid" && alive=$((alive + 1)); done
  jq -cn --arg now "$now" --argjson main "${current_main:-0}" --argjson restarts "${current_restarts:-0}" \
    --argjson old_agents_alive "$alive" \
    '{boottime_seconds:($now|tonumber),main_pid:$main,nrestarts:$restarts,old_agents_alive:$old_agents_alive}' \
    >> "$evidence/timeline.jsonl"
  if [[ "$current_main" != 0 && "$current_main" != "$old_main" ]]; then
    [[ $alive -eq 0 ]] && agents_gone_before_restart=true
    break
  fi
  sleep 0.01
done

new_main=$(main_pid)
new_restarts=$(nrestarts)
[[ "$new_main" != 0 && "$new_main" != "$old_main" ]]
[[ "$new_restarts" -eq $((old_restarts + 1)) ]]
[[ "$agents_gone_before_restart" == true ]]
: > "$evidence/execution-cgroup-events-before-new-main.txt"
for index in "${!event_fds[@]}"; do
  cgroup=${execution_cgroups[$index]}
  fd=${event_fds[$index]}
  if [[ -e "$cgroup" ]]; then
    cat "/proc/$$/fd/$fd" >> "$evidence/execution-cgroup-events-before-new-main.txt"
  else
    printf 'cgroup=%s state=ABSENT_AFTER_VERIFIED_KILL\n' "$cgroup" \
      >> "$evidence/execution-cgroup-events-before-new-main.txt"
  fi
done
! grep -q '^populated 1$' "$evidence/execution-cgroup-events-before-new-main.txt"
wait_for restarted-ready "ss -H -ltn 'sport = :18106' | grep -q ."

journalctl -u "$unit.service" -o json --no-pager > "$evidence/journal.jsonl"
jq -e 'all(.[]; has("__MONOTONIC_TIMESTAMP"))' < <(jq -s . "$evidence/journal.jsonl")
grep -q 'startup.swept' "$evidence/journal.jsonl"
grep -q 'startup.ready' "$evidence/journal.jsonl"
nft -j list table inet soglia_b6_observe > "$evidence/effects-after-restart.json"
ss -H -n -t -a > "$evidence/sockets-after-restart.txt"

barrier=SYSTEMD_KILL_BARRIER
if [[ "$case_name" == enforcer_sigkill ]]; then
  # The main process waits for sandboxd EOF cleanup before returning the failure to systemd.
  barrier=SANDBOX_KILL_ALL_BEFORE_MAIN_EXIT
fi
jq -n --arg case "$case_name" --argjson old_main "$old_main" --argjson new_main "$new_main" \
  --argjson old_restarts "$old_restarts" --argjson new_restarts "$new_restarts" \
  --arg loss_at "$loss_at" --arg barrier "$barrier" --argjson agents "$(printf '%s\n' "${old_agents[@]}" | jq -Rsc 'split("\n")|map(select(length>0)|tonumber)')" \
  '{case:$case,old_main_pid:$old_main,new_main_pid:$new_main,nrestarts_before:$old_restarts,
    nrestarts_after:$new_restarts,loss_boottime_seconds:($loss_at|tonumber),old_agent_pids:$agents,
    old_agents_absent_before_new_main:true,barrier_attribution:$barrier,
    unit:{Delegate:true,KillMode:"mixed",Restart:"on-failure"},verdict:"PASS"}' \
  > "$evidence/result.json"
printf '%s\n' PASS > "$evidence/verdict.txt"

kill "$sleep_client" "$proxy_client" >/dev/null 2>&1 || true
wait "$sleep_client" "$proxy_client" >/dev/null 2>&1 || true
