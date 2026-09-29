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
runc_path=/usr/sbin/runc
if [[ "$case_name" == sandbox_sigkill ]]; then
  runc_path="/var/tmp/$unit-runc-wrapper"
  cat > "$runc_path" <<EOF
#!/usr/bin/env bash
set -euo pipefail
args=("\$@")
create_index=-1
for index in "\${!args[@]}"; do
  [[ "\${args[\$index]}" == create ]] && create_index=\$index
done
/usr/sbin/runc "\${args[@]}"
if [[ \$create_index -ge 0 && -f '$runtime/b6-hold-next-create' ]]; then
  container=\${!#}
  prefix=("\${args[@]:0:\$create_index}")
  /usr/sbin/runc "\${prefix[@]}" state "\$container" \
    > '$evidence/created-not-started-runc-state.json'
  awk '{print \$1}' /proc/uptime > '$evidence/created-not-started-boottime.txt'
  printf '%s\n' "\$container" > '$evidence/created-not-started-marker'
  while [[ ! -f '$runtime/b6-release-create' ]]; do sleep 0.01; done
fi
EOF
  chmod 0755 "$runc_path"
fi

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
two_agents_running() {
  [[ $(journalctl -u "$unit.service" --after-cursor "$journal_cursor" -o cat --no-pager \
    | grep -c 'execution phase.*Running') -ge 2 ]]
}

cleanup() {
  local status=$?
  set +e
  if [[ -d $unit_cgroup/executions ]]; then
    find "$unit_cgroup/executions" -mindepth 1 -maxdepth 1 -type d -exec sh -c \
      'echo 0 > "$1/cgroup.freeze" 2>/dev/null || true' _ {} \;
  fi
  systemctl stop "$unit.service" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  if [[ -f $runtime/cgroup-bpf/state.json ]]; then
    jq -r '.executions[].tag // empty' "$runtime/cgroup-bpf/state.json" | while read -r tag; do
      ip netns delete "soglia-${tag:0:10}" >/dev/null 2>&1
      ip link delete "sgh-${tag:0:10}" >/dev/null 2>&1
    done
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
  [[ "$runc_path" != /usr/sbin/runc ]] && rm -f "$runc_path"
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
  runc: $runc_path
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

journal_cursor=$(journalctl -n 0 --show-cursor --no-pager \
  | sed -n 's/^-- cursor: //p')
[[ -n "$journal_cursor" ]]
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

proxy_command='proxy-fixed-report 40000 1 /tmp/b6-unresolved.jsonl 30'
staged_lifecycle=false
created_pid=0
first_cgroup=
if [[ "$case_name" == resolve_channel_watchdog ]]; then
  proxy_command='delayed-proxy-fixed-report 3000 40000 1 /tmp/b6-unresolved.jsonl 30'
fi
if [[ "$case_name" == sandbox_sigkill ]]; then
  staged_lifecycle=true
  wait_for first-running "[[ \$(SYSTEMD_COLORS=0 journalctl -u '$unit.service' --after-cursor '$journal_cursor' -o cat --no-pager | grep -c 'execution phase.*Running') -ge 1 ]]"
  first_cgroup=$(find "$unit_cgroup/executions" -mindepth 1 -maxdepth 1 -type d | head -1)
  echo 1 > "$first_cgroup/cgroup.freeze"
  wait_for first-frozen "grep -q '^frozen 1$' '$first_cgroup/cgroup.events'"
  {
    printf 'cgroup=%s\n' "$first_cgroup"
    cat "$first_cgroup/cgroup.events"
    printf 'procs:\n'
    cat "$first_cgroup/cgroup.procs"
  } > "$evidence/frozen-execution-before-loss.txt"
  : > "$runtime/b6-hold-next-create"
  proxy_command='sleep 30000'
fi
curl --silent --show-error --max-time 45 -X POST \
  --data-binary "$proxy_command" \
  http://127.0.0.1:18106/v1/execute/probe > "$evidence/proxy-client.txt" 2>&1 &
proxy_client=$!
wait_for two-executions "[[ \$(find '$unit_cgroup/executions' -mindepth 1 -maxdepth 1 -type d | wc -l) -ge 2 ]]"
wait_for two-execution-agents "[[ \$(cat '$unit_cgroup'/executions/*/cgroup.procs 2>/dev/null | sed '/^$/d' | wc -l) -ge 2 ]]"
if [[ "$case_name" == sandbox_sigkill ]]; then
  wait_for created-not-started "[[ -f '$evidence/created-not-started-marker' ]]"
  rm "$runtime/b6-hold-next-create"
  jq -e '.status == "created" and (.pid | type == "number")' \
    "$evidence/created-not-started-runc-state.json"
  created_pid=$(jq -r .pid "$evidence/created-not-started-runc-state.json")
  created_cgroup=$(grep -l -x "$created_pid" "$unit_cgroup"/executions/*/cgroup.procs \
    | xargs -r -n1 dirname)
  [[ -n "$created_cgroup" && "$created_cgroup" != "$first_cgroup" ]]
  {
    printf 'cgroup=%s\n' "$created_cgroup"
    cat "$created_cgroup/cgroup.events"
    printf 'procs:\n'
    cat "$created_cgroup/cgroup.procs"
  } > "$evidence/created-not-started-before-loss.txt"
  ! grep -q '^frozen 1$' "$created_cgroup/cgroup.events"
else
  wait_for two-running-executions two_agents_running
fi

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
cp "$runtime/cgroup-bpf/state.json" "$evidence/state-before-loss.json"
old_generation=$(jq -r .generation "$evidence/state-before-loss.json")
old_attachment_inode=$(jq -r .attachment_inode "$evidence/state-before-loss.json")

loss_at=$(boot_now)
case "$case_name" in
  enforcer_sigkill) kill -KILL "$enforcer" ;;
  supervisor_sigkill) kill -KILL "$old_main" ;;
  sandbox_sigkill) kill -KILL "$sandbox" ;;
  resolve_channel_watchdog)
    kill -STOP "$enforcer"
    wait_for enforcer-stopped "grep -q '^State:[[:space:]]*T' '/proc/$enforcer/status'"
    ;;
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

journalctl -u "$unit.service" --after-cursor "$journal_cursor" -o json --no-pager \
  > "$evidence/journal.jsonl"
journalctl -u "$unit.service" --after-cursor "$journal_cursor" -o short-monotonic --no-pager \
  > "$evidence/journal.txt"
jq -e 'all(.[]; has("__MONOTONIC_TIMESTAMP"))' < <(jq -s . "$evidence/journal.jsonl")
grep -q 'event.name=cgroup_bpf.target_released result=PASS' "$evidence/journal.txt"
[[ $(grep -c 'event.name=cgroup_bpf.target_released_link_observation' "$evidence/journal.txt") -eq 6 ]]
! grep 'event.name=cgroup_bpf.target_released_link_observation' "$evidence/journal.txt" \
  | grep -Ev 'cgroup_id=0([^0-9]|$)'
grep -q 'event.name=cgroup_bpf.recovery_cleanup_observation' "$evidence/journal.txt"
grep -q 'event.name=cgroup_bpf.ready generation=2' "$evidence/journal.txt"
target_released_line=$(grep -n -m1 'event.name=cgroup_bpf.target_released result=PASS' \
  "$evidence/journal.txt" | cut -d: -f1)
cleanup_observed_line=$(grep -n -m1 'event.name=cgroup_bpf.recovery_cleanup_observation' \
  "$evidence/journal.txt" | cut -d: -f1)
ready_line=$(grep -n -m1 'event.name=cgroup_bpf.ready generation=2' \
  "$evidence/journal.txt" | cut -d: -f1)
[[ "$target_released_line" -lt "$cleanup_observed_line" ]]
[[ "$cleanup_observed_line" -lt "$ready_line" ]]
nft -j list table inet soglia_b6_observe > "$evidence/effects-after-restart.json"
ss -H -n -t -a > "$evidence/sockets-after-restart.txt"
cp "$runtime/cgroup-bpf/state.json" "$evidence/state-after-restart.json"
new_generation=$(jq -r .generation "$evidence/state-after-restart.json")
new_attachment_inode=$(jq -r .attachment_inode "$evidence/state-after-restart.json")
[[ "$new_generation" -gt "$old_generation" ]]
[[ "$new_attachment_inode" != "$old_attachment_inode" ]]
for map in soglia_policy soglia_cookie_a soglia_tuples; do
  pin=$(jq -r --arg map "$map" '.maps[] | select(.name == $map) | .pin' \
    "$evidence/state-after-restart.json")
  bpftool -j map dump pinned "$pin" > "$evidence/new-$map.json"
  jq -e 'length == 0' "$evidence/new-$map.json"
done
bpftool -j prog show > "$evidence/programs-after-restart.json"
bpftool -j link show > "$evidence/links-after-restart.json"
bpftool -j map show > "$evidence/maps-after-restart.json"
jq -e --slurpfile current "$evidence/programs-after-restart.json" \
  'all(.programs[]; .id as $id | $id == 0 or ([ $current[0][].id ] | index($id)) == null)' \
  "$evidence/state-before-loss.json"
jq -e --slurpfile current "$evidence/links-after-restart.json" \
  'all(.links[]; .id as $id | $id == 0 or ([ $current[0][].id ] | index($id)) == null)' \
  "$evidence/state-before-loss.json"
jq -e --slurpfile current "$evidence/maps-after-restart.json" \
  'all(.maps[]; .id as $id | $id == 0 or ([ $current[0][].id ] | index($id)) == null)' \
  "$evidence/state-before-loss.json"

effect_packets() {
  local file=$1 comment=$2
  jq --arg comment "$comment" '[.. | objects |
    select(.comment? == $comment) | .counter.packets // 0] | add // 0' "$file"
}
for comment in b6_dns b6_dns_tcp b6_outbound; do
  before=$(effect_packets "$evidence/effects-at-loss.json" "$comment")
  after=$(effect_packets "$evidence/effects-after-restart.json" "$comment")
  [[ "$after" -eq "$before" ]]
done

barrier=SYSTEMD_KILL_BARRIER
if [[ "$case_name" == enforcer_sigkill ]]; then
  # The main process waits for sandboxd EOF cleanup before returning the failure to systemd.
  barrier=SANDBOX_KILL_ALL_BEFORE_MAIN_EXIT
fi
jq -n --arg case "$case_name" --argjson old_main "$old_main" --argjson new_main "$new_main" \
  --argjson old_restarts "$old_restarts" --argjson new_restarts "$new_restarts" \
  --arg loss_at "$loss_at" --arg barrier "$barrier" --argjson agents "$(printf '%s\n' "${old_agents[@]}" | jq -Rsc 'split("\n")|map(select(length>0)|tonumber)')" \
  --argjson old_generation "$old_generation" --argjson new_generation "$new_generation" \
  --argjson old_attachment_inode "$old_attachment_inode" \
  --argjson new_attachment_inode "$new_attachment_inode" \
  --argjson staged_lifecycle "$staged_lifecycle" --argjson created_pid "$created_pid" \
  --arg frozen_cgroup "$first_cgroup" \
  '{case:$case,old_main_pid:$old_main,new_main_pid:$new_main,nrestarts_before:$old_restarts,
    nrestarts_after:$new_restarts,loss_boottime_seconds:($loss_at|tonumber),old_agent_pids:$agents,
    old_agents_absent_before_new_main:true,barrier_attribution:$barrier,
    unit:{Delegate:true,KillMode:"mixed",Restart:"on-failure"},
    lifecycle_preconditions:{frozen_execution:$staged_lifecycle,
      frozen_cgroup:(if $staged_lifecycle then $frozen_cgroup else null end),
      created_not_started:$staged_lifecycle,
      created_not_started_pid:(if $staged_lifecycle then $created_pid else null end)},
    target_released:{old_generation:$old_generation,new_generation:$new_generation,
      old_attachment_inode:$old_attachment_inode,new_attachment_inode:$new_attachment_inode,
      links_observed_detached:6,detach_timeout_ms:5000,poll_interval_ms:10,
      old_ids_absent:true,new_authorization_maps_empty:true},verdict:"PASS"}' \
  > "$evidence/result.json"
printf '%s\n' PASS > "$evidence/verdict.txt"

kill "$sleep_client" "$proxy_client" >/dev/null 2>&1 || true
wait "$sleep_client" "$proxy_client" >/dev/null 2>&1 || true
