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
target_offline_diagnostic=${B6_TARGET_OFFLINE_DIAGNOSTIC:-false}
target_offline_page_cache_mb=${B6_TARGET_OFFLINE_PAGE_CACHE_MB:-0}
target_offline_detach=${B6_TARGET_OFFLINE_DETACH:-false}
case "$target_offline_diagnostic" in
  true|false) ;;
  *) echo 'B6_TARGET_OFFLINE_DIAGNOSTIC must be true or false' >&2; exit 13 ;;
esac
if [[ $target_offline_diagnostic == true && $case_name != sandbox_sigkill ]]; then
  echo 'target-offline diagnostics are valid only for sandbox_sigkill' >&2
  exit 13
fi
if [[ ! $target_offline_page_cache_mb =~ ^[0-9]+$ ]] \
  || ((target_offline_page_cache_mb > 1024)); then
  echo 'B6_TARGET_OFFLINE_PAGE_CACHE_MB must be an integer from 0 to 1024' >&2
  exit 13
fi
case "$target_offline_detach" in
  true|false) ;;
  *) echo 'B6_TARGET_OFFLINE_DETACH must be true or false' >&2; exit 13 ;;
esac
if [[ $target_offline_diagnostic != true && $target_offline_page_cache_mb != 0 ]]; then
  echo 'page-cache injection is qualification-only' >&2
  exit 13
fi
if [[ $target_offline_diagnostic != true && $target_offline_detach == true ]]; then
  echo 'explicit link detach is qualification-only' >&2
  exit 13
fi

suffix=${case_name//_/-}
unit="soglia-b6-$suffix"
runtime="/run/$unit"
pin_parent="/sys/fs/bpf/$unit"
rootfs="/var/tmp/$unit-rootfs"
config="$evidence/config.yaml"
unit_cgroup="/sys/fs/cgroup/system.slice/$unit.service"
offline_helper=/var/tmp/soglia-b6-offline-kernel
offline_handle_pid=
mkdir -p "$evidence" "$rootfs"/{proc,dev,sys,tmp}
install -m 0755 "$agent" "$rootfs/agent"
if [[ $target_offline_diagnostic == true ]]; then
  {
    printf 'head='
    git -C /soglia rev-parse HEAD
    printf 'working_tree:\n'
    git -C /soglia status --short
    printf 'artifacts_and_sources:\n'
    sha256sum "$binary" "$agent" "$0" \
      /soglia/spikes/cgroup-bpf/runner/helpers/b6-offline-kernel.c \
      /soglia/crates/soglia-enforcer/src/cgroup_bpf.rs
    printf 'parameters: page_cache_mb=%s explicit_detach=%s\n' \
      "$target_offline_page_cache_mb" "$target_offline_detach"
  } > "$evidence/diagnostic-source-fingerprint.txt"
fi
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

capture_cgroup_diagnostic() {
  local label=$1 path=$2 output=$3
  {
    printf 'label=%s\npath=%s\nboottime_seconds=%s\n' "$label" "$path" "$(boot_now)"
    if [[ -d $path ]]; then
      printf 'state=PRESENT\n'
      stat -Lc 'inode=%i owner_uid=%u owner_gid=%g mode=%a' "$path"
      printf '%s\n' '--- cgroup.stat ---'
      cat "$path/cgroup.stat"
      if [[ -r $path/memory.current ]]; then
        printf '%s\n' '--- memory.current ---'
        cat "$path/memory.current"
      fi
      if [[ -r $path/memory.stat ]]; then
        printf '%s\n' '--- memory.stat ---'
        cat "$path/memory.stat"
      fi
    else
      printf 'state=ABSENT\n'
    fi
  } > "$output"
}

capture_link_diagnostic() {
  local label=$1 output=$2
  local pin name status sample
  : > "$output"
  while IFS=$'\t' read -r name pin; do
    sample=$(mktemp)
    set +e
    bpftool -j link show pinned "$pin" > "$sample" 2> "$sample.stderr"
    status=$?
    set -e
    if jq -e . "$sample" >/dev/null 2>&1; then
      jq -c --arg label "$label" --arg name "$name" --arg pin "$pin" \
        --arg now "$(boot_now)" --argjson command_exit "$status" '
          . + {label:$label,name:$name,pin:$pin,
               boottime_seconds:($now|tonumber),command_exit:$command_exit}' \
        "$sample" >> "$output"
    else
      jq -cn --arg label "$label" --arg name "$name" --arg pin "$pin" \
        --arg now "$(boot_now)" --argjson command_exit "$status" \
        --rawfile stderr "$sample.stderr" \
        '{label:$label,name:$name,pin:$pin,boottime_seconds:($now|tonumber),
          command_exit:$command_exit,error:$stderr}' >> "$output"
    fi
    rm -f "$sample" "$sample.stderr"
  done < <(jq -r '.links[] | [.name,.pin] | @tsv' "$evidence/state-before-loss.json")
}

capture_target_offline_snapshot() {
  local label=$1
  local directory="$evidence/target-offline"
  mkdir -p "$directory"
  capture_cgroup_diagnostic "$label" /sys/fs/cgroup/system.slice \
    "$directory/$label-system.slice.txt"
  capture_cgroup_diagnostic "$label" "$unit_cgroup" \
    "$directory/$label-unit.txt"
  capture_cgroup_diagnostic "$label" "$unit_cgroup/executions" \
    "$directory/$label-executions.txt"
  capture_link_diagnostic "$label" "$directory/$label-links.jsonl"
  ss -tanp > "$directory/$label-sockets.txt"
}

poll_target_offline_state() {
  local phase=$1 iterations=$2 delay=$3
  local output="$evidence/target-offline/$phase-observations.jsonl"
  local iteration stat_file dying
  : > "$output"
  for iteration in $(seq 0 "$iterations"); do
    stat_file=$(mktemp)
    cat /sys/fs/cgroup/system.slice/cgroup.stat > "$stat_file"
    dying=$(awk '$1 == "nr_dying_descendants" {print $2}' "$stat_file")
    while IFS=$'\t' read -r name pin; do
      set +e
      link=$(bpftool -j link show pinned "$pin" 2>/dev/null)
      status=$?
      set -e
      if jq -e . >/dev/null 2>&1 <<<"$link"; then
        jq -c --arg phase "$phase" --arg name "$name" --arg pin "$pin" \
          --arg now "$(boot_now)" --argjson iteration "$iteration" \
          --argjson command_exit "$status" --argjson dying "${dying:-0}" '
            . + {phase:$phase,name:$name,pin:$pin,
                 boottime_seconds:($now|tonumber),iteration:$iteration,
                 command_exit:$command_exit,
                 system_slice_nr_dying_descendants:$dying}' \
          <<<"$link" >> "$output"
      fi
    done < <(jq -r '.links[] | [.name,.pin] | @tsv' "$evidence/state-before-loss.json")
    rm -f "$stat_file"
    [[ $iteration -eq $iterations ]] || sleep "$delay"
  done
}

cleanup() {
  local status=$?
  set +e
  if [[ -n ${offline_handle_pid:-} ]]; then
    kill "$offline_handle_pid" >/dev/null 2>&1
    wait "$offline_handle_pid" 2>/dev/null
  fi
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
  [[ $target_offline_diagnostic == true ]] && rm -f "$offline_helper"
  rm -f "/var/tmp/$unit-page-cache"
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
  if [[ $target_offline_diagnostic == true && $target_offline_page_cache_mb != 0 ]]; then
    bash -c "echo \$\$ > '$first_cgroup/cgroup.procs'; dd if=/dev/zero of='/var/tmp/$unit-page-cache' bs=1M count='$target_offline_page_cache_mb' conv=fsync status=none"
    printf '%s\n' "$target_offline_page_cache_mb" \
      > "$evidence/target-offline-page-cache-mb.txt"
  fi
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
: > "$evidence/execution-cgroup-events-before-loss.txt"
for cgroup in "${execution_cgroups[@]}"; do
  while read -r pid; do [[ -n "$pid" ]] && old_agents+=("$pid"); done < "$cgroup/cgroup.procs"
  printf 'cgroup=%s\n' "$cgroup" >> "$evidence/execution-cgroup-events-before-loss.txt"
  cat "$cgroup/cgroup.events" >> "$evidence/execution-cgroup-events-before-loss.txt"
done
printf '%s\n' "${old_agents[@]}" > "$evidence/old-agent-pids.txt"
ss -H -n -t -a > "$evidence/sockets-before-loss.txt"
nft -j list table inet soglia_b6_observe > "$evidence/effects-at-loss.json"
cp "$runtime/cgroup-bpf/state.json" "$evidence/state-before-loss.json"
old_generation=$(jq -r .generation "$evidence/state-before-loss.json")
old_attachment_inode=$(jq -r .attachment_inode "$evidence/state-before-loss.json")
if [[ $target_offline_diagnostic == true ]]; then
  cc -O2 -Wall -Wextra -Werror \
    /soglia/spikes/cgroup-bpf/runner/helpers/b6-offline-kernel.c \
    -o "$offline_helper"
  rm -f "$evidence/target-offline-handle-release"
  strace -qq -f -e trace=name_to_handle_at,open_by_handle_at \
    -o "$evidence/target-offline-handle-syscalls.txt" \
    "$offline_helper" handle-probe "$unit_cgroup/executions" \
    "$evidence/target-offline-handle-release" \
    > "$evidence/target-offline-handle.jsonl" \
    2> "$evidence/target-offline-handle.stderr" &
  offline_handle_pid=$!
  for _ in $(seq 1 500); do
    [[ -s $evidence/target-offline-handle.jsonl ]] && break
    kill -0 "$offline_handle_pid" 2>/dev/null || break
    sleep 0.01
  done
  jq -e 'select(.stage == "before" and .open_result == 0)' \
    "$evidence/target-offline-handle.jsonl" >/dev/null
  capture_target_offline_snapshot before-loss
  mkdir -p "$evidence/target-offline/executions-before-loss"
  for cgroup in "${execution_cgroups[@]}"; do
    name=$(basename "$cgroup")
    capture_cgroup_diagnostic before-loss "$cgroup" \
      "$evidence/target-offline/executions-before-loss/$name.txt"
  done
fi

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
for cgroup in "${execution_cgroups[@]}"; do
  if [[ -e "$cgroup" ]]; then
    printf 'cgroup=%s\n' "$cgroup" >> "$evidence/execution-cgroup-events-before-new-main.txt"
    cat "$cgroup/cgroup.events" >> "$evidence/execution-cgroup-events-before-new-main.txt"
  else
    printf 'cgroup=%s state=ABSENT_AFTER_VERIFIED_KILL\n' "$cgroup" \
      >> "$evidence/execution-cgroup-events-before-new-main.txt"
  fi
done
! grep -q '^populated 1$' "$evidence/execution-cgroup-events-before-new-main.txt"
if [[ $target_offline_diagnostic == true ]]; then
  touch "$evidence/target-offline-handle-release"
  wait "$offline_handle_pid"
  offline_handle_pid=
  find /sys/fs/cgroup -xdev -inum "$old_attachment_inode" -print \
    > "$evidence/target-offline-old-id-live-paths.txt"
  capture_target_offline_snapshot after-new-main
  poll_target_offline_state before-reclaim 20 0.25

  set +e
  printf '1073741824\n' > /sys/fs/cgroup/system.slice/memory.reclaim \
    2> "$evidence/target-offline/memory-reclaim.stderr"
  printf '%s\n' "$?" > "$evidence/target-offline/memory-reclaim.exit"
  set -e
  poll_target_offline_state after-memory-reclaim 40 0.25

  sync
  set +e
  printf '3\n' > /proc/sys/vm/drop_caches \
    2> "$evidence/target-offline/drop-caches.stderr"
  printf '%s\n' "$?" > "$evidence/target-offline/drop-caches.exit"
  set -e
  poll_target_offline_state after-drop-caches 40 0.25
  capture_target_offline_snapshot after-reclaim
  journalctl -u "$unit.service" --after-cursor "$journal_cursor" -o json --no-pager \
    > "$evidence/target-offline/journal.jsonl"
  jq -r 'if (.MESSAGE|type) == "array" then (.MESSAGE|implode) else (.MESSAGE // "") end' \
    "$evidence/target-offline/journal.jsonl" \
    > "$evidence/target-offline/journal-decoded.txt"
  unknown_refusals=$(grep -Ec 'startup\.refused.*UNKNOWN' \
    "$evidence/target-offline/journal-decoded.txt" || true)
  target_released_passes=$(grep -c 'event.name=cgroup_bpf.target_released result=PASS' \
    "$evidence/target-offline/journal-decoded.txt" || true)

  : > "$evidence/target-offline/explicit-detach.jsonl"
  if [[ $target_offline_detach == true ]]; then
    while IFS=$'\t' read -r name pin; do
      strace -qq -f -e trace=bpf \
        -o "$evidence/target-offline/explicit-detach-$name-syscalls.txt" \
        "$offline_helper" link-detach "$pin" \
        | jq -c --arg name "$name" --arg pin "$pin" \
          '. + {name:$name,pin:$pin}' \
        >> "$evidence/target-offline/explicit-detach.jsonl"
    done < <(jq -r '.links[] | [.name,.pin] | @tsv' "$evidence/state-before-loss.json")
  fi

  jq -n \
    --argjson old_attachment_inode "$old_attachment_inode" \
    --slurpfile before "$evidence/target-offline/before-reclaim-observations.jsonl" \
    --slurpfile memory "$evidence/target-offline/after-memory-reclaim-observations.jsonl" \
    --slurpfile caches "$evidence/target-offline/after-drop-caches-observations.jsonl" \
    --slurpfile handle "$evidence/target-offline-handle.jsonl" \
    --slurpfile detach "$evidence/target-offline/explicit-detach.jsonl" \
    --rawfile old_paths "$evidence/target-offline-old-id-live-paths.txt" \
    --argjson memory_reclaim_exit "$(cat "$evidence/target-offline/memory-reclaim.exit")" \
    --argjson drop_caches_exit "$(cat "$evidence/target-offline/drop-caches.exit")" \
    --argjson unknown_refusals "$unknown_refusals" \
    --argjson target_released_passes "$target_released_passes" '
      {
        authoritative:false,
        purpose:"diagnose delayed TargetReleased convergence in the production sandbox-loss topology",
        old_attachment_inode:$old_attachment_inode,
        handle_observations:$handle,
        old_id_live_paths:($old_paths|split("\n")|map(select(length > 0))),
        observations:{before_reclaim:$before,after_memory_reclaim:$memory,after_drop_caches:$caches},
        reclamation:{memory_reclaim_bytes:1073741824,memory_reclaim_exit:$memory_reclaim_exit,
          drop_caches_exit:$drop_caches_exit},
        production_outcome:{unknown_refusals:$unknown_refusals,
          target_released_passes:$target_released_passes},
        explicit_detach:$detach,
        assertions:{
          old_link_id_observed_after_path_removal:any($before[]; .cgroup_id == $old_attachment_inode),
          handle_stale_after_restart:($handle[1].open_result == -1 and $handle[1].open_errno == 116),
          old_id_absent_from_live_hierarchy:(
            ($old_paths|split("\n")|map(select(length > 0))|length) == 0
          ),
          links_never_retargeted_to_another_live_id:all(($before + $memory + $caches)[];
            .cgroup_id == $old_attachment_inode or .cgroup_id == 0),
          explicit_detach_safe:(
            if ($detach|length) == 0 then true else
              ($detach|length) == 6 and all($detach[];
                .before.cgroup_id == $old_attachment_inode and
                .detach_result == 0 and .after.cgroup_id == 0 and
                .before.id == .after.id and
                .before.prog_id == .after.prog_id and
                .before.attach_type == .after.attach_type)
            end
          ),
          production_refused_instead_of_mutating:(
            $unknown_refusals > 0 and $target_released_passes == 0
          )
        }
      }
      | .verdict = (if all(.assertions[]; .) then "PASS" else "UNPROVEN" end)' \
    > "$evidence/target-offline/result.json"
  checksum_tmp=$(mktemp "$evidence/.SHA256SUMS.XXXXXX")
  (cd "$evidence" && find . -type f ! -name SHA256SUMS \
    ! -name '.SHA256SUMS.*' -print0 | sort -z | xargs -0 sha256sum) \
    > "$checksum_tmp"
  mv "$checksum_tmp" "$evidence/SHA256SUMS"
  exit 0
fi
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
