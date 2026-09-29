#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Qualification-only negative TargetReleased cases. Every mutation is explicit,
# one-at-a-time, and restored/removed by exact recorded identity.

set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo 'usage: b6-target-released-negative.sh <soglia> <agent> <link-injector> <b6-driver> <case> <evidence>' >&2
  exit 13
fi
binary=$1
agent=$2
injector=$3
driver=$4
case_name=$5
evidence=$6
case "$case_name" in
  link_still_attached|mixed_links|nonempty_target|target_outside_unit) ;;
  *) echo "unknown TargetReleased negative case: $case_name" >&2; exit 13 ;;
esac

suffix=${case_name//_/-}
owner="soglia-b6-target-$suffix"
consumer="$owner-consumer"
runtime="/run/$owner"
pin_parent="/sys/fs/bpf/$owner"
rootfs="/var/tmp/$owner-rootfs"
owner_cgroup="/sys/fs/cgroup/system.slice/$owner.service"
target="$owner_cgroup/executions"
live_target="/sys/fs/cgroup/$owner-injected-live"
config="$evidence/config.yaml"
state="$runtime/cgroup-bpf/state.json"
port=$((18600 + RANDOM % 300))

wait_for() {
  local description=$1 predicate=$2
  for _ in $(seq 1 3000); do
    eval "$predicate" && return 0
    sleep 0.01
  done
  echo "timed out waiting for $description" >&2
  return 1
}

link_cgroup_id() {
  local pin=$1
  link_info "$pin" | jq -r 'if type == "array" then .[0].cgroup_id else .cgroup_id end'
}

link_info() {
  local pin=$1 output status
  set +e
  output=$(bpftool -j link show pinned "$pin")
  status=$?
  set -e
  # bpftool v7.4.0 returns 255 after printing valid cgroup-link JSON.
  [[ $status -eq 0 || $status -eq 255 ]]
  jq -e . >/dev/null <<<"$output"
  printf '%s\n' "$output"
}

all_links_detached() {
  local pin
  while read -r pin; do
    [[ $(link_cgroup_id "$pin") -eq 0 ]] || return 1
  done < <(jq -r '.links[].pin' "$state")
}

launch() {
  local unit=$1 command_file=$2
  shift 2
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  systemd-run --unit="$unit" --property=Type=simple --property=Delegate=yes \
    --property=KillMode=mixed --property=Restart=no --property=TimeoutStopSec=2s \
    -- "$@" >> "$command_file"
}

launch_restarting() {
  local unit=$1 command_file=$2
  shift 2
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  systemd-run --unit="$unit" --property=Type=simple --property=Delegate=yes \
    --property=KillMode=mixed --property=Restart=on-failure --property=RestartSec=100ms \
    --property=TimeoutStopSec=2s -- "$@" >> "$command_file"
}

unknown_refusal_count() {
  SYSTEMD_COLORS=0 journalctl -u "$1.service" --after-cursor "$2" -o cat --no-pager \
    | grep -c 'refusal.class.*UNKNOWN' || true
}

remove_owned() {
  set +e
  systemctl stop "$consumer.service" >/dev/null 2>&1
  systemctl reset-failed "$consumer.service" >/dev/null 2>&1
  systemctl stop "$owner.service" >/dev/null 2>&1
  systemctl reset-failed "$owner.service" >/dev/null 2>&1
  if [[ -f $state ]]; then
    jq -r '.links[].pin,.maps[].pin' "$state" | while read -r pin; do
      case "$pin" in "$pin_parent"/*) rm -f "$pin" ;; esac
    done
    owned_root=$(jq -r .pin_root "$state" 2>/dev/null)
    case "$owned_root" in "$pin_parent"/*)
      find "$owned_root" -depth -mindepth 1 -delete 2>/dev/null
      rmdir "$owned_root" 2>/dev/null
      ;;
    esac
  fi
  if [[ -f $runtime/net/host.json ]] \
    && [[ $(jq -r .dummy "$runtime/net/host.json" 2>/dev/null) == soglia0 ]]; then
    nft delete table inet soglia_host >/dev/null 2>&1
    ip link delete soglia0 >/dev/null 2>&1
  fi
  rmdir "$target/injected" "$target" "$owner_cgroup" "$live_target" 2>/dev/null
  find "$runtime" -depth -mindepth 1 -delete 2>/dev/null
  rmdir "$runtime" "$pin_parent" 2>/dev/null
  find "$pin_parent" -depth -mindepth 1 -delete 2>/dev/null
  rmdir "$pin_parent" 2>/dev/null
  find "$rootfs" -depth -mindepth 1 -delete 2>/dev/null
  rmdir "$rootfs" 2>/dev/null
  set -e
}

cleanup() {
  status=$?
  remove_owned
  exit "$status"
}
trap cleanup EXIT

remove_owned
mkdir -p "$evidence" "$rootfs"/{proc,dev,sys,tmp}
install -m 0755 "$agent" "$rootfs/agent"
: > "$evidence/systemd-run.txt"

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
ingress: { listen: "127.0.0.1:$port" }
network:
  backend: cgroup-bpf
  execution_pool: 10.218.0.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
egress:
  connect_timeout_ms: 1000
  idle_timeout_ms: 30000
  allow: [{ host: allowed.test, ports: [443] }]
cgroup: { root: "$owner_cgroup" }
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

launch "$owner" "$evidence/systemd-run.txt" "$binary" run -f "$config"
wait_for initial-ready "ss -H -ltn 'sport = :$port' | grep -q ."
cp "$state" "$evidence/state-production-ready.json"
old_generation=$(jq -r .generation "$state")
old_main=$(systemctl show "$owner.service" -p MainPID --value)
kill -KILL "$old_main"
wait_for initial-failure "[[ \$(systemctl show '$owner.service' -p ActiveState --value) == failed ]]"
systemctl reset-failed "$owner.service"
wait_for released-target "[[ ! -e '$target' ]] && all_links_detached"

mutation=none
case "$case_name" in
  link_still_attached|mixed_links)
    mkdir "$live_target"
    live_id=$(stat -Lc %i "$live_target")
    qualification_programs="$pin_parent/qualification-programs"
    mkdir "$qualification_programs"
    while IFS=$'\t' read -r symbol id; do
      bpftool prog pin id "$id" "$qualification_programs/$symbol"
    done < <(jq -r '.programs[] | [.symbol, (.id|tostring)] | @tsv' "$state")
    replace_count=6
    [[ "$case_name" == mixed_links ]] && replace_count=1
    for index in $(seq 0 $((replace_count - 1))); do
      program_id=$(jq -r ".links[$index].program_id" "$state")
      pin=$(jq -r ".links[$index].pin" "$state")
      name=$(jq -r ".links[$index].name" "$state")
      case "$name" in
        sock_create) attach_type=2 ;; sock_ops) attach_type=3 ;;
        connect4) attach_type=10 ;; connect6) attach_type=11 ;;
        sendmsg4) attach_type=14 ;; sendmsg6) attach_type=15 ;;
        *) echo "unknown link $name" >&2; exit 1 ;;
      esac
      rm "$pin"
      "$injector" "$program_id" "$attach_type" "$live_target" "$pin"
      new_id=$(link_info "$pin" \
        | jq -r 'if type == "array" then .[0].id else .id end')
      jq --argjson index "$index" --argjson id "$new_id" --argjson target "$live_id" \
        '.links[$index].id = $id | .links[$index].target_inode = $target |
         .links[].target_inode = $target | .attachment_inode = $target' \
        "$state" > "$state.next"
      chmod 0600 "$state.next"
      mv "$state.next" "$state"
    done
    find "$qualification_programs" -mindepth 1 -maxdepth 1 -type f -delete
    rmdir "$qualification_programs"
    mutation=injected_links
    ;;
  nonempty_target)
    mutation=nonempty_wrapper
    ;;
  target_outside_unit)
    mutation=outside_unit
    ;;
esac

cp "$state" "$evidence/state-before-refusal.json"
stat -c '%a %u %g %i %s' "$state" > "$evidence/state-stat-before.txt"
sha256sum "$state" > "$evidence/state-sha256-before.txt"
bpftool -j prog show > "$evidence/programs-before.json"
bpftool -j link show > "$evidence/links-before.json"
bpftool -j map show > "$evidence/maps-before.json"
while read -r pin; do
  printf '{"pin":%s,"info":' "$(jq -Rn --arg value "$pin" '$value')"
  link_info "$pin"
  printf '}\n'
done < <(jq -r '.links[].pin' "$state") > "$evidence/recorded-links-before.jsonl"

cursor=$(journalctl -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
case "$case_name" in
  link_still_attached|mixed_links)
    if [[ "$case_name" == link_still_attached ]]; then
      launch_restarting "$owner" "$evidence/systemd-run.txt" "$binary" run -f "$config"
    else
      launch "$owner" "$evidence/systemd-run.txt" "$binary" run -f "$config"
    fi
    refusal_unit=$owner
    ;;
  nonempty_target)
    launch "$owner" "$evidence/systemd-run.txt" \
      "$driver" "$binary" "$config" "$evidence" /dev/null target-released-nonempty
    wait_for sandbox-ready "[[ -f '$evidence/sandbox-ready' ]]"
    mkdir "$target/injected"
    sleep 60 &
    injected_pid=$!
    echo "$injected_pid" > "$target/injected/cgroup.procs"
    printf '%s\n' COMPLETE > "$evidence/injection-complete"
    refusal_unit=$owner
    ;;
  target_outside_unit)
    anchor="$evidence/outside-anchor.sh"
    cat > "$anchor" <<EOF
#!/usr/bin/env bash
set -euo pipefail
mkdir -p '$target'
exec sleep 60
EOF
    chmod 0755 "$anchor"
    launch "$owner" "$evidence/systemd-run.txt" "$anchor"
    wait_for outside-target "[[ -d '$target' ]]"
    launch "$consumer" "$evidence/systemd-run.txt" \
      "$driver" "$binary" "$config" "$evidence" /dev/null target-released-outside
    refusal_unit=$consumer
    ;;
esac

expected_status=21
expected_result=exit-code
if [[ "$case_name" == nonempty_target || "$case_name" == target_outside_unit ]]; then
  expected_status=0
  expected_result=success
fi
if [[ "$case_name" == link_still_attached ]]; then
  wait_for repeated-typed-unknown "[[ \$(unknown_refusal_count '$refusal_unit' '$cursor') -ge 2 ]]"
  systemctl show "$refusal_unit.service" -p Restart -p NRestarts \
    > "$evidence/refusal-restart-properties.txt"
  systemctl stop "$refusal_unit.service"
else
  wait_for typed-unknown "[[ \$(systemctl show '$refusal_unit.service' -p ActiveState --value) != active ]]"
fi
systemctl show "$refusal_unit.service" -p ExecMainStatus -p Result > "$evidence/refusal-unit-result.txt"
if [[ "$case_name" != link_still_attached ]]; then
  grep -Fx "ExecMainStatus=$expected_status" "$evidence/refusal-unit-result.txt"
  grep -Fx "Result=$expected_result" "$evidence/refusal-unit-result.txt"
fi
if [[ "$case_name" == link_still_attached ]]; then
  grep -Fx 'Restart=on-failure' "$evidence/refusal-restart-properties.txt"
  [[ $(unknown_refusal_count "$refusal_unit" "$cursor") -ge 2 ]]
else
  systemctl show "$refusal_unit.service" -p Restart -p NRestarts \
    > "$evidence/refusal-restart-properties.txt"
fi
SYSTEMD_COLORS=0 journalctl -u "$refusal_unit.service" --after-cursor "$cursor" -o json --no-pager \
  > "$evidence/refusal-journal.jsonl"
SYSTEMD_COLORS=0 journalctl -u "$refusal_unit.service" --after-cursor "$cursor" -o cat --no-pager --no-hostname \
  > "$evidence/refusal-journal.txt"
if [[ "$case_name" == link_still_attached ]]; then
  jq -se '[.[] | select(.EXIT_STATUS? == "21")] | length >= 2' \
    "$evidence/refusal-journal.jsonl"
fi
if [[ "$case_name" == nonempty_target || "$case_name" == target_outside_unit ]]; then
  jq -e '.class == "UNKNOWN" and .exit_code == 21 and .verdict == "PASS"' \
    "$evidence/helper-refusal.json"
else
  grep -q 'refusal.class.*UNKNOWN' "$evidence/refusal-journal.txt"
fi
! grep -q 'event.name.*startup.ready' "$evidence/refusal-journal.txt"

sha256sum "$state" > "$evidence/state-sha256-after.txt"
stat -c '%a %u %g %i %s' "$state" > "$evidence/state-stat-after.txt"
cmp "$evidence/state-sha256-before.txt" "$evidence/state-sha256-after.txt"
cmp "$evidence/state-stat-before.txt" "$evidence/state-stat-after.txt"
bpftool -j prog show > "$evidence/programs-after.json"
bpftool -j link show > "$evidence/links-after.json"
bpftool -j map show > "$evidence/maps-after.json"
jq -e --slurpfile now "$evidence/programs-after.json" \
  'all(.programs[]; .id as $id | ([ $now[0][].id ] | index($id)) != null)' "$state"
jq -e --slurpfile now "$evidence/links-after.json" \
  'all(.links[]; .id as $id | ([ $now[0][].id ] | index($id)) != null)' "$state"
jq -e --slurpfile now "$evidence/maps-after.json" \
  'all(.maps[]; .id as $id | ([ $now[0][].id ] | index($id)) != null)' "$state"
while read -r pin; do
  printf '{"pin":%s,"info":' "$(jq -Rn --arg value "$pin" '$value')"
  link_info "$pin"
  printf '}\n'
done < <(jq -r '.links[].pin' "$state") > "$evidence/recorded-links-after.jsonl"
cmp "$evidence/recorded-links-before.jsonl" "$evidence/recorded-links-after.jsonl"

observed_ids=$(jq -s '[.[] | .info | if type == "array" then .[0].cgroup_id else .cgroup_id end]' \
  "$evidence/recorded-links-after.jsonl")
if [[ "$case_name" == link_still_attached ]]; then
  jq -e 'length == 6 and all(.[]; . != 0)' <<<"$observed_ids"
elif [[ "$case_name" == mixed_links ]]; then
  jq -e 'length == 6 and ([.[] | select(. == 0)] | length) > 0 and ([.[] | select(. != 0)] | length) > 0' \
    <<<"$observed_ids"
fi

jq -n --arg case "$case_name" --arg mutation "$mutation" \
  --argjson old_generation "$old_generation" --argjson cgroup_ids "$observed_ids" \
    '{case:$case,mutation:$mutation,expected_refusal:"UNKNOWN",exit_code:21,
    state_bytes_preserved:true,state_metadata_preserved:true,kernel_ids_preserved:true,
    ready_emitted:false,recorded_link_cgroup_ids:$cgroup_ids,
    old_generation:$old_generation,verdict:"PASS"}' > "$evidence/result.json"
printf '%s\n' PASS > "$evidence/verdict.txt"
trap - EXIT
remove_owned
