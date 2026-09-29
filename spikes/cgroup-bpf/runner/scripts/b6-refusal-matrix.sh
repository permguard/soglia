#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Exercise one-defect-at-a-time S13 startup refusals through the production process boundary.

set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo 'usage: b6-refusal-matrix.sh <soglia> <agent> <evidence> [case]' >&2
  exit 13
fi
binary=$1
agent=$2
evidence=$3
active_unit=
active_runtime=
active_pin_parent=
active_rootfs=

cases=(
  incompatible_schema incompatible_abi incompatible_object incompatible_config
  unknown_trust unknown_pin_root unknown_cgroup unknown_kernel_identity unknown_metadata
  unknown_foreign_inventory unknown_orphan_policy unknown_binding_key unknown_unexpected_pin
)
if [[ $# -eq 4 ]]; then
  requested_case=$4
  case " ${cases[*]} " in
    *" $requested_case "*) cases=("$requested_case") ;;
    *) echo "unknown refusal case $requested_case" >&2; exit 13 ;;
  esac
fi

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
  local state=$runtime/cgroup-bpf/state.json
  set +e
  systemctl stop "$unit.service" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  if [[ -f $state ]] && jq -e '.pin_root and .links and .maps' "$state" >/dev/null 2>&1; then
    jq -r '.executions[].tag // empty' "$state" | while read -r tag; do
      ip netns delete "soglia-${tag:0:10}" >/dev/null 2>&1
      ip link delete "sgh-${tag:0:10}" >/dev/null 2>&1
    done
    jq -r '.links[].pin,.maps[].pin' "$state" | while read -r pin; do
      case "$pin" in "$pin_parent"/*) rm -f "$pin" ;; esac
    done
    owned_root=$(jq -r .pin_root "$state")
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
  find "$runtime" -depth -mindepth 1 -delete 2>/dev/null
  rmdir "$runtime" "$pin_parent" 2>/dev/null
  find "$rootfs" -depth -mindepth 1 -delete 2>/dev/null
  rmdir "$rootfs" 2>/dev/null
  set -e
}

cleanup() {
  local status=$?
  if [[ -n "$active_unit" ]]; then
    remove_case_resources "$active_unit" "$active_runtime" "$active_pin_parent" "$active_rootfs"
  fi
  exit "$status"
}
trap cleanup EXIT

inventory() {
  local state=$1 output=$2
  bpftool -j prog show > "$output.programs.json"
  bpftool -j link show > "$output.links.json"
  bpftool -j map show > "$output.maps.json"
  jq -n --slurpfile state "$state" \
    --slurpfile programs "$output.programs.json" --slurpfile links "$output.links.json" \
    --slurpfile maps "$output.maps.json" '
      ($state[0]) as $s |
      {programs:[$s.programs[].id | select(. != 0)] | sort,
       links:[$s.links[].id | select(. != 0)] | sort,
       maps:[$s.maps[].id | select(. != 0)] | sort,
       owned_program_objects:[$programs[0][] as $object |
         select([$s.programs[].id] | index($object.id) != null) | $object] | sort_by(.id),
       owned_link_objects:[$links[0][] as $object |
         select([$s.links[].id] | index($object.id) != null) | $object] | sort_by(.id),
       owned_map_objects:[$maps[0][] as $object |
         select([$s.maps[].id] | index($object.id) != null) | $object] | sort_by(.id),
       observed_programs:[$programs[0][].id] | sort,
       observed_links:[$links[0][].id] | sort,
       observed_maps:[$maps[0][].id] | sort}' > "$output.owned.json"
}

recorded_ids_present() {
  local inventory=$1
  jq -e '
    . as $inventory |
    all($inventory.programs[]; . as $id | $inventory.observed_programs | index($id) != null) and
    all($inventory.links[]; . as $id | $inventory.observed_links | index($id) != null) and
    all($inventory.maps[]; . as $id | $inventory.observed_maps | index($id) != null)' "$inventory"
}

write_json_mutation() {
  local state=$1 filter=$2
  jq "$filter" "$state" > "$state.mutated"
  chmod 0600 "$state.mutated"
  mv "$state.mutated" "$state"
}

map_tokens() {
  jq -r "$1[] | if type == \"string\" then ltrimstr(\"0x\") else
    error(\"unexpected numeric bpftool byte\") end" "$2"
}

snapshot_maps() {
  local state=$1 output=$2 pin show
  : > "$output.jsonl"
  while read -r pin; do
    show=$(bpftool -j map show pinned "$pin")
    if [[ $(jq -r 'if type == "array" then .[0].type else .type end' <<<"$show") == ringbuf ]]; then
      jq -nc --arg pin "$pin" --argjson show "$show" \
        '{pin:$pin,show:$show,contents:"NOT_APPLICABLE:ringbuf"}' >> "$output.jsonl"
    else
      jq -nc --arg pin "$pin" --argjson show "$show" \
        --argjson contents "$(bpftool -j map dump pinned "$pin")" \
        '{pin:$pin,show:$show,contents:$contents}' >> "$output.jsonl"
    fi
  done < <(jq -r '.maps[].pin' "$state")
  jq -s 'sort_by(.pin)' "$output.jsonl" > "$output.json"
  rm "$output.jsonl"
}

launch_unit() {
  local unit=$1 binary=$2 config=$3 output=$4
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  systemd-run --unit="$unit" --property=Type=simple --property=Delegate=yes \
    --property=KillMode=mixed --property=Restart=no --property=TimeoutStopSec=2s \
    -- "$binary" run -f "$config" >> "$output"
}

run_case() {
  local case_name=$1 ordinal=$2
  local unit="soglia-b6-refusal-$ordinal"
  local case_evidence="$evidence/$case_name"
  local runtime="/run/$unit"
  local pin_parent="/sys/fs/bpf/$unit"
  local rootfs="/var/tmp/$unit-rootfs"
  local unit_cgroup="/sys/fs/cgroup/system.slice/$unit.service"
  local port=$((18400 + ordinal))
  local config="$case_evidence/config.yaml"
  local state="$runtime/cgroup-bpf/state.json"
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
ingress: { listen: "127.0.0.1:$port" }
network:
  backend: cgroup-bpf
  execution_pool: 10.$((100 + ordinal)).0.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
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
  probe:
    rootfs: $rootfs
    command: ["/agent", "serve"]
    env: {}
    timeout_ms: 40000
    tmpfs: [{ path: /tmp, size_bytes: 1048576 }]
YAML

  journal_cursor=$(journalctl -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
  : > "$case_evidence/systemd-run.txt"
  launch_unit "$unit" "$binary" "$config" "$case_evidence/systemd-run.txt"
  systemctl show "$unit.service" -p Delegate -p KillMode -p Restart -p ControlGroup \
    > "$case_evidence/unit-properties.txt"
  grep -Fx 'Delegate=yes' "$case_evidence/unit-properties.txt"
  grep -Fx 'KillMode=mixed' "$case_evidence/unit-properties.txt"
  grep -Fx 'Restart=no' "$case_evidence/unit-properties.txt"
  wait_for initial-ready "ss -H -ltn 'sport = :$port' | grep -q ."

  client=
  if [[ "$case_name" == unknown_binding_key ]]; then
    curl --silent --show-error --max-time 45 -X POST --data-binary 'sleep 30000' \
      "http://127.0.0.1:$port/v1/execute/probe" > "$case_evidence/client.txt" 2>&1 &
    client=$!
    wait_for active-record "[[ \$(jq '.executions | length' '$state') -eq 1 ]]"
  fi

  cp "$state" "$case_evidence/original-state.json"
  old_generation=$(jq -r .generation "$state")
  main_pid=$(systemctl show "$unit.service" -p MainPID --value)
  kill -KILL "$main_pid"
  wait_for initial-process-exit "[[ \$(systemctl show '$unit.service' -p ActiveState --value) == failed ]]"
  [[ -z "$client" ]] || wait "$client" >/dev/null 2>&1 || true
  cp "$case_evidence/original-state.json" "$state"
  chmod 0600 "$state"

  mutation_kind=json
  case "$case_name" in
    incompatible_schema) write_json_mutation "$state" '.schema += 1' ; expected=20 ;;
    incompatible_abi) write_json_mutation "$state" '.abi += 1' ; expected=20 ;;
    incompatible_object) write_json_mutation "$state" '.object_sha256 = ([range(64) | "0"] | join(""))' ; expected=20 ;;
    incompatible_config) write_json_mutation "$state" '.config_sha256 = ([range(64) | "0"] | join(""))' ; expected=20 ;;
    unknown_trust) chmod 0644 "$state" ; mutation_kind=mode ; expected=21 ;;
    unknown_pin_root) write_json_mutation "$state" '.pin_root += "-other"' ; expected=21 ;;
    unknown_cgroup) write_json_mutation "$state" '.attachment_inode += 1' ; expected=21 ;;
    unknown_kernel_identity) write_json_mutation "$state" '.links[0].id += 1' ; expected=21 ;;
    unknown_foreign_inventory)
      write_json_mutation "$state" '.ancestor_bpf += [{program_id:4294967294,name:"external",program_type:"cgroup_skb",tag:"0000000000000000",attach_type:"cgroup_inet_ingress"}]'
      expected=21
      ;;
    unknown_binding_key)
      write_json_mutation "$state" \
        '.executions[(.executions|keys[0])].binding.execution_nonce[0] = ((.executions[(.executions|keys[0])].binding.execution_nonce[0] + 1) % 256)'
      expected=21
      ;;
    unknown_metadata)
      mutation_kind=metadata
      meta_pin=$(jq -r '.maps[] | select(.name == "soglia_meta") | .pin' "$state")
      bpftool -j map dump pinned "$meta_pin" > "$case_evidence/meta-original.json"
      mapfile -t meta_key < <(map_tokens '.[0].key' "$case_evidence/meta-original.json")
      mapfile -t meta_value < <(map_tokens '.[0].value' "$case_evidence/meta-original.json")
      meta_mutated=("${meta_value[@]}")
      [[ ${meta_mutated[0]} == 00 ]] && meta_mutated[0]=01 || meta_mutated[0]=00
      bpftool map update pinned "$meta_pin" key hex "${meta_key[@]}" value hex "${meta_mutated[@]}"
      expected=21
      ;;
    unknown_orphan_policy)
      mutation_kind=orphan_policy
      policy_pin=$(jq -r '.maps[] | select(.name == "soglia_policy") | .pin' "$state")
      orphan_key=(01 00 00 00 00 00 00 00)
      orphan_value=()
      for _ in $(seq 1 40); do orphan_value+=(00); done
      bpftool map update pinned "$policy_pin" key hex "${orphan_key[@]}" value hex "${orphan_value[@]}"
      expected=21
      ;;
    unknown_unexpected_pin)
      mutation_kind=unexpected_pin
      extra_pin=$(jq -r .pin_root "$state")/unexpected-map
      bpftool map create "$extra_pin" type hash key 4 value 4 entries 1 name b6_extra
      expected=21
      ;;
    *) echo "unknown refusal case $case_name" >&2; return 1 ;;
  esac

  cp "$state" "$case_evidence/mutated-state-before.json"
  chmod --reference="$state" "$case_evidence/mutated-state-before.json"
  stat -c '%a %u %g %i %s' "$state" > "$case_evidence/state-stat-before.txt"
  sha256sum "$state" > "$case_evidence/state-sha256-before.txt"
  inventory "$state" "$case_evidence/before-refusal"
  recorded_ids_present "$case_evidence/before-refusal.owned.json"
  snapshot_maps "$case_evidence/original-state.json" "$case_evidence/maps-before-refusal"

  refusal_cursor=$(journalctl -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
  launch_unit "$unit" "$binary" "$config" "$case_evidence/systemd-run.txt"
  wait_for typed-refusal "[[ \$(systemctl show '$unit.service' -p ActiveState --value) == failed ]]"
  systemctl show "$unit.service" -p ExecMainStatus -p Result > "$case_evidence/refusal-unit-result.txt"
  grep -Fx "ExecMainStatus=$expected" "$case_evidence/refusal-unit-result.txt"
  grep -Fx 'Result=exit-code' "$case_evidence/refusal-unit-result.txt"
  SYSTEMD_COLORS=0 journalctl -u "$unit.service" --after-cursor "$refusal_cursor" -o json --no-pager \
    > "$case_evidence/refusal-journal.jsonl"
  SYSTEMD_COLORS=0 journalctl -u "$unit.service" --after-cursor "$refusal_cursor" -o cat --no-pager --no-hostname \
    > "$case_evidence/refusal-journal.txt"
  expected_class=UNKNOWN
  [[ "$expected" -ne 20 ]] || expected_class=INCOMPATIBLE
  grep -q "refusal.class.*$expected_class" "$case_evidence/refusal-journal.txt"
  ! grep -q 'event.name.*startup.ready' "$case_evidence/refusal-journal.txt"
  sha256sum "$state" > "$case_evidence/state-sha256-after.txt"
  cmp "$case_evidence/state-sha256-before.txt" "$case_evidence/state-sha256-after.txt"
  stat -c '%a %u %g %i %s' "$state" > "$case_evidence/state-stat-after.txt"
  cmp "$case_evidence/state-stat-before.txt" "$case_evidence/state-stat-after.txt"
  inventory "$state" "$case_evidence/after-refusal"
  jq 'del(.observed_programs,.observed_links,.observed_maps)' \
    "$case_evidence/before-refusal.owned.json" > "$case_evidence/before-refusal.test-owned.json"
  jq 'del(.observed_programs,.observed_links,.observed_maps)' \
    "$case_evidence/after-refusal.owned.json" > "$case_evidence/after-refusal.test-owned.json"
  cmp "$case_evidence/before-refusal.test-owned.json" "$case_evidence/after-refusal.test-owned.json"
  recorded_ids_present "$case_evidence/after-refusal.owned.json"
  snapshot_maps "$case_evidence/original-state.json" "$case_evidence/maps-after-refusal"
  cmp "$case_evidence/maps-before-refusal.json" "$case_evidence/maps-after-refusal.json"

  case "$mutation_kind" in
    json) cp "$case_evidence/original-state.json" "$state"; chmod 0600 "$state" ;;
    mode) chmod 0600 "$state" ;;
    metadata)
      bpftool map update pinned "$meta_pin" key hex "${meta_key[@]}" value hex "${meta_value[@]}"
      ;;
    orphan_policy) bpftool map delete pinned "$policy_pin" key hex "${orphan_key[@]}" ;;
    unexpected_pin) rm -f "$extra_pin" ;;
  esac
  cmp "$case_evidence/original-state.json" "$state"

  recovery_cursor=$(journalctl -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
  launch_unit "$unit" "$binary" "$config" "$case_evidence/systemd-run.txt"
  wait_for positive-recovery "ss -H -ltn 'sport = :$port' | grep -q ."
  new_generation=$(jq -r .generation "$state")
  [[ "$new_generation" -gt "$old_generation" ]]
  for map in soglia_policy soglia_cookie_a soglia_tuples; do
    pin=$(jq -r --arg map "$map" '.maps[] | select(.name == $map) | .pin' "$state")
    bpftool -j map dump pinned "$pin" > "$case_evidence/recovered-$map.json"
    jq -e 'length == 0' "$case_evidence/recovered-$map.json"
  done
  SYSTEMD_COLORS=0 journalctl -u "$unit.service" --after-cursor "$recovery_cursor" -o cat --no-pager --no-hostname \
    > "$case_evidence/recovery-journal.txt"
  grep -q 'event.name.*startup.ready' "$case_evidence/recovery-journal.txt"
  jq -n --arg case "$case_name" --arg class "$expected_class" --argjson exit_code "$expected" \
    --argjson old_generation "$old_generation" --argjson new_generation "$new_generation" \
    '{case:$case,refusal_class:$class,exit_code:$exit_code,state_bytes_preserved:true,
      state_metadata_preserved:true,kernel_ids_preserved:true,map_contents_preserved:true,
      ready_emitted_on_refusal:false,positive_recovery:true,
      old_generation:$old_generation,new_generation:$new_generation,verdict:"PASS"}' \
    > "$case_evidence/result.json"
  printf '%s\n' PASS > "$case_evidence/verdict.txt"
  remove_case_resources "$unit" "$runtime" "$pin_parent" "$rootfs"
  active_unit=
  active_runtime=
  active_pin_parent=
  active_rootfs=
}

mkdir -p "$evidence"
ordinal=1
for case_name in "${cases[@]}"; do
  run_case "$case_name" "$ordinal"
  ordinal=$((ordinal + 1))
done
printf '%s\n' PASS > "$evidence/verdict.txt"
trap - EXIT
