#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# B1 portability case: an unnamed external cgroup-device program on an ancestor
# is preserved, while replacement with a different tag is refused as UNKNOWN.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
helpers=/soglia/spikes/cgroup-bpf/runner/helpers
# shellcheck source=spikes/cgroup-bpf/runner/scripts/systemd-cgroup-common.sh
source "$scripts/systemd-cgroup-common.sh"

binary="${1:?usage: b1-production-unnamed-external.sh <soglia>}"
run_id="b1-unnamed-external-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
unit=soglia-b1-unnamed
runtime=/run/soglia-b1-unnamed
pin_parent=/sys/fs/bpf/soglia-b1-unnamed
external_root="/sys/fs/bpf/$run_id-external"
loader="/var/tmp/$run_id-unnamed-device"
config="$evidence/config.yaml"
state="$runtime/cgroup-bpf/state.json"
program_a="$external_root/program-a"
program_b="$external_root/program-b"
link_a="$external_root/link-a"
link_b="$external_root/link-b"
runtime_cgroup=/sys/fs/cgroup/system.slice/soglia-b1-unnamed.service
ancestor=/sys/fs/cgroup/system.slice

mkdir -p "$evidence/positive" "$evidence/negative" "$evidence/control" \
  "$evidence/final"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

remove_owned_after_failure() {
  if [[ -f $state ]] && jq -e '.pin_root and .links and .maps' "$state" >/dev/null 2>&1; then
    while IFS= read -r pin; do
      case "$pin" in "$pin_parent"/*) [[ ! -e $pin ]] || rm -f "$pin" ;; esac
    done < <(jq -r '.links[].pin, .maps[].pin' "$state")
    owned_root=$(jq -r .pin_root "$state" 2>/dev/null || true)
    case "$owned_root" in "$pin_parent"/*)
      rmdir "$owned_root/links" "$owned_root/maps" "$owned_root" 2>/dev/null || true
      ;;
    esac
  fi
  if [[ -f $runtime/net/host.json ]] \
    && [[ $(jq -r '.dummy // ""' "$runtime/net/host.json" 2>/dev/null) == soglia0 ]]; then
    nft delete table inet soglia_host >/dev/null 2>&1 || true
    ip link delete soglia0 >/dev/null 2>&1 || true
  fi
  rm -f "$state" "$runtime/cgroup-bpf/.state.json.tmp" \
    "$runtime/net/host.json" "$runtime/lock"
  rmdir "$runtime/cgroup-bpf" "$runtime/net" "$runtime" "$pin_parent" 2>/dev/null || true
}

cleanup() {
  local status=$?
  set +e
  stop_and_prune_unit_cgroup "$unit" "$evidence/final/abort-unit-stop" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  remove_owned_after_failure
  rm -f "$link_b" "$program_b" "$link_a" "$program_a"
  rmdir "$external_root" 2>/dev/null
  rm -f "$loader"
  set -e
  exit "$status"
}
trap cleanup EXIT

wait_for() {
  local description=$1 predicate=$2
  for _ in $(seq 1 1000); do
    eval "$predicate" && return 0
    sleep 0.01
  done
  printf 'timed out waiting for %s\n' "$description" >&2
  return 1
}

object_json() {
  local kind=$1 pin=$2 output=$3 status
  set +e
  bpftool -j "$kind" show pinned "$pin" > "$output"
  status=$?
  set -e
  [[ $status -eq 0 || $status -eq 255 ]]
  jq 'if type == "array" then .[0] else . end' "$output" > "$output.normalized"
  mv "$output.normalized" "$output"
}

stable_program() {
  jq -S '{id,type,tag,name:(.name // "")}' "$1"
}

stable_link() {
  jq -S '{id,prog_id,cgroup_id,attach_type}' "$1"
}

assert_unnamed_device() {
  jq -e '.type == "cgroup_device" and ((.name // "") == "") and
    (.id | type == "number") and (.tag | type == "string" and length > 0)' "$1" >/dev/null
}

launch_runtime() {
  local output=$1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  systemd-run --unit="$unit" --property=Delegate=yes \
    --property=Type=simple --property=KillMode=mixed --property=Restart=no \
    --property=TimeoutStopSec=2s -- "$binary" run -f "$config" > "$output"
}

wait_ready() {
  local phase=$1
  wait_for "$phase READY" "[[ -f '$state' ]] && jq -e '.phase == \"READY\"' '$state' >/dev/null 2>&1 && ss -H -ltn 'sport = :18097' | grep -q ."
}

stop_runtime() {
  local output=$1
  stop_and_prune_unit_cgroup "$unit" "$output"
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
}

run_uninstall() {
  local directory=$1
  set +e
  "$binary" uninstall -f "$config" > "$directory/uninstall.stdout" \
    2> "$directory/uninstall.stderr"
  local status=$?
  set -e
  printf '%s\n' "$status" > "$directory/uninstall.exit"
  [[ $status -eq 0 ]]
}

assert_soglia_absent() {
  [[ ! -e $runtime ]]
  [[ ! -e $pin_parent ]]
  [[ -z $runtime_cgroup || ! -e $runtime_cgroup ]]
  [[ ! -e /sys/class/net/soglia0 ]]
  ! nft list table inet soglia_host >/dev/null 2>&1
}

cc -O2 -Wall -Wextra -Werror "$helpers/b1-unnamed-device.c" -o "$loader"
mkdir "$external_root"
"$loader" load 1 "$ancestor" "$program_a" "$link_a"

object_json prog "$program_a" "$evidence/external-program-a.json"
object_json link "$link_a" "$evidence/external-link-a-initial.json"
assert_unnamed_device "$evidence/external-program-a.json"
program_a_id=$(jq -r .id "$evidence/external-program-a.json")
program_a_tag=$(jq -r .tag "$evidence/external-program-a.json")
bpftool -j cgroup show "$ancestor" > "$evidence/ancestor-direct-initial.json"
jq -e --argjson id "$program_a_id" \
  'any(.[]; .id == $id and .attach_type == "cgroup_device" and ((.name // "") == ""))' \
  "$evidence/ancestor-direct-initial.json" >/dev/null

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
ingress: { listen: "127.0.0.1:18097" }
network:
  backend: cgroup-bpf
  execution_pool: 10.231.0.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
cgroup: { root: "$runtime_cgroup" }
cgroup_bpf:
  max_tracked_sockets: 64
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: $pin_parent
agents:
  probe:
    rootfs: /var/empty
    command: ["/bin/false"]
YAML

# Positive: startup sees the unnamed ancestor, and uninstall preserves it exactly.
launch_runtime "$evidence/positive/systemd-run.txt"
wait_ready positive
cp "$state" "$evidence/positive/state-ready.json"
bpftool -j cgroup show "$runtime_cgroup/executions" effective \
  > "$evidence/positive/effective.json"
jq -e --argjson id "$program_a_id" \
  'any(.[]; .id == $id and .attach_type == "cgroup_device" and ((.name // "") == ""))' \
  "$evidence/positive/effective.json" >/dev/null
object_json prog "$program_a" "$evidence/positive/program-before-uninstall.json"
object_json link "$link_a" "$evidence/positive/link-before-uninstall.json"
stop_runtime "$evidence/positive/unit-stop"
run_uninstall "$evidence/positive"
object_json prog "$program_a" "$evidence/positive/program-after-uninstall.json"
object_json link "$link_a" "$evidence/positive/link-after-uninstall.json"
diff -u <(stable_program "$evidence/positive/program-before-uninstall.json") \
  <(stable_program "$evidence/positive/program-after-uninstall.json") \
  > "$evidence/positive/program-preservation.diff"
diff -u <(stable_link "$evidence/positive/link-before-uninstall.json") \
  <(stable_link "$evidence/positive/link-after-uninstall.json") \
  > "$evidence/positive/link-preservation.diff"
assert_soglia_absent

# Negative: a different unnamed program with a different tag is UNKNOWN.
launch_runtime "$evidence/negative/initial-systemd-run.txt"
wait_ready negative-initial
cp "$state" "$evidence/negative/state-before-replacement.json"
sha256sum "$state" > "$evidence/negative/state-before-replacement.sha256"
stop_runtime "$evidence/negative/initial-unit-stop"
rm "$link_a"
"$loader" load 2 "$ancestor" "$program_b" "$link_b"
object_json prog "$program_b" "$evidence/negative/replacement-program.json"
object_json link "$link_b" "$evidence/negative/replacement-link-before-refusal.json"
assert_unnamed_device "$evidence/negative/replacement-program.json"
program_b_id=$(jq -r .id "$evidence/negative/replacement-program.json")
program_b_tag=$(jq -r .tag "$evidence/negative/replacement-program.json")
[[ $program_a_tag != "$program_b_tag" ]]

refusal_started=$(date -u +%FT%T.%NZ)
launch_runtime "$evidence/negative/refusal-systemd-run.txt"
wait_for 'UNKNOWN refusal' "[[ \$(systemctl show '$unit.service' -p ActiveState --value) == failed ]]"
journalctl -u "$unit.service" --since "$refusal_started" --no-pager \
  > "$evidence/negative/refusal-journal.txt"
systemctl show "$unit.service" -p ActiveState -p Result -p ExecMainStatus \
  > "$evidence/negative/refusal-status.txt"
grep -Fx 'ExecMainStatus=21' "$evidence/negative/refusal-status.txt" >/dev/null
grep -E 'refusal.class.*UNKNOWN|class.*UNKNOWN' \
  "$evidence/negative/refusal-journal.txt" > "$evidence/negative/typed-unknown.txt"
sha256sum -c "$evidence/negative/state-before-replacement.sha256"
object_json prog "$program_b" "$evidence/negative/replacement-program-after-refusal.json"
object_json link "$link_b" "$evidence/negative/replacement-link-after-refusal.json"
diff -u <(stable_program "$evidence/negative/replacement-program.json") \
  <(stable_program "$evidence/negative/replacement-program-after-refusal.json") \
  > "$evidence/negative/replacement-program-preservation.diff"
diff -u <(stable_link "$evidence/negative/replacement-link-before-refusal.json") \
  <(stable_link "$evidence/negative/replacement-link-after-refusal.json") \
  > "$evidence/negative/replacement-link-preservation.diff"
systemctl reset-failed "$unit.service"

# Restore the original program identity and prove recovery plus uninstall still work.
rm "$link_b" "$program_b"
"$loader" attach "$ancestor" "$program_a" "$link_a"
object_json link "$link_a" "$evidence/control/link-restored-before-start.json"
launch_runtime "$evidence/control/systemd-run.txt"
wait_ready restored-control
bpftool -j cgroup show "$runtime_cgroup/executions" effective \
  > "$evidence/control/effective.json"
jq -e --argjson id "$program_a_id" 'any(.[]; .id == $id and .attach_type == "cgroup_device")' \
  "$evidence/control/effective.json" >/dev/null
stop_runtime "$evidence/control/unit-stop"
run_uninstall "$evidence/control"
object_json prog "$program_a" "$evidence/control/program-after-uninstall.json"
object_json link "$link_a" "$evidence/control/link-after-uninstall.json"
diff -u <(stable_link "$evidence/control/link-restored-before-start.json") \
  <(stable_link "$evidence/control/link-after-uninstall.json") \
  > "$evidence/control/link-preservation.diff"
assert_soglia_absent

jq -n \
  --argjson original_id "$program_a_id" \
  --arg original_tag "$program_a_tag" \
  --argjson replacement_id "$program_b_id" \
  --arg replacement_tag "$program_b_tag" \
  '{verdict:"PASS",
    positive:{startup_ready:true,effective_on_execution_subtree:true,
      bpftool_name:"ABSENT_OR_EMPTY",program_id:$original_id,tag:$original_tag,
      program_preserved_by_uninstall:true,link_preserved_by_uninstall:true},
    negative:{replacement_name:"ABSENT_OR_EMPTY",program_id:$replacement_id,
      tag:$replacement_tag,tag_differs_from_original:($replacement_tag != $original_tag),
      refusal_class:"UNKNOWN",exit_code:21,replacement_preserved_during_refusal:true},
    control:{original_identity_restored:true,startup_ready:true,
      uninstall_preserved_external_program:true},
    cleanup:{soglia_owned_resources_absent:true}}' > "$evidence/result.json"

rm "$link_a" "$program_a"
rmdir "$external_root"
rm "$loader"
[[ ! -e $external_root ]]
[[ ! -e $runtime_cgroup ]]
printf '%s\n' PASS > "$evidence/final/cleanup-verdict.txt"
printf '%s\n' PASS > "$evidence/verdict.txt"
trap - EXIT

printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
cat "$evidence/result.json"
