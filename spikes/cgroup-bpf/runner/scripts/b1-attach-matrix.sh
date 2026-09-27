#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Diagnostic-only B1 attach-mode matrix. This exercises the exact production BPF object against a
# disposable delegated cgroup hierarchy. It does not invoke or modify the production backend.

set -euo pipefail

prod_obj="${1:?usage: b1-attach-matrix.sh <production-object> <diagnostic-loader>}"
diag_bin="${2:?usage: b1-attach-matrix.sh <production-object> <diagnostic-loader>}"
run_id="b1-attach-diag-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
runtime="/run/$run_id"
pin_root="/sys/fs/bpf/$run_id"
unit="soglia-spike-$run_id"
foreign_dir="/var/tmp/$run_id-bpf"

mkdir -p "$evidence" "$runtime" "$pin_root" "$foreign_dir"
printf '%s\n' RUNNING > "$evidence/verdict.txt"
printf '%s\n' "$run_id" > "$evidence/run-id.txt"
printf '%s\n' "$unit" > "$evidence/unit-name.txt"

unit_started=0
foreign_attached=0
foreign_pin=""
child_pid=""
ancestor=""

cleanup() {
  set +e
  if [[ -n "$child_pid" ]]; then
    kill "$child_pid" 2>/dev/null
    wait "$child_pid" 2>/dev/null
  fi
  if [[ "$foreign_attached" == 1 ]]; then
    bpftool cgroup detach "$ancestor" cgroup_inet4_connect pinned "$foreign_pin" \
      >/dev/null 2>&1
  fi
  if [[ "$unit_started" == 1 ]]; then
    systemctl stop "$unit.service" >/dev/null 2>&1
    systemctl reset-failed "$unit.service" >/dev/null 2>&1
  fi
  find "$pin_root" -type f -delete 2>/dev/null
  find "$pin_root" -depth -type d -empty -delete 2>/dev/null
  rm -rf "$runtime" "$foreign_dir"
}
trap cleanup EXIT

{
  uname -a
  bpftool version
  systemd --version | head -1
} > "$evidence/environment.txt"
{
  sha256sum "$prod_obj"
  sha256sum "$diag_bin"
  git -C /soglia status --short
  git -C /soglia rev-parse HEAD
} > "$evidence/source-fingerprint.txt"

bpftool -j prog show > "$evidence/host-pre-programs.json"
bpftool -j link show > "$evidence/host-pre-links.json"
bpftool -j map show > "$evidence/host-pre-maps.json"

systemd-run --unit="$unit" --property=Delegate=yes --property=Type=simple sleep infinity \
  > "$evidence/systemd-run.txt"
unit_started=1
for _ in $(seq 1 100); do
  cg_rel=$(systemctl show "$unit.service" --property=ControlGroup --value)
  if [[ -n "$cg_rel" && -d "/sys/fs/cgroup$cg_rel" ]]; then
    break
  fi
  sleep 0.05
done
ancestor="/sys/fs/cgroup$cg_rel"
executions="$ancestor/executions"
mkdir "$executions"
{
  systemctl show "$unit.service" --property=Delegate --property=ControlGroup --property=ActiveState
  stat -c 'ancestor=%n inode=%i mode=%a owner=%u:%g' "$ancestor"
  stat -c 'executions=%n inode=%i mode=%a owner=%u:%g' "$executions"
  cat "$ancestor/cgroup.procs"
} > "$evidence/delegation.txt"

bpftool -j prog show > "$evidence/baseline-programs.json"
bpftool -j link show > "$evidence/baseline-links.json"
bpftool -j map show > "$evidence/baseline-maps.json"

snapshot_cgroup() {
  local path="$1"
  local out="$2"
  bpftool -j cgroup show "$path" > "$out"
  if [[ -z $(tr -d '[:space:]' < "$out") ]]; then
    printf '%s\n' '[]' > "$out"
  fi
}

snapshot_cgroup "$ancestor" "$evidence/baseline-ancestor-direct.json"
snapshot_cgroup "$executions" "$evidence/baseline-executions-direct.json"
bpftool -j cgroup show "$executions" effective > "$evidence/baseline-executions-effective.json"

wait_ready() {
  local ready="$1"
  local pid="$2"
  for _ in $(seq 1 400); do
    if [[ -s "$ready" ]]; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" || true
      return 1
    fi
    sleep 0.025
  done
  return 1
}

run_case() {
  local label="$1"
  local cgroup="$2"
  local hook="$3"
  local mode="$4"
  local expected="$5"
  local case_dir="$evidence/$label"
  local ready="$runtime/$label.ready"
  local stop="$runtime/$label.stop"
  local pin="$pin_root/$label.link"
  mkdir -p "$case_dir"
  rm -f "$ready" "$stop"
  if [[ -e "$pin" ]]; then
    rm -f "$pin"
  fi
  "$diag_bin" "$prod_obj" "$cgroup" "$pin" "$hook" "$mode" "$ready" "$stop" \
    > "$case_dir/loader.stdout" 2> "$case_dir/loader.stderr" &
  child_pid=$!
  if ! wait_ready "$ready" "$child_pid"; then
    printf '%s\n' 'loader did not publish a result' > "$case_dir/harness-error.txt"
    return 90
  fi
  cp "$ready" "$case_dir/result.json"
  snapshot_cgroup "$cgroup" "$case_dir/during-direct.json"
  bpftool -j cgroup show "$cgroup" effective > "$case_dir/during-effective.json"
  bpftool -j prog show > "$case_dir/during-programs.json"
  bpftool -j link show > "$case_dir/during-links.json"
  bpftool -j map show > "$case_dir/during-maps.json"
  actual=$(jq -r .status "$case_dir/result.json")
  if [[ "$actual" != "$expected" ]]; then
    printf 'expected=%s actual=%s\n' "$expected" "$actual" > "$case_dir/assertion.txt"
    return 91
  fi
  if [[ "$actual" == ATTACHED ]]; then
    touch "$stop"
  fi
  wait "$child_pid"
  child_pid=""
  snapshot_cgroup "$cgroup" "$case_dir/after-direct.json"
  if [[ $(jq 'length' "$case_dir/after-direct.json") != 0 ]]; then
    printf '%s\n' 'test-owned direct attachment remained' > "$case_dir/assertion.txt"
    return 92
  fi
  rm -f "$ready" "$stop"
}

hooks=(
  soglia_sock_create
  soglia_connect4
  soglia_connect6
  soglia_sendmsg4
  soglia_sendmsg6
  soglia_sockops
)
for hook in "${hooks[@]}"; do
  run_case "$hook-single" "$executions" "$hook" single ATTACHED
  run_case "$hook-allow-multiple" "$executions" "$hook" allow-multiple ATTACH_ERROR
done

/soglia/spikes/cgroup-bpf/build.sh "$foreign_dir" > "$evidence/build-foreign.txt"
sha256sum "$foreign_dir/foreign.o" > "$evidence/foreign-object-sha256.txt"

foreign_multi="$pin_root/foreign-multi"
mkdir "$foreign_multi"
bpftool prog loadall "$foreign_dir/foreign.o" "$foreign_multi"
foreign_pin="$foreign_multi/foreign_allow"
bpftool cgroup attach "$ancestor" cgroup_inet4_connect pinned "$foreign_pin" multi
foreign_attached=1
snapshot_cgroup "$ancestor" "$evidence/foreign-multi-ancestor-direct.json"
bpftool -j cgroup show "$executions" effective \
  > "$evidence/foreign-multi-child-effective-before.json"
run_case foreign-multi-child-single "$executions" soglia_connect4 single ATTACHED
bpftool cgroup detach "$ancestor" cgroup_inet4_connect pinned "$foreign_pin"
foreign_attached=0
rm -f "$foreign_multi/foreign_allow" "$foreign_multi/foreign_rewrite"
rmdir "$foreign_multi"
snapshot_cgroup "$ancestor" "$evidence/foreign-multi-ancestor-after.json"

foreign_exclusive="$pin_root/foreign-exclusive"
mkdir "$foreign_exclusive"
bpftool prog loadall "$foreign_dir/foreign.o" "$foreign_exclusive"
foreign_pin="$foreign_exclusive/foreign_allow"
bpftool cgroup attach "$ancestor" cgroup_inet4_connect pinned "$foreign_pin"
foreign_attached=1
snapshot_cgroup "$ancestor" "$evidence/foreign-exclusive-ancestor-direct.json"
bpftool -j cgroup show "$executions" effective \
  > "$evidence/foreign-exclusive-child-effective-before.json"
run_case foreign-exclusive-child-single "$executions" soglia_connect4 single ATTACH_ERROR
bpftool cgroup detach "$ancestor" cgroup_inet4_connect pinned "$foreign_pin"
foreign_attached=0
rm -f "$foreign_exclusive/foreign_allow" "$foreign_exclusive/foreign_rewrite"
rmdir "$foreign_exclusive"
snapshot_cgroup "$ancestor" "$evidence/foreign-exclusive-ancestor-after.json"

python3 - "$evidence" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
hooks = {
    "soglia_sock_create": "cgroup_inet_sock_create",
    "soglia_connect4": "cgroup_inet4_connect",
    "soglia_connect6": "cgroup_inet6_connect",
    "soglia_sendmsg4": "cgroup_udp4_sendmsg",
    "soglia_sendmsg6": "cgroup_udp6_sendmsg",
    "soglia_sockops": "cgroup_sock_ops",
}
checks = []

def add(name, passed, detail):
    checks.append({"name": name, "passed": bool(passed), "detail": detail})

for hook, attach_type in hooks.items():
    single_dir = root / f"{hook}-single"
    single = json.loads((single_dir / "result.json").read_text())
    direct = json.loads((single_dir / "during-direct.json").read_text())
    matches = [
        item for item in direct
        if item.get("name") == hook and item.get("attach_type") == attach_type
    ]
    add(f"{hook}: Single attached", single["status"] == "ATTACHED", single)
    add(
        f"{hook}: kernel inventory is multi",
        len(matches) == 1 and matches[0].get("attach_flags") == "multi",
        matches,
    )

    multi_dir = root / f"{hook}-allow-multiple"
    multi = json.loads((multi_dir / "result.json").read_text())
    error = multi.get("error") or ""
    add(
        f"{hook}: AllowMultiple rejected EINVAL",
        multi["status"] == "ATTACH_ERROR"
        and ("22" in error or "Invalid argument" in error),
        multi,
    )

compatible_effective = json.loads(
    (root / "foreign-multi-child-single" / "during-effective.json").read_text()
)
compatible_names = {item.get("name") for item in compatible_effective}
add(
    "ancestor legacy MULTI coexists with child production Single",
    {"foreign_allow", "soglia_connect4"}.issubset(compatible_names),
    sorted(name for name in compatible_names if name),
)

exclusive = json.loads(
    (root / "foreign-exclusive-child-single" / "result.json").read_text()
)
exclusive_error = exclusive.get("error") or ""
exclusive_effective = json.loads(
    (root / "foreign-exclusive-child-single" / "during-effective.json").read_text()
)
exclusive_names = {item.get("name") for item in exclusive_effective}
add(
    "ancestor legacy EXCLUSIVE rejects child production Single with EPERM",
    exclusive["status"] == "ATTACH_ERROR"
    and (
        "code: 1" in exclusive_error
        or "Permission denied" in exclusive_error
        or "Operation not permitted" in exclusive_error
    ),
    exclusive,
)
add(
    "exclusive rejection leaves only foreign effective",
    "foreign_allow" in exclusive_names and "soglia_connect4" not in exclusive_names,
    sorted(name for name in exclusive_names if name),
)

summary = {
    "classification": "SINGLE_VALIDATED" if all(item["passed"] for item in checks)
    else "DESIGN_BLOCKED",
    "checks": checks,
}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
if not all(item["passed"] for item in checks):
    raise SystemExit(93)
PY

bpftool -j prog show > "$evidence/final-programs.json"
bpftool -j link show > "$evidence/final-links.json"
bpftool -j map show > "$evidence/final-maps.json"
snapshot_cgroup "$ancestor" "$evidence/final-ancestor-direct.json"
snapshot_cgroup "$executions" "$evidence/final-executions-direct.json"
bpftool -j cgroup show "$executions" effective > "$evidence/final-executions-effective.json"

python3 - "$evidence" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

def load(name):
    return json.loads((root / name).read_text())

def semantic_programs(items):
    return sorted((item.get("name"), item.get("type"), item.get("tag")) for item in items)

programs_before = load("baseline-programs.json")
programs_after = load("final-programs.json")
links_before = load("baseline-links.json")
links_after = load("final-links.json")
maps_before = load("baseline-maps.json")
maps_after = load("final-maps.json")
cleanup = {
    "test_owned_program_absent": not any(
        (item.get("name") or "").startswith(("soglia_", "foreign_"))
        for item in programs_after
    ),
    "test_owned_link_absent": not any(
        (item.get("prog_name") or "").startswith(("soglia_", "foreign_"))
        for item in links_after
    ),
    "test_owned_map_absent": not any(
        (item.get("name") or "").startswith(("soglia_", "foreign_"))
        for item in maps_after
    ),
    "program_semantic_inventory_restored": (
        semantic_programs(programs_before) == semantic_programs(programs_after)
    ),
    "links_strictly_restored": links_before == links_after,
    "maps_strictly_restored": maps_before == maps_after,
    "ancestor_direct_empty": load("final-ancestor-direct.json") == [],
    "executions_direct_empty": load("final-executions-direct.json") == [],
}
cleanup["passed"] = all(cleanup.values())
(root / "cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n")
if not cleanup["passed"]:
    raise SystemExit(94)
PY

systemctl stop "$unit.service"
systemctl reset-failed "$unit.service" || true
unit_started=0
for _ in $(seq 1 100); do
  if [[ ! -d "$ancestor" ]]; then
    break
  fi
  sleep 0.05
done
[[ ! -d "$ancestor" ]]
[[ -z $(find "$pin_root" -mindepth 1 -print -quit) ]]
rmdir "$pin_root"
rm -rf "$runtime" "$foreign_dir"
{
  printf 'unit_absent='
  if systemctl status "$unit.service" >/dev/null 2>&1; then printf 'false\n'; else printf 'true\n'; fi
  printf 'cgroup_absent='
  if [[ -e "$ancestor" ]]; then printf 'false\n'; else printf 'true\n'; fi
  printf 'runtime_absent='
  if [[ -e "$runtime" ]]; then printf 'false\n'; else printf 'true\n'; fi
  printf 'pin_root_absent='
  if [[ -e "$pin_root" ]]; then printf 'false\n'; else printf 'true\n'; fi
} > "$evidence/post-cleanup.txt"
printf '%s\n' SINGLE_VALIDATED > "$evidence/verdict.txt"
trap - EXIT

printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
cat "$evidence/verdict.txt"
jq -r '.checks[] | "\(.passed) \(.name) :: \(.detail|tostring)"' "$evidence/summary.json"
cat "$evidence/cleanup.json"
cat "$evidence/post-cleanup.txt"
