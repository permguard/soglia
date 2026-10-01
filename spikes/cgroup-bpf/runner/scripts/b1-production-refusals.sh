#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Diagnostic B1 refusals that do not alter the production binary or BPF object.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
# shellcheck source=spikes/cgroup-bpf/runner/scripts/systemd-cgroup-common.sh
source "$scripts/systemd-cgroup-common.sh"

binary="${1:?usage: b1-production-refusals.sh <soglia>}"
run_id="b1-diagnostic-refusals-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
foreign_build="/var/tmp/$run_id-bpf"
foreign_pin="/sys/fs/bpf/$run_id-foreign"
direct_attached=0

mkdir -p "$evidence" "$foreign_build"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

cleanup_runtime() {
  local runtime="$1"
  rm -f "$runtime/lock"
  find "$runtime" -depth -type d -empty -delete 2>/dev/null || true
}

cleanup() {
  set +e
  for unit in \
    soglia-b1-no-delegation \
    soglia-b1-no-bpftool \
    soglia-b1-direct-app \
    soglia-b1-direct-root \
    soglia-b1-unknown-app \
    soglia-b1-unknown-root; do
    stop_and_prune_unit_cgroup "$unit" "$evidence/abort-unit-stops/$unit" >/dev/null 2>&1
    systemctl reset-failed "$unit.service" >/dev/null 2>&1
  done
  if [[ "$direct_attached" == 1 ]]; then
    bpftool cgroup detach \
      /sys/fs/cgroup/system.slice/soglia-b1-direct-root.service/executions \
      cgroup_inet4_connect pinned "$foreign_pin/foreign_allow" >/dev/null 2>&1
  fi
  for root in "$foreign_pin" /sys/fs/bpf/soglia-b1-unknown; do
    if [[ -d "$root" ]]; then
      find "$root" -type f -delete 2>/dev/null
      rmdir "$root" 2>/dev/null
    fi
  done
  for runtime in \
    /run/soglia-b1-no-delegation \
    /run/soglia-b1-no-bpftool \
    /run/soglia-b1-direct \
    /run/soglia-b1-unknown; do
    cleanup_runtime "$runtime"
  done
  rm -rf "$foreign_build"
}

record_failure() {
  printf 'DIAGNOSTIC_FAIL line=%s status=%s\n' "$1" "$2" > "$evidence/verdict.txt"
}
trap 'record_failure "$LINENO" "$?"' ERR
trap cleanup EXIT

write_config() {
  local path="$1" runtime="$2" ingress="$3" proxy_ip="$4" proxy_port="$5"
  local root="$6" pin_root="$7" bpftool_path="$8"
  cat > "$path" <<YAML
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
  bpftool: $bpftool_path
ingress:
  listen: 127.0.0.1:$ingress
network:
  backend: cgroup-bpf
  execution_pool: 10.205.0.0/24
  proxy_address: $proxy_ip
  proxy_port: $proxy_port
cgroup:
  root: $root
cgroup_bpf:
  max_tracked_sockets: 4096
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: $pin_root
agents:
  probe:
    rootfs: /var/empty
    command: ["/bin/false"]
YAML
}

wait_stopped() {
  local unit="$1"
  for _ in $(seq 1 800); do
    if ! systemctl is-active --quiet "$unit.service"; then return 0; fi
    sleep 0.025
  done
  return 1
}

capture_failure() {
  local unit="$1" started="$2" output="$3"
  wait_stopped "$unit"
  journalctl -u "$unit.service" --since "$started" --no-pager > "$output/journal.txt"
  systemctl status "$unit.service" --no-pager > "$output/status.txt" || true
}

assert_no_owned_effect() {
  local runtime="$1" pin_root="$2" port="$3"
  [[ ! -e "$runtime/cgroup-bpf/state.json" ]]
  if ss -H -ltn "( sport = :$port )" | grep -q .; then return 1; fi
  if nft list table inet soglia_host >/dev/null 2>&1; then return 1; fi
  [[ ! -e /sys/class/net/soglia0 ]]
  if [[ -d "$pin_root" ]] && find "$pin_root" -mindepth 1 -print -quit | grep -q .; then
    return 1
  fi
}

sha256sum "$binary" > "$evidence/binary-sha256.txt"
bpftool -j prog show > "$evidence/baseline-programs.json"
bpftool -j link show > "$evidence/baseline-links.json"
bpftool -j map show > "$evidence/baseline-maps.json"

# An explicitly configured root that does not exist is not a delegated cgroup environment.
case_dir="$evidence/missing-delegation"
mkdir "$case_dir"
write_config "$case_dir/config.yaml" /run/soglia-b1-no-delegation 18095 10.200.255.5 15005 \
  /sys/fs/cgroup/system.slice/soglia-b1-absent-root.service \
  /sys/fs/bpf/soglia-b1-no-delegation /usr/sbin/bpftool
started=$(date -u +%FT%TZ)
systemd-run --unit=soglia-b1-no-delegation --property=Type=simple \
  "$binary" run -f "$case_dir/config.yaml" > "$case_dir/systemd-run.txt"
capture_failure soglia-b1-no-delegation "$started" "$case_dir"
grep -F 'is not a usable cgroup v2 directory' "$case_dir/journal.txt" \
  > "$case_dir/typed-refusal.txt"
assert_no_owned_effect /run/soglia-b1-no-delegation \
  /sys/fs/bpf/soglia-b1-no-delegation 18095
stop_and_prune_unit_cgroup soglia-b1-no-delegation "$case_dir/unit-stop"
systemctl reset-failed soglia-b1-no-delegation.service >/dev/null 2>&1 || true
cleanup_runtime /run/soglia-b1-no-delegation
printf '%s\n' PASS > "$case_dir/verdict.txt"

# A required production dependency must fail in probe_capabilities, before initialization.
case_dir="$evidence/missing-bpftool"
mkdir "$case_dir"
write_config "$case_dir/config.yaml" /run/soglia-b1-no-bpftool 18096 10.200.255.6 15006 \
  /sys/fs/cgroup/system.slice/soglia-b1-no-bpftool.service \
  /sys/fs/bpf/soglia-b1-no-bpftool /usr/sbin/soglia-missing-bpftool
started=$(date -u +%FT%TZ)
systemd-run --unit=soglia-b1-no-bpftool --property=Delegate=yes --property=Type=simple \
  "$binary" run -f "$case_dir/config.yaml" > "$case_dir/systemd-run.txt"
capture_failure soglia-b1-no-bpftool "$started" "$case_dir"
grep -F 'bpftool is unavailable' "$case_dir/journal.txt" > "$case_dir/typed-refusal.txt"
assert_no_owned_effect /run/soglia-b1-no-bpftool /sys/fs/bpf/soglia-b1-no-bpftool 18096
stop_and_prune_unit_cgroup soglia-b1-no-bpftool "$case_dir/unit-stop"
systemctl reset-failed soglia-b1-no-bpftool.service >/dev/null 2>&1 || true
cleanup_runtime /run/soglia-b1-no-bpftool
printf '%s\n' PASS > "$case_dir/verdict.txt"

/soglia/spikes/cgroup-bpf/build.sh "$foreign_build" > "$evidence/build-foreign.txt"
mkdir "$foreign_pin"
bpftool prog loadall "$foreign_build/foreign.o" "$foreign_pin"

# An unrecorded direct attachment is never adopted or replaced.
case_dir="$evidence/unexpected-direct"
mkdir "$case_dir"
write_config "$case_dir/config.yaml" /run/soglia-b1-direct 18097 10.200.255.7 15007 \
  /sys/fs/cgroup/system.slice/soglia-b1-direct-root.service \
  /sys/fs/bpf/soglia-b1-direct /usr/sbin/bpftool
systemd-run --unit=soglia-b1-direct-root --property=Delegate=yes --property=Type=simple \
  sleep infinity > "$case_dir/root-systemd-run.txt"
direct_root=/sys/fs/cgroup/system.slice/soglia-b1-direct-root.service
for _ in $(seq 1 200); do [[ -d "$direct_root" ]] && break; sleep 0.025; done
mkdir "$direct_root/executions"
bpftool cgroup attach "$direct_root/executions" cgroup_inet4_connect \
  pinned "$foreign_pin/foreign_allow" multi
direct_attached=1
bpftool -j cgroup show "$direct_root/executions" > "$case_dir/direct-before.json"
started=$(date -u +%FT%TZ)
systemd-run --unit=soglia-b1-direct-app --property=Type=simple \
  "$binary" run -f "$case_dir/config.yaml" > "$case_dir/app-systemd-run.txt"
capture_failure soglia-b1-direct-app "$started" "$case_dir"
grep -F 'unrecorded direct BPF attachment(s)' "$case_dir/journal.txt" \
  > "$case_dir/typed-refusal.txt"
assert_no_owned_effect /run/soglia-b1-direct /sys/fs/bpf/soglia-b1-direct 18097
bpftool -j cgroup show "$direct_root/executions" > "$case_dir/direct-after.json"
cmp "$case_dir/direct-before.json" "$case_dir/direct-after.json"
bpftool cgroup detach "$direct_root/executions" cgroup_inet4_connect \
  pinned "$foreign_pin/foreign_allow"
direct_attached=0
stop_and_prune_unit_cgroup soglia-b1-direct-app "$case_dir/app-unit-stop"
stop_and_prune_unit_cgroup soglia-b1-direct-root "$case_dir/root-unit-stop"
systemctl reset-failed soglia-b1-direct-app.service soglia-b1-direct-root.service \
  >/dev/null 2>&1 || true
cleanup_runtime /run/soglia-b1-direct
printf '%s\n' PASS > "$case_dir/verdict.txt"

# Pins without an exact trusted manifest are preserved and startup refuses.
case_dir="$evidence/unknown-state"
mkdir "$case_dir"
write_config "$case_dir/config.yaml" /run/soglia-b1-unknown 18098 10.200.255.8 15008 \
  /sys/fs/cgroup/system.slice/soglia-b1-unknown-root.service \
  /sys/fs/bpf/soglia-b1-unknown /usr/sbin/bpftool
systemd-run --unit=soglia-b1-unknown-root --property=Delegate=yes --property=Type=simple \
  sleep infinity > "$case_dir/root-systemd-run.txt"
unknown_root=/sys/fs/cgroup/system.slice/soglia-b1-unknown-root.service
for _ in $(seq 1 200); do [[ -d "$unknown_root" ]] && break; sleep 0.025; done
mkdir "$unknown_root/executions"
mkdir /sys/fs/bpf/soglia-b1-unknown
bpftool prog loadall "$foreign_build/foreign.o" /sys/fs/bpf/soglia-b1-unknown
find /sys/fs/bpf/soglia-b1-unknown -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
  > "$case_dir/pins-before.txt"
started=$(date -u +%FT%TZ)
systemd-run --unit=soglia-b1-unknown-app --property=Type=simple \
  "$binary" run -f "$case_dir/config.yaml" > "$case_dir/app-systemd-run.txt"
capture_failure soglia-b1-unknown-app "$started" "$case_dir"
grep -F 'UNKNOWN cgroup-BPF state:' "$case_dir/journal.txt" > "$case_dir/typed-refusal.txt"
[[ ! -e /run/soglia-b1-unknown/cgroup-bpf/state.json ]]
find /sys/fs/bpf/soglia-b1-unknown -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
  > "$case_dir/pins-after.txt"
cmp "$case_dir/pins-before.txt" "$case_dir/pins-after.txt"
if ss -H -ltn '( sport = :18098 )' | grep -q .; then exit 40; fi
if nft list table inet soglia_host >/dev/null 2>&1; then exit 41; fi
[[ ! -e /sys/class/net/soglia0 ]]
find /sys/fs/bpf/soglia-b1-unknown -type f -delete
rmdir /sys/fs/bpf/soglia-b1-unknown
stop_and_prune_unit_cgroup soglia-b1-unknown-app "$case_dir/app-unit-stop"
stop_and_prune_unit_cgroup soglia-b1-unknown-root "$case_dir/root-unit-stop"
systemctl reset-failed soglia-b1-unknown-app.service soglia-b1-unknown-root.service \
  >/dev/null 2>&1 || true
cleanup_runtime /run/soglia-b1-unknown
printf '%s\n' PASS > "$case_dir/verdict.txt"

rm "$foreign_pin/foreign_allow" "$foreign_pin/foreign_rewrite"
rmdir "$foreign_pin"
rm -rf "$foreign_build"

bpftool -j prog show > "$evidence/final-programs.json"
bpftool -j link show > "$evidence/final-links.json"
bpftool -j map show > "$evidence/final-maps.json"
if jq -e 'any(.[]; ((.name // "") | startswith("soglia_") or startswith("foreign_")))' \
  "$evidence/final-programs.json" >/dev/null; then exit 42; fi
for path in \
  /run/soglia-b1-no-delegation \
  /run/soglia-b1-no-bpftool \
  /run/soglia-b1-direct \
  /run/soglia-b1-unknown \
  /sys/fs/bpf/soglia-b1-no-delegation \
  /sys/fs/bpf/soglia-b1-no-bpftool \
  /sys/fs/bpf/soglia-b1-direct \
  /sys/fs/bpf/soglia-b1-unknown; do
  [[ ! -e "$path" ]]
done
printf '%s\n' PASS > "$evidence/cleanup-verdict.txt"
printf '%s\n' PASS > "$evidence/verdict.txt"
trap - ERR EXIT

printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
