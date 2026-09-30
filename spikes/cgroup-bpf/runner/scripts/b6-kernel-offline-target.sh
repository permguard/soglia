#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Qualification-only kernel probe for an offline cgroup that remains internally
# referenced after removal. This script never uses the result as production
# authority.

set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: b6-kernel-offline-target.sh EVIDENCE_DIR' >&2
  exit 64
fi
if [[ $EUID -ne 0 ]]; then
  echo 'b6-kernel-offline-target: root is required' >&2
  exit 77
fi

evidence=$1
loader=/var/tmp/soglia-spike-2/bin/b1-attach-diag
source=/soglia/crates/soglia-enforcer/bpf/candidate_a.c
helper_source=/soglia/spikes/cgroup-bpf/runner/helpers/b6-offline-kernel.c
object=/var/tmp/soglia-b6-offline-target.o
helper=/var/tmp/soglia-b6-offline-kernel
cgroup_root=/sys/fs/cgroup/soglia-b6-offline-target
pin_root=/sys/fs/bpf/soglia-b6-offline-target
scratch=/var/tmp/soglia-b6-offline-target
loader_pid=
admission_pid=

mkdir -p "$evidence"

cleanup() {
  local status=$?
  set +e
  if [[ -n $loader_pid ]]; then
    touch "$scratch/stop"
    wait "$loader_pid" 2>/dev/null
  fi
  if [[ -n $admission_pid ]]; then
    kill "$admission_pid" >/dev/null 2>&1
    wait "$admission_pid" 2>/dev/null
  fi
  find "$pin_root" -mindepth 1 -maxdepth 1 -type f -delete 2>/dev/null
  rmdir "$pin_root" 2>/dev/null
  find "$cgroup_root" -depth -type d -exec rmdir {} \; 2>/dev/null
  rm -rf "$scratch"
  rm -f "$object" "$helper"
  exit "$status"
}
trap cleanup EXIT

for path in "$cgroup_root" "$pin_root" "$scratch"; do
  if [[ -e $path ]]; then
    echo "refusing pre-existing probe path $path" >&2
    exit 78
  fi
done
if [[ ! -x $loader || ! -r $source || ! -r $helper_source ]]; then
  echo 'required diagnostic artifacts are absent' >&2
  exit 69
fi

mkdir -p "$scratch" "$cgroup_root" "$pin_root"
if ! grep -qw memory "$cgroup_root/cgroup.controllers"; then
  echo 'memory controller is unavailable below the diagnostic cgroup root' >&2
  exit 77
fi
printf '+memory\n' > "$cgroup_root/cgroup.subtree_control"
clang -target bpf -O2 -g -Wall -Werror -D__TARGET_ARCH_arm64 \
  -I/usr/include/aarch64-linux-gnu -c "$source" -o "$object"
cc -O2 -Wall -Wextra -Werror "$helper_source" -o "$helper"

uname -a > "$evidence/uname.txt"
systemd --version > "$evidence/systemd-version.txt"
bpftool version > "$evidence/bpftool-version.txt"
mount | grep ' on /sys/fs/cgroup ' > "$evidence/cgroup2-mount.txt"
sha256sum "$object" "$loader" "$helper" "$helper_source" \
  > "$evidence/artifact-sha256.txt"
bpftool -j -p prog show > "$evidence/baseline-programs.json"
bpftool -j -p link show > "$evidence/baseline-links.json"
bpftool -j -p map show > "$evidence/baseline-maps.json"

attach_and_pin() {
  local cgroup=$1 pin=$2 prefix=$3
  rm -f "$scratch/ready" "$scratch/stop"
  "$loader" "$object" "$cgroup" "$scratch/unused-pin" soglia_connect4 single \
    "$scratch/ready" "$scratch/stop" > "$evidence/$prefix-loader.stdout" \
    2> "$evidence/$prefix-loader.stderr" &
  loader_pid=$!
  for _ in $(seq 1 500); do
    [[ -e $scratch/ready ]] && break
    kill -0 "$loader_pid" 2>/dev/null || break
    sleep 0.01
  done
  jq -e '.status == "ATTACHED"' "$scratch/ready" >/dev/null

  local cgroup_id link_id
  cgroup_id=$(stat -c %i "$cgroup")
  link_id=$(bpftool -j link show | jq -r --argjson id "$cgroup_id" \
    '[.[] | select(.type == "cgroup" and .cgroup_id == $id)] | if length == 1 then .[0].id else empty end')
  [[ $link_id =~ ^[0-9]+$ ]]
  bpftool link pin id "$link_id" "$pin"
  printf '%s\n' "$cgroup_id" > "$evidence/$prefix-cgroup-id.txt"
  printf '%s\n' "$link_id" > "$evidence/$prefix-link-id.txt"
  "$helper" link-info "$pin" > "$evidence/$prefix-link-before.json"

  touch "$scratch/stop"
  wait "$loader_pid"
  loader_pid=
}

capture_stat() {
  local path=$1 output=$2
  {
    printf 'path=%s\n' "$path"
    cat "$path/cgroup.stat"
  } > "$output"
}

run_case() {
  local name=$1 workload=$2
  local target="$cgroup_root/$name"
  local execution="$target/execution"
  local pin="$pin_root/$name-link"
  local marker="$scratch/$name-removed"
  local handle_pid old_id

  mkdir "$target"
  printf '+memory\n' > "$target/cgroup.subtree_control"
  mkdir "$execution"
  attach_and_pin "$target" "$pin" "$name"
  old_id=$(cat "$evidence/$name-cgroup-id.txt")
  capture_stat "$cgroup_root" "$evidence/$name-parent-stat-before.txt"

  strace -qq -f -e trace=name_to_handle_at,open_by_handle_at \
    -o "$evidence/$name-handle-syscalls.txt" \
    "$helper" handle-probe "$target" "$marker" \
    > "$evidence/$name-handle.jsonl" \
    2> "$evidence/$name-handle.stderr" &
  handle_pid=$!
  for _ in $(seq 1 500); do
    [[ -s $evidence/$name-handle.jsonl ]] && break
    kill -0 "$handle_pid" 2>/dev/null || break
    sleep 0.01
  done
  jq -e 'select(.stage == "before" and .open_result == 0)' \
    "$evidence/$name-handle.jsonl" >/dev/null

  strace -qq -f -e trace=openat,write,clone3 \
    -o "$evidence/$name-offline-admission-syscalls.txt" \
    "$helper" offline-admission-probe "$target" "$marker" \
    > "$evidence/$name-offline-admission.jsonl" \
    2> "$evidence/$name-offline-admission.stderr" &
  admission_pid=$!
  for _ in $(seq 1 500); do
    [[ -s $evidence/$name-offline-admission.jsonl ]] && break
    kill -0 "$admission_pid" 2>/dev/null || break
    sleep 0.01
  done
  jq -e 'select(.stage == "before" and .directory_fd_open == true and
    .cgroup_procs_fd_open == true)' \
    "$evidence/$name-offline-admission.jsonl" >/dev/null

  if [[ $workload == page-cache ]]; then
    bash -c "echo \$\$ > '$execution/cgroup.procs'; dd if=/dev/zero of='$scratch/$name-cache' bs=1M count=256 conv=fsync status=none"
  else
    /usr/bin/sleep 0 >/dev/null 2>&1
    bash -c "echo \$\$ > '$execution/cgroup.procs'; exec /usr/bin/sleep 0.1"
  fi
  [[ ! -s $execution/cgroup.procs ]]
  cat "$execution/memory.current" > "$evidence/$name-memory.current"
  cat "$execution/memory.stat" > "$evidence/$name-memory.stat"
  cat "$execution/cgroup.stat" > "$evidence/$name-execution-stat-before-removal.txt"
  cat "$target/cgroup.stat" > "$evidence/$name-target-stat-before-removal.txt"
  ss -tanp > "$evidence/$name-sockets-before-removal.txt"

  rmdir "$execution"
  rmdir "$target"
  find /sys/fs/cgroup -xdev -inum "$old_id" -print \
    > "$evidence/$name-old-id-live-paths.txt"
  set +e
  bash -c "echo \$\$ > '$target/cgroup.procs'" \
    > "$evidence/$name-move-after-removal.stdout" \
    2> "$evidence/$name-move-after-removal.stderr"
  printf '%s\n' "$?" > "$evidence/$name-move-after-removal.exit"
  set -e
  touch "$marker"
  wait "$handle_pid"
  wait "$admission_pid"
  admission_pid=
  capture_stat "$cgroup_root" "$evidence/$name-parent-stat-after-removal.txt"
  "$helper" link-info "$pin" > "$evidence/$name-link-after-removal.json"
  : > "$evidence/$name-link-retention.jsonl"
  for iteration in $(seq 0 20); do
    "$helper" link-info "$pin" \
      | jq -c --argjson iteration "$iteration" --arg now "$(date +%s%N)" \
        '. + {iteration:$iteration,timestamp_ns:$now}' \
      >> "$evidence/$name-link-retention.jsonl"
    [[ $iteration -eq 20 ]] || sleep 0.25
  done

  set +e
  strace -qq -f -e trace=bpf -o "$evidence/$name-detach-syscalls.txt" \
    "$helper" link-detach "$pin" > "$evidence/$name-detach.json" \
    2> "$evidence/$name-detach.stderr"
  printf '%s\n' "$?" > "$evidence/$name-detach.exit"
  set -e
  "$helper" link-info "$pin" > "$evidence/$name-link-after-detach.json"
  rm -f "$pin" "$scratch/$name-cache"

  jq -n \
    --arg name "$name" \
    --arg workload "$workload" \
    --argjson old_id "$old_id" \
    --argjson memory_current "$(cat "$evidence/$name-memory.current")" \
    --slurpfile before "$evidence/$name-link-before.json" \
    --slurpfile removed "$evidence/$name-link-after-removal.json" \
    --slurpfile detached "$evidence/$name-detach.json" \
    --slurpfile handle "$evidence/$name-handle.jsonl" \
    --slurpfile admission "$evidence/$name-offline-admission.jsonl" \
    --slurpfile retention "$evidence/$name-link-retention.jsonl" \
    --rawfile paths "$evidence/$name-old-id-live-paths.txt" \
    --argjson move_exit "$(cat "$evidence/$name-move-after-removal.exit")" '
      ($paths | split("\n") | map(select(length > 0))) as $live_paths |
      {
        case: $name,
        workload: $workload,
        old_cgroup_id: $old_id,
        memory_current_before_removal: $memory_current,
        live_paths_after_removal: $live_paths,
        handle_observations: $handle,
        offline_admission_observations: $admission,
        link_retention_observations: $retention,
        link_before: $before[0],
        link_after_removal: $removed[0],
        detach: $detached[0],
        move_after_removal_exit: $move_exit,
        assertions: {
          handle_opened_while_live: ($handle[0].open_result == 0),
          handle_stale_after_removal: ($handle[1].open_result == -1 and $handle[1].open_errno == 116),
          cgroup_procs_write_refused_enodev: (
            $admission[1].write_result == -1 and $admission[1].write_errno == 19
          ),
          clone_into_cgroup_refused_enoent: (
            $admission[1].clone3_result == -1 and $admission[1].clone3_errno == 2
          ),
          old_id_absent_from_live_hierarchy: ($live_paths | length == 0),
          process_cannot_enter_removed_path: ($move_exit != 0),
          link_never_retargeted: (
            all($retention[]; .cgroup_id == $old_id or .cgroup_id == 0)
          ),
          explicit_detach_succeeded: ($detached[0].detach_result == 0),
          link_reports_zero_after_detach: ($detached[0].after.cgroup_id == 0),
          link_identity_preserved: (
            $detached[0].before.id == $before[0].id and
            $detached[0].before.prog_id == $before[0].prog_id and
            $detached[0].before.attach_type == $before[0].attach_type and
            $detached[0].after.id == $before[0].id and
            $detached[0].after.prog_id == $before[0].prog_id and
            $detached[0].after.attach_type == $before[0].attach_type
          )
        }
      }' > "$evidence/$name-result.json"
}

run_case no-file no-file
run_case page-cache page-cache

bpftool -j -p prog show > "$evidence/final-programs.json"
bpftool -j -p link show > "$evidence/final-links.json"
bpftool -j -p map show > "$evidence/final-maps.json"

jq -n \
  --slurpfile memory "$evidence/page-cache-result.json" \
  --slurpfile control "$evidence/no-file-result.json" '
    {
      authoritative: false,
      purpose: "kernel proof for an offline cgroup target retained after pathname removal",
      cases: {page_cache: $memory[0], no_file_control: $control[0]}
    }
    | .verdict = (
        if all(.cases[]; all(.assertions[]; .))
        then "PASS"
        else "UNPROVEN"
        end
      )' > "$evidence/result.json"

checksum_tmp=$(mktemp "$evidence/.SHA256SUMS.XXXXXX")
(cd "$evidence" && find . -type f ! -name SHA256SUMS \
  ! -name '.SHA256SUMS.*' -print0 | sort -z | xargs -0 sha256sum) \
  > "$checksum_tmp"
mv "$checksum_tmp" "$evidence/SHA256SUMS"
jq -e '.verdict == "PASS"' "$evidence/result.json" >/dev/null
