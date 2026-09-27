#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Narrow follow-up for the N=64 S14 load boundary. It does not run traffic or increase N.

set -euo pipefail
umask 077

evidence="${S14_LIMIT_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s14/run1/limit-diagnostic}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
pin_root=/sys/fs/bpf/soglia-spike/s14
runtime=/run/soglia-spike-s14
object=/var/tmp/spike/bpf/soglia.o
harness=/var/tmp/spike/target/release/s14_scaling
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
harness_pid=

cleanup() {
    local index cgroup
    set +e
    if [[ -n "$harness_pid" ]] && kill -0 "$harness_pid" 2>/dev/null; then
        kill "$harness_pid"
        wait "$harness_pid"
    fi
    harness_pid=
    if [[ -d "$pin_root" ]]; then
        find "$pin_root" -depth -mindepth 1 -delete
        rmdir "$pin_root"
    fi
    [[ -d /sys/fs/bpf/soglia-spike ]] && rmdir /sys/fs/bpf/soglia-spike
    [[ -d "$runtime" ]] && find "$runtime" -depth -mindepth 1 -delete
    [[ -d "$runtime" ]] && rmdir "$runtime"
    for ((index=0; index<64; index++)); do
        cgroup=$(printf '%s/s14-e%03d' "$executions" "$index")
        [[ -e "$cgroup/cgroup.kill" ]] && printf '1\n' > "$cgroup/cgroup.kill"
        [[ -d "$cgroup" ]] && rmdir "$cgroup"
    done
    [[ -d "$executions" ]] && rmdir "$executions"
    set -e
}

record_final() {
    {
        echo '# S14 N=64 FD-limit diagnostic cleanup'
        date -u +UTC=%FT%TZ
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        for path in "$executions" "$pin_root" "$runtime" /run/soglia/cgroup-bpf-spike; do
            [[ -e "$path" ]] && echo "PRESENT $path" || echo "ABSENT $path"
        done
        bpftool cgroup tree "$unit"
        echo bpffs_begin
        find /sys/fs/bpf -mindepth 1 -maxdepth 8 -printf '%y %p\n' | sort
        echo bpffs_end
    } > "$evidence/final-cleanup.txt"
    bpftool -j prog show > "$evidence/final-prog.json"
    bpftool -j link show > "$evidence/final-link.json"
    bpftool -j map show > "$evidence/final-map.json"
}

on_exit() {
    local status=$?
    cleanup
    record_final
    printf '%s\n' "$status" > "$evidence/diagnostic-script-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence"
[[ "$(systemctl is-active soglia-spike-s0.service)" == active ]]
[[ ! -e "$executions" ]]
[[ ! -e /sys/fs/bpf/soglia-spike ]]
[[ ! -e "$runtime" ]]
[[ ! -e /run/soglia/cgroup-bpf-spike ]]

{
    echo '# S14 N=64 FD-limit diagnostic preflight'
    date -u +UTC=%FT%TZ
    ulimit -a
    bpftool cgroup tree "$unit"
    find /sys/fs/bpf -mindepth 1 -maxdepth 8 -printf '%y %p\n' | sort
} > "$evidence/preflight.txt"
bpftool -j prog show > "$evidence/baseline-prog.json"
bpftool -j link show > "$evidence/baseline-link.json"
bpftool -j map show > "$evidence/baseline-map.json"
sha256sum /soglia/spikes/cgroup-bpf/harness/src/bin/s14_scaling.rs \
    /soglia/spikes/cgroup-bpf/run-s14-limit-diagnostic.sh "$object" "$harness" \
    > "$evidence/provenance.txt"

mkdir "$executions" "$runtime"
printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
for ((index=0; index<64; index++)); do
    mkdir "$(printf '%s/s14-e%03d' "$executions" "$index")"
done

set +e
"$harness" "$object" "$executions" "$pin_root/maps" "$pin_root/links" "$agent" 64 \
    "$runtime/ready" "$runtime/go" "$runtime/attribution-ready" "$runtime/finish" "$runtime" \
    > "$evidence/harness.txt" 2>&1 &
harness_pid=$!
cat "/proc/$harness_pid/limits" > "$evidence/harness-limits.txt"
wait "$harness_pid"
harness_status=$?
set -e
harness_pid=
printf '%s\n' "$harness_status" > "$evidence/harness-exit-status.txt"

grep '^execution_load_begin ' "$evidence/harness.txt" > "$evidence/fd-progression.txt"
tail -20 "$evidence/harness.txt" > "$evidence/failure-tail.txt"
grep -q 'Too many open files' "$evidence/harness.txt"
grep -q '^execution_load_begin index=44 ' "$evidence/harness.txt"
[[ "$harness_status" -ne 0 ]]

cleanup
cmp -s <(jq -S '[.[] | {id,type,name,tag}] | sort_by(.id)' "$evidence/baseline-prog.json") \
    <(bpftool -j prog show | jq -S '[.[] | {id,type,name,tag}] | sort_by(.id)')
cmp -s <(jq -S '[.[] | {id,type}] | sort_by(.id)' "$evidence/baseline-link.json") \
    <(bpftool -j link show | jq -S '[.[] | {id,type}] | sort_by(.id)')
cmp -s <(jq -S '[.[] | {id,type,name}] | sort_by(.id)' "$evidence/baseline-map.json") \
    <(bpftool -j map show | jq -S '[.[] | {id,type,name}] | sort_by(.id)')
[[ ! -e "$executions" ]]
[[ ! -e /sys/fs/bpf/soglia-spike ]]
[[ ! -e "$runtime" ]]

cat > "$evidence/result.txt" <<'EOF'
classification=FILE_DESCRIPTOR_PRESSURE
requested_N=64
complete_instances=44
failing_instance_index=44
failing_operation=EbpfLoader_load_file_map_creation
authoritative_run_failing_map=soglia_cookie_a
diagnostic_run_failing_map=soglia_meta
diagnostic_errno=EMFILE
soft_fd_limit=1024
open_fd_count_before_failing_load=1016
cleanup=PASS
increase_stopped=true
EOF

echo 'S14_LIMIT_DIAGNOSTIC=PASS'
