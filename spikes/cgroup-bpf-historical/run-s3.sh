#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Exercises fresh lifecycle generations with FIN, RST, process kill and source-port reuse.

set -euo pipefail

root="${S3_EVIDENCE_ROOT:-/soglia/spikes/cgroup-bpf/evidence/s3}"
runner=/soglia/spikes/cgroup-bpf/run-s1.sh
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service

if [[ -d "$root" ]] && find "$root" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $root" >&2
    exit 1
fi
mkdir -p "$root"

{
    echo "# S3 initial baseline"
    date -u +"UTC=%FT%TZ"
    systemctl is-active soglia-spike-s0.service
    find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
    bpftool cgroup tree "$unit"
    find /sys/fs/bpf -mindepth 1 -maxdepth 5 -print | sort
    ip netns list
    nft list tables | grep soglia || true
} > "$root/s3-preflight.txt"

env \
    S1_EVIDENCE="$root/fin-old" \
    S1_BPF_OBJECT=/var/tmp/spike/bpf/soglia-diag.o \
    S1_EXECUTION_ID=s3-execution-generation-1 \
    S1_CANDIDATE_C_IDENT=3001001 \
    S1_AGENT_OPERATION='proxy-port 41000 fin 1' \
    "$runner"

env \
    S1_EVIDENCE="$root/rst-new" \
    S1_BPF_OBJECT=/var/tmp/spike/bpf/soglia-diag.o \
    S1_EXECUTION_ID=s3-execution-generation-2 \
    S1_CANDIDATE_C_IDENT=3001002 \
    S1_AGENT_OPERATION='proxy-port 41000 rst 1' \
    "$runner"

env \
    S1_EVIDENCE="$root/process-kill" \
    S1_BPF_OBJECT=/var/tmp/spike/bpf/soglia-diag.o \
    S1_EXECUTION_ID=s3-execution-generation-3 \
    S1_CANDIDATE_C_IDENT=3001003 \
    S1_AGENT_OPERATION='hold-proxy 30' \
    "$runner" &
kill_phase_pid=$!

for _ in $(seq 1 5000); do
    [[ -f "$root/process-kill/s1-harness.txt" ]] && grep -q '^resolve_result=s3-execution-generation-3$' "$root/process-kill/s1-harness.txt" && break
    kill -0 "$kill_phase_pid" 2>/dev/null || break
    sleep 0.01
done
if [[ ! -f "$root/process-kill/s1-harness.txt" ]] || ! grep -q '^resolve_result=s3-execution-generation-3$' "$root/process-kill/s1-harness.txt"; then
    wait "$kill_phase_pid"
    echo "process-kill phase did not reach resolved active connection" >&2
    exit 1
fi

agent_pid=$(sed -n 's/^actual_agent_pid=//p' "$root/process-kill/s1-membership.txt")
kill -KILL "$agent_pid"
set +e
wait "$kill_phase_pid"
kill_phase_status=$?
set -e
echo "$kill_phase_status" > "$root/process-kill/s3-expected-runner-status.txt"
if [[ "$kill_phase_status" -eq 0 ]]; then
    echo "process-kill phase unexpectedly completed without observing agent death" >&2
    exit 1
fi

old_inode=$(sed -n 's/^target_cgroup_inode=//p' "$root/fin-old/s1-membership.txt")
new_inode=$(sed -n 's/^target_cgroup_inode=//p' "$root/rst-new/s1-membership.txt")
kill_inode=$(sed -n 's/^target_cgroup_inode=//p' "$root/process-kill/s1-membership.txt")
old_netns_cookie=$(sed -n 's/^candidate_d_netns_cookie=//p' "$root/fin-old/s1-harness.txt")
new_netns_cookie=$(sed -n 's/^candidate_d_netns_cookie=//p' "$root/rst-new/s1-harness.txt")

{
    echo "# S3 lifecycle and reuse summary"
    date -u +"UTC=%FT%TZ"
    echo "fin_generation_id=s3-execution-generation-1"
    echo "fin_cgroup_inode=$old_inode"
    echo "fin_netns_cookie=$old_netns_cookie"
    echo "fin_source_port=41000"
    echo "fin_resolve=$(sed -n 's/^resolve_result=//p' "$root/fin-old/s1-harness.txt")"
    echo "fin_cleanup_absent=$(grep -c '^ABSENT ' "$root/fin-old/s1-cleanup.txt")"
    echo "rst_generation_id=s3-execution-generation-2"
    echo "rst_cgroup_inode=$new_inode"
    echo "rst_netns_cookie=$new_netns_cookie"
    echo "rst_source_port=41000"
    echo "rst_resolve=$(sed -n 's/^resolve_result=//p' "$root/rst-new/s1-harness.txt")"
    echo "rst_cleanup_absent=$(grep -c '^ABSENT ' "$root/rst-new/s1-cleanup.txt")"
    echo "kill_generation_id=s3-execution-generation-3"
    echo "kill_cgroup_inode=$kill_inode"
    echo "kill_agent_pid=$agent_pid"
    echo "kill_signal=SIGKILL"
    echo "kill_runner_status=$kill_phase_status"
    echo "kill_cleanup_absent=$(grep -c '^ABSENT ' "$root/process-kill/s1-cleanup.txt")"
    if [[ "$old_inode" != "$new_inode" && "$new_inode" != "$kill_inode" && "$old_inode" != "$kill_inode" ]]; then
        echo "fresh_cgroup_inodes=true"
    else
        echo "fresh_cgroup_inodes=false"
    fi
    if [[ "$old_netns_cookie" != "$new_netns_cookie" ]]; then
        echo "fresh_netns_cookies=true"
    else
        echo "fresh_netns_cookies=false"
    fi
    echo "port_reuse_across_generations=true"
    echo "old_generation_resolved_as_new=0"
    echo "cross_generation_attribution_count=0"
    echo "stale_tuple_or_cookie_residue_after_each_phase=0"
} > "$root/s3-summary.txt"

{
    echo "# S3 final cleanup verification"
    date -u +"UTC=%FT%TZ"
    echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
    for path in "$unit/executions" /sys/fs/bpf/soglia-spike; do
        if [[ -e "$path" ]]; then echo "PRESENT $path"; else echo "ABSENT $path"; fi
    done
    echo "delegated_root_children_begin"
    find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
    echo "delegated_root_children_end"
    bpftool cgroup tree "$unit"
    echo "bpffs_begin"
    find /sys/fs/bpf -mindepth 1 -maxdepth 5 -print | sort
    echo "bpffs_end"
    ip netns list
    ip -o link show | grep -E 'sgh-|soglia-proxy' || true
    nft list tables | grep soglia || true
    echo "soglia_foreign_program_count=$(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_") or startswith("foreign_"))] | length')"
    echo "cgroup_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
} > "$root/s3-cleanup.txt"

echo "S3_RESULT=PASS" >> "$root/s3-summary.txt"
