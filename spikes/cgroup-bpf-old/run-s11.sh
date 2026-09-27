#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# S11: representative complete lifecycle followed by independent zero-residue checks.

set -euo pipefail

evidence="${S11_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s11/run1}"
lifecycle="$evidence/lifecycle"
runner=/soglia/spikes/cgroup-bpf/run-s1.sh
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
execution="$executions/s1-e1"
netns=soglia-s1-e1
host_veth=sgh-s1e1
proxy_link=soglia-proxy0
host_table=soglia_spike_s1
pin_root=/sys/fs/bpf/soglia-spike
map_pins="$pin_root/s1/maps"
link_pins="$pin_root/s1/links"
execution_id=s11-execution-generation-1
runner_pid=

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence"

owned_state() {
    local phase="$1"
    local out="$evidence/s11-$phase-owned-state.txt"
    {
        echo '[cgroups]'
        find "$unit" -mindepth 1 -maxdepth 2 -type d -printf '%P inode=%i\n' 2>/dev/null | sort
        echo '[unit_processes]'
        while IFS= read -r procs; do
            rel="${procs#"$unit"/}"
            while IFS= read -r pid; do
                [[ -z "$pid" ]] && continue
                args=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
                printf '%s pid=%s args=%s\n' "${rel%/cgroup.procs}" "$pid" "$args"
            done < "$procs"
        done < <(find "$unit" -name cgroup.procs -type f | sort)
        echo '[runc_containers]'
        runc list --format json 2>/dev/null | jq -r '.[] | [.id, (.pid|tostring), .status, .bundle] | @tsv' 2>/dev/null | sort || true
        echo '[owned_netns]'
        ip netns list | awk '$1 ~ /^soglia-/ {print}' | sort
        echo '[owned_links]'
        ip -o link show | awk -F': ' '$2 ~ /^(sgh-|soglia-proxy)/ {print $2}' | sed 's/@.*//' | sort
        echo '[owned_nft_tables]'
        nft list tables 2>/dev/null | grep soglia | sort || true
        echo '[bpffs_paths]'
        find /sys/fs/bpf -mindepth 1 -maxdepth 6 -printf '%y %p\n' 2>/dev/null | sort
        echo '[owned_bpf_programs]'
        bpftool -j prog show | jq -r '.[] | select(((.name // "") | startswith("soglia_")) or ((.name // "") | startswith("foreign_"))) | [.id,.type,.name,.tag] | @tsv' | sort
        echo '[cgroup_bpf_links]'
        bpftool -j link show | jq -r '.[] | select(.type == "cgroup") | [.id,.type,.prog_id,.cgroup_id,.attach_type] | @tsv' | sort
        echo '[owned_bpf_maps]'
        bpftool -j map show | jq -r '.[] | select((.name // "") | startswith("soglia_")) | [.id,.type,.name] | @tsv' | sort
        echo '[runtime_state]'
        find /run -maxdepth 3 \( -name 'soglia-spike-*' -o -name 'soglia-s1-*' \) -printf '%y %p\n' 2>/dev/null | sort
    } > "$out"
}

capture_phase() {
    local phase="$1"
    {
        echo "# S11 $phase cgroup and process state"
        date -u +"UTC=%FT%TZ"
        systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID -p ControlGroup -p NRestarts --no-pager
        echo "unit_inode=$(stat -c %i "$unit")"
        find "$unit" -mindepth 1 -maxdepth 3 -type d -printf '%p inode=%i\n' | sort
        echo 'cgroup_tree_begin'
        bpftool cgroup tree "$unit"
        echo 'cgroup_tree_end'
        echo 'cgroup_processes_begin'
        find "$unit" -name cgroup.procs -type f -print -exec sh -c 'tr "\n" " " < "$1"; echo' sh {} \;
        echo 'cgroup_processes_end'
    } > "$evidence/s11-$phase-cgroups.txt"
    ps -eo pid,ppid,sid,stat,comm,args --sort=pid > "$evidence/s11-$phase-processes.txt"
    {
        echo "# S11 $phase runc and runtime state"
        date -u +"UTC=%FT%TZ"
        echo 'runc_list_begin'
        runc list --format json 2>&1 || true
        echo 'runc_list_end'
        echo 'runc_directory_begin'
        find /run/runc -maxdepth 4 -printf '%y %p\n' 2>/dev/null | sort || true
        echo 'runc_directory_end'
        echo 'soglia_runtime_paths_begin'
        find /run -maxdepth 4 \( -iname '*soglia*' -o -path '/run/runc*' \) -printf '%y %p\n' 2>/dev/null | sort
        echo 'soglia_runtime_paths_end'
    } > "$evidence/s11-$phase-runtime.txt"
    ip netns list > "$evidence/s11-$phase-netns.txt"
    ip -j -details link show > "$evidence/s11-$phase-links.json"
    nft list ruleset > "$evidence/s11-$phase-nft.txt"
    nft -j list ruleset > "$evidence/s11-$phase-nft.json"
    find /sys/fs/bpf -mindepth 1 -maxdepth 6 -printf '%y %p\n' 2>/dev/null | sort > "$evidence/s11-$phase-bpffs.txt"
    bpftool -j prog show > "$evidence/s11-$phase-bpf-prog.json"
    bpftool -j link show > "$evidence/s11-$phase-bpf-link.json"
    bpftool -j map show > "$evidence/s11-$phase-bpf-map.json"
    owned_state "$phase"
}

cleanup_on_exit() {
    status=$?
    set +e
    if [[ -n "$runner_pid" ]] && kill -0 "$runner_pid" 2>/dev/null; then
        kill -TERM "$runner_pid"
        wait "$runner_pid"
    fi
    exit "$status"
}
trap cleanup_on_exit EXIT

capture_phase baseline

baseline_blocker=false
[[ -d "$executions" ]] && baseline_blocker=true
[[ -e "$pin_root" ]] && baseline_blocker=true
ip netns list | grep -q "^$netns\b" && baseline_blocker=true
ip link show "$host_veth" >/dev/null 2>&1 && baseline_blocker=true
ip link show "$proxy_link" >/dev/null 2>&1 && baseline_blocker=true
nft list table inet "$host_table" >/dev/null 2>&1 && baseline_blocker=true
[[ "$(bpftool -j prog show | jq '[.[] | select(((.name // "") | startswith("soglia_")) or ((.name // "") | startswith("foreign_")))] | length')" -ne 0 ]] && baseline_blocker=true
[[ "$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')" -ne 0 ]] && baseline_blocker=true
if [[ "$baseline_blocker" == true ]]; then
    printf 'S11_RESULT=UNPROVEN\nreason=nonempty_owned_baseline\n' > "$evidence/s11-summary.txt"
    exit 1
fi

env \
    S1_EVIDENCE="$lifecycle" \
    S1_BPF_OBJECT=/var/tmp/spike/bpf/soglia-diag.o \
    S1_EXECUTION_ID="$execution_id" \
    S1_CANDIDATE_C_IDENT=11001001 \
    S1_AGENT_OPERATION='hold-proxy 30' \
    S1_TRUSTED_TEARDOWN=true \
    S1_CLEANUP_LOG="$evidence/s11-teardown-order.txt" \
    "$runner" > "$evidence/s11-runner.txt" 2>&1 &
runner_pid=$!

for _ in $(seq 1 6000); do
    if [[ -f "$lifecycle/s1-harness.txt" ]] && grep -q "^resolve_result=$execution_id$" "$lifecycle/s1-harness.txt"; then
        break
    fi
    kill -0 "$runner_pid" 2>/dev/null || break
    sleep 0.01
done
if [[ ! -f "$lifecycle/s1-harness.txt" ]] || ! grep -q "^resolve_result=$execution_id$" "$lifecycle/s1-harness.txt"; then
    echo 'representative lifecycle did not reach successful Resolve' >&2
    wait "$runner_pid"
    exit 1
fi

capture_phase live
bpftool -j cgroup show "$execution" > "$evidence/s11-live-cgroup-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s11-live-cgroup-effective.json"
ip netns exec "$netns" ip -j -details addr show > "$evidence/s11-live-netns-links.json"
ip netns exec "$netns" ip -j route show > "$evidence/s11-live-netns-routes.json"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s11-live-netns-nft.json"
for map in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag soglia_staging; do
    if [[ -e "$map_pins/$map" ]]; then
        bpftool -j map dump pinned "$map_pins/$map" > "$evidence/s11-live-$map.json" 2> "$evidence/s11-live-$map.stderr" || true
    fi
done
{
    echo '# S11 live ownership and connection proof'
    date -u +"UTC=%FT%TZ"
    echo "execution_id=$execution_id"
    echo "execution_cgroup=$execution"
    echo "execution_inode=$(stat -c %i "$execution")"
    echo "execution_procs=$(tr '\n' ' ' < "$execution/cgroup.procs")"
    echo "agent_pid=$(sed -n 's/^actual_agent_pid=//p' "$lifecycle/s1-membership.txt")"
    grep -E '^(actual_agent_pid_matches_placed_host_pid|proc_exact_membership|cgroup_procs_contains_agent|agent_netns_inode|owned_netns_inode)=' "$lifecycle/s1-membership.txt"
    echo "effective_program_count=$(jq 'length' "$evidence/s11-live-cgroup-effective.json")"
    echo "link_pin_count=$(find "$link_pins" -mindepth 1 -maxdepth 1 -type f | wc -l)"
    echo "map_pin_count=$(find "$map_pins" -mindepth 1 -maxdepth 1 -type f | wc -l)"
    grep -E '^(accepted_|proxy_|tuple_|candidate_[abcd]_|resolve_result=|diagnostic_tuple_entries=)' "$lifecycle/s1-harness.txt" || true
    echo 'socket_state_begin'
    ss -tnp | grep -E ':15001\b' || true
    echo 'socket_state_end'
    echo 'runtime_markers_begin'
    find /run -maxdepth 1 -name 'soglia-spike-s1*' -printf '%y %p\n' | sort
    echo 'runtime_markers_end'
} > "$evidence/s11-live-proof.txt"

kill -TERM "$runner_pid"
set +e
wait "$runner_pid"
runner_status=$?
set -e
runner_pid=
echo "$runner_status" > "$evidence/s11-runner-exit-status.txt"

capture_phase after

agent_pid=$(sed -n 's/^actual_agent_pid=//p' "$lifecycle/s1-membership.txt")
process_absent=true
kill -0 "$agent_pid" 2>/dev/null && process_absent=false
pgrep -f '/var/tmp/spike/target/release/s1_attribution|soglia-spike-agent.*hold-proxy' >/dev/null 2>&1 && process_absent=false
cgroup_absent=true
[[ -d "$executions" || -d "$execution" ]] && cgroup_absent=false
runtime_absent=true
runc list --format json 2>/dev/null | jq -e --arg id "$execution_id" '.[] | select(.id == $id)' >/dev/null 2>&1 && runtime_absent=false
find /run -maxdepth 1 -name 'soglia-spike-s1*' -print -quit | grep -q . && runtime_absent=false
netns_absent=true
ip netns list | grep -q "^$netns\b" && netns_absent=false
links_absent=true
ip link show "$host_veth" >/dev/null 2>&1 && links_absent=false
ip link show "$proxy_link" >/dev/null 2>&1 && links_absent=false
nft_absent=true
nft list table inet "$host_table" >/dev/null 2>&1 && nft_absent=false
bpf_absent=true
[[ "$(bpftool -j prog show | jq '[.[] | select(((.name // "") | startswith("soglia_")) or ((.name // "") | startswith("foreign_")))] | length')" -ne 0 ]] && bpf_absent=false
[[ "$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')" -ne 0 ]] && bpf_absent=false
bpffs_absent=true
[[ -e "$pin_root" ]] && bpffs_absent=false
attribution_absent=true
[[ "$(bpftool -j map show | jq '[.[] | select((.name // "") | startswith("soglia_"))] | length')" -ne 0 ]] && attribution_absent=false
ownership_absent=true
[[ -d "$executions" ]] && ownership_absent=false
find /run -maxdepth 1 -name 'soglia-spike-s1*' -print -quit | grep -q . && ownership_absent=false

jq '[.[] | {id,type,name,tag}] | sort_by(.id)' "$evidence/s11-baseline-bpf-prog.json" > "$evidence/s11-baseline-bpf-prog-normalized.json"
jq '[.[] | {id,type,prog_id,cgroup_id,attach_type}] | sort_by(.id)' "$evidence/s11-baseline-bpf-link.json" > "$evidence/s11-baseline-bpf-link-normalized.json"
jq '[.[] | {id,type,name}] | sort_by(.id)' "$evidence/s11-baseline-bpf-map.json" > "$evidence/s11-baseline-bpf-map-normalized.json"
jq '[.[] | {id,type,name,tag}] | sort_by(.id)' "$evidence/s11-after-bpf-prog.json" > "$evidence/s11-after-bpf-prog-normalized.json"
jq '[.[] | {id,type,prog_id,cgroup_id,attach_type}] | sort_by(.id)' "$evidence/s11-after-bpf-link.json" > "$evidence/s11-after-bpf-link-normalized.json"
jq '[.[] | {id,type,name}] | sort_by(.id)' "$evidence/s11-after-bpf-map.json" > "$evidence/s11-after-bpf-map-normalized.json"
jq '[.[] | {ifname,link_type,address,mtu,master,info_kind:(.linkinfo.info_kind // null)}] | sort_by(.ifname)' "$evidence/s11-baseline-links.json" > "$evidence/s11-baseline-links-normalized.json"
jq '[.[] | {ifname,link_type,address,mtu,master,info_kind:(.linkinfo.info_kind // null)}] | sort_by(.ifname)' "$evidence/s11-after-links.json" > "$evidence/s11-after-links-normalized.json"
jq 'walk(if type == "object" then del(.handle,.packets,.bytes) else . end)' "$evidence/s11-baseline-nft.json" > "$evidence/s11-baseline-nft-structure.json"
jq 'walk(if type == "object" then del(.handle,.packets,.bytes) else . end)' "$evidence/s11-after-nft.json" > "$evidence/s11-after-nft-structure.json"
{
    echo '# S11 external/non-owned baseline comparison'
    date -u +"UTC=%FT%TZ"
    for class in bpf-prog bpf-link bpf-map; do
        if cmp -s "$evidence/s11-baseline-$class-normalized.json" "$evidence/s11-after-$class-normalized.json"; then
            echo "$class=UNCHANGED"
        else
            echo "$class=EXTERNAL_CHURN_RECORDED_BELOW"
            diff -u "$evidence/s11-baseline-$class-normalized.json" "$evidence/s11-after-$class-normalized.json" || true
        fi
    done
    if cmp -s "$evidence/s11-baseline-links-normalized.json" "$evidence/s11-after-links-normalized.json"; then
        echo 'host_link_structure=UNCHANGED'
    else
        echo 'host_link_structure=EXTERNAL_CHURN_RECORDED_IN_RAW_SNAPSHOTS'
    fi
    if cmp -s "$evidence/s11-baseline-nft-structure.json" "$evidence/s11-after-nft-structure.json"; then
        echo 'host_nft_structure=UNCHANGED'
    else
        echo 'host_nft_structure=EXTERNAL_CHURN_RECORDED_IN_RAW_SNAPSHOTS'
    fi
    if cmp -s "$evidence/s11-baseline-netns.txt" "$evidence/s11-after-netns.txt"; then
        echo 'host_netns_set=UNCHANGED'
    else
        echo 'host_netns_set=EXTERNAL_CHURN_RECORDED_IN_RAW_SNAPSHOTS'
    fi
    echo 'process_set=EXPECTED_EXTERNAL_CHURN_NOT_USED_FOR_OWNERSHIP_DECISION'
    echo 'whole_host_nft_counters=NOT_REQUIRED_BYTE_EQUAL;_OWNED_TABLE_ABSENCE_REQUIRED'
    echo 'whole_host_link_counters=NOT_REQUIRED_BYTE_EQUAL;_OWNED_LINK_ABSENCE_REQUIRED'
    echo 'runtime_model=PROVEN_S1_DIRECT_AGENT_TOPOLOGY;_NO_RUNC_CONTAINER_CREATED_OR_EXPECTED'
} > "$evidence/s11-external-churn.txt"

baseline_restored=false
if cmp -s "$evidence/s11-baseline-owned-state.txt" "$evidence/s11-after-owned-state.txt" \
    && cmp -s "$evidence/s11-baseline-links-normalized.json" "$evidence/s11-after-links-normalized.json" \
    && cmp -s "$evidence/s11-baseline-nft-structure.json" "$evidence/s11-after-nft-structure.json" \
    && cmp -s "$evidence/s11-baseline-netns.txt" "$evidence/s11-after-netns.txt"; then
    baseline_restored=true
fi
lifecycle_created=false
if grep -q '^proc_exact_membership=true$' "$lifecycle/s1-membership.txt" \
    && grep -q '^cgroup_procs_contains_agent=true$' "$lifecycle/s1-membership.txt" \
    && grep -q "^resolve_result=$execution_id$" "$lifecycle/s1-harness.txt" \
    && grep -q '^candidate_a_resolves_current_execution=true$' "$lifecycle/s1-harness.txt" \
    && grep -q '^candidate_b_resolves_current_execution=true$' "$lifecycle/s1-harness.txt" \
    && grep -q '^candidate_c_resolves_current_execution=true$' "$lifecycle/s1-harness.txt" \
    && grep -q '^link_pin_count=6$' "$evidence/s11-live-proof.txt" \
    && grep -Eq '^map_pin_count=([1-9]|1[0-9])$' "$evidence/s11-live-proof.txt" \
    && [[ "$(jq 'length' "$evidence/s11-live-cgroup-direct.json")" -eq 6 ]] \
    && [[ "$(jq 'length' "$evidence/s11-live-cgroup-effective.json")" -eq 6 ]] \
    && [[ "$(jq 'length' "$evidence/s11-live-soglia_tuples.json")" -ge 1 ]] \
    && [[ "$(jq 'length' "$evidence/s11-live-soglia_cookie_a.json")" -ge 1 ]] \
    && jq -e '.nftables | length > 0' "$evidence/s11-live-netns-nft.json" >/dev/null; then
    lifecycle_created=true
fi

result=PASS
for value in "$lifecycle_created" "$process_absent" "$cgroup_absent" "$runtime_absent" "$netns_absent" "$links_absent" "$nft_absent" "$bpf_absent" "$bpffs_absent" "$attribution_absent" "$ownership_absent" "$baseline_restored"; do
    [[ "$value" == true ]] || result=FAIL
done
{
    echo '# S11 zero-residue verdict'
    date -u +"UTC=%FT%TZ"
    echo "representative_lifecycle_created=$lifecycle_created"
    echo "successful_resolve=$(grep -c "^resolve_result=$execution_id$" "$lifecycle/s1-harness.txt")"
    echo "trusted_runner_exit_status=$runner_status"
    echo "processes_absent=$process_absent"
    echo "cgroups_absent=$cgroup_absent"
    echo "container_runtime_state_absent=$runtime_absent"
    echo "network_namespace_absent=$netns_absent"
    echo "veth_dummy_links_absent=$links_absent"
    echo "nft_state_absent=$nft_absent"
    echo "bpf_links_programs_absent=$bpf_absent"
    echo "bpffs_pins_absent=$bpffs_absent"
    echo "attribution_state_absent=$attribution_absent"
    echo "ownership_metadata_absent=$ownership_absent"
    echo "owned_baseline_restored=$baseline_restored"
    echo "failure_control_reused=S3_process_kill_and_S7_S8_independent_residue_verifiers"
    echo "S11_RESULT=$result"
} > "$evidence/s11-summary.txt"

[[ "$result" == PASS ]]
