#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# S12: exhaust the bounded tuple/cookie maps and prove bounded fail-closed Resolve.

set -euo pipefail

evidence="${S12_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s12/run1}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
execution="$executions/s12-e1"
netns=soglia-s12-e1
host_veth=sgh-s12e1
proxy_link=soglia-proxy0
host_table=soglia_spike_s12
pin_root=/sys/fs/bpf/soglia-spike/s12
map_pins="$pin_root/maps"
link_pins="$pin_root/links"
object=/var/tmp/spike/bpf/soglia-small-diag.o
harness=/var/tmp/spike/target/release/s12_exhaustion
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
execution_id=s12-execution-generation-1
exec_ident=12001001
ready=/run/soglia-spike-s12.ready
go=/run/soglia-spike-s12.go
membership_ready=/run/soglia-spike-s12-membership.ready
membership_captured=/run/soglia-spike-s12-membership.captured
overflow_ready=/run/soglia-spike-s12-overflow.ready
control_go=/run/soglia-spike-s12-control.go
harness_pid=

markers=(
    "$ready" "$go" "$membership_ready" "$membership_captured" "$overflow_ready" "$control_go"
    /run/soglia-spike-s12-precontrol-host.ready
    /run/soglia-spike-s12-precontrol-agent.ready
    /run/soglia-spike-s12-precontrol-agent.go
    /run/soglia-spike-s12-fill-host.ready
    /run/soglia-spike-s12-fill-agent.ready
    /run/soglia-spike-s12-fill-agent.go
    /run/soglia-spike-s12-overflow-host.ready
    /run/soglia-spike-s12-overflow-agent.ready
    /run/soglia-spike-s12-overflow-agent.go
    /run/soglia-spike-s12-control-host.ready
    /run/soglia-spike-s12-control-agent.ready
    /run/soglia-spike-s12-control-agent.go
)

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence"

cleanup_owned() {
    set +e
    if [[ -n "$harness_pid" ]] && kill -0 "$harness_pid" 2>/dev/null; then
        kill -TERM "$harness_pid"
        wait "$harness_pid"
    fi
    harness_pid=
    if [[ -e "$execution/cgroup.kill" ]]; then
        printf '1\n' > "$execution/cgroup.kill"
        for _ in $(seq 1 100); do
            [[ ! -s "$execution/cgroup.procs" ]] && break
            sleep 0.01
        done
    fi
    nft list table inet "$host_table" >/dev/null 2>&1 && nft delete table inet "$host_table"
    ip link show "$host_veth" >/dev/null 2>&1 && ip link del "$host_veth"
    ip netns list | grep -q "^$netns\b" && ip netns del "$netns"
    ip link show "$proxy_link" >/dev/null 2>&1 && ip link del "$proxy_link"
    for pin in sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops; do
        [[ -e "$link_pins/$pin" ]] && rm "$link_pins/$pin"
    done
    for pin in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag soglia_map_fail_diag; do
        [[ -e "$map_pins/$pin" ]] && rm "$map_pins/$pin"
    done
    rmdir "$link_pins" "$map_pins" "$pin_root" /sys/fs/bpf/soglia-spike 2>/dev/null
    for marker in "${markers[@]}"; do rm -f "$marker"; done
    [[ -d "$execution" ]] && rmdir "$execution"
    [[ -d "$executions" ]] && rmdir "$executions"
    set -e
}

record_cleanup() {
    {
        echo '# S12 cleanup verification'
        date -u +"UTC=%FT%TZ"
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        for path in "$executions" "$execution" /sys/fs/bpf/soglia-spike; do
            [[ -e "$path" ]] && echo "PRESENT $path" || echo "ABSENT $path"
        done
        echo delegated_children_begin
        find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f inode=%i\n' | sort
        echo delegated_children_end
        echo cgroup_tree_begin
        bpftool cgroup tree "$unit"
        echo cgroup_tree_end
        echo bpffs_begin
        find /sys/fs/bpf -mindepth 1 -maxdepth 6 -print | sort
        echo bpffs_end
        echo test_processes_begin
        ps -eo pid=,ppid=,comm=,args= | awk '$3 == "s12_exhaustion" || $3 == "soglia-spike-agent"'
        echo test_processes_end
        echo netns_begin
        ip netns list
        echo netns_end
        echo owned_links_begin
        ip -o link show | grep -E "$host_veth|$proxy_link" || true
        echo owned_links_end
        echo owned_nft_begin
        nft list tables | grep "$host_table" || true
        echo owned_nft_end
        echo "soglia_foreign_program_count=$(bpftool -j prog show | jq '[.[] | select(((.name // "") | startswith("soglia_")) or ((.name // "") | startswith("foreign_")))] | length')"
        echo "cgroup_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
        echo "soglia_map_count=$(bpftool -j map show | jq '[.[] | select((.name // "") | startswith("soglia_"))] | length')"
        echo small_object_loaded_count_begin
        bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_"))] | length'
        echo small_object_loaded_count_end
    } > "$evidence/s12-cleanup.txt"
    bpftool -j prog show > "$evidence/s12-final-prog.json"
    bpftool -j link show > "$evidence/s12-final-link.json"
    bpftool -j map show > "$evidence/s12-final-map.json"
    find /sys/fs/bpf -mindepth 1 -maxdepth 6 -printf '%y %p\n' | sort > "$evidence/s12-final-bpffs.txt"
}

on_exit() {
    status=$?
    cleanup_owned
    record_cleanup
    echo "$status" > "$evidence/s12-run-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

cleanup_owned

bpftool -j prog show > "$evidence/s12-baseline-prog.json"
bpftool -j link show > "$evidence/s12-baseline-link.json"
bpftool -j map show > "$evidence/s12-baseline-map.json"
find /sys/fs/bpf -mindepth 1 -maxdepth 6 -printf '%y %p\n' | sort > "$evidence/s12-baseline-bpffs.txt"
{
    echo '# S12 fresh preflight'
    date -u +"UTC=%FT%TZ"
    uname -a
    systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID -p Delegate -p DelegateControllers -p ControlGroup -p NRestarts --no-pager
    echo "delegated_root_inode=$(stat -c %i "$unit")"
    echo delegated_children_begin
    find "$unit" -mindepth 1 -maxdepth 2 -type d -printf '%P inode=%i\n' | sort
    echo delegated_children_end
    bpftool cgroup tree "$unit"
    echo bpffs_begin
    cat "$evidence/s12-baseline-bpffs.txt"
    echo bpffs_end
    echo netns_begin
    ip netns list
    echo netns_end
    echo owned_links_begin
    ip -o link show | grep -E 'sgh-|soglia-proxy' || true
    echo owned_links_end
    echo owned_nft_begin
    nft list tables | grep soglia || true
    echo owned_nft_end
} > "$evidence/s12-preflight.txt"

{
    echo '# S12 authorization-relevant map characterization'
    date -u +"UTC=%FT%TZ"
    echo 'soglia_tuples|HASH|8 in S12 (4096 normal)|sockops ACTIVE_ESTABLISHED publish|Proxy Resolve|failed update increments C_TUPLE_INSERT_FAILED and emits EV_MAP_FULL; no tuple means bounded DENY|authorization-final'
    echo 'soglia_cookie_a|HASH|8 in S12 (4096 normal)|connect4 cookie->cgid|sockops candidate-A evidence|failed update leaves A absent; incomplete evidence must not authorize|authorization-supporting'
    echo 'soglia_sk_b|SK_STORAGE|kernel-managed/no finite max_entries knob|connect4 create/get|sockops candidate-B evidence|allocation failure leaves B absent; incomplete evidence must not authorize; deterministic full test unavailable|authorization-supporting'
    echo 'policy_local|ARRAY|1|trusted loader existing-key set|connect4 active gate|loader aborts if set fails; not a dynamic exhaustion case|authorization-gate'
    echo 'soglia_policy|HASH|1024|shared-instance loader path|active gate when exec_ident=0|not read by the per-Execution path exercised in S12|not-current-path'
    echo 'soglia_staging|HASH|SPIKE_TUPLE_MAX|delay variant sockops|S1b harness promotion|absent from small non-delay variant and not read by Resolve|not-current-path'
    echo 'soglia_counters/soglia_denies/soglia_events/soglia_diag_entries/soglia_port_diag/soglia_map_fail_diag/soglia_meta|diagnostic/metadata|various|diagnostics|observers only|not-authorization'
    echo 'candidate_C=loader rodata; no insertion-capacity failure'
    echo 'candidate_D=netns-cookie helper only in this spike; trusted owner map not implemented/tested'
} > "$evidence/s12-map-characterization.txt"

{
    echo '# S12 small-variant provenance and scope'
    date -u +"UTC=%FT%TZ"
    grep -n 'SPIKE_TUPLE_MAX\|SPIKE_MAP_FAILURE_DIAGNOSTIC\|build soglia-small' /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c /soglia/spikes/cgroup-bpf/build.sh
    sha256sum /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c /soglia/spikes/cgroup-bpf/build.sh /soglia/spikes/cgroup-bpf/harness/src/bin/s12_exhaustion.rs "$object" "$harness" "$agent"
    file "$object" "$harness" "$agent"
    llvm-objdump -d /var/tmp/spike/bpf/soglia.o > /tmp/s12-normal.dis
    llvm-objdump -d /var/tmp/spike/bpf/soglia-small.o > /tmp/s12-small.dis
    sed -E 's#(/var/tmp/spike/bpf/)?soglia(-small)?\.o#OBJECT#g' /tmp/s12-normal.dis > /tmp/s12-normal.normalized.dis
    sed -E 's#(/var/tmp/spike/bpf/)?soglia(-small)?\.o#OBJECT#g' /tmp/s12-small.dis > /tmp/s12-small.normalized.dis
    if cmp -s /tmp/s12-normal.normalized.dis /tmp/s12-small.normalized.dis; then
        echo 'normal_vs_capacity_only_program_instructions=IDENTICAL'
    else
        echo 'normal_vs_capacity_only_program_instructions=DIFFERENT'
        diff -u /tmp/s12-normal.normalized.dis /tmp/s12-small.normalized.dis || true
    fi
    echo 'small_diag_extra_semantics=SPIKE_DIAGNOSTIC entry counters plus SPIKE_MAP_FAILURE_DIAGNOSTIC passive helper-result observations only'
} > "$evidence/s12-provenance.txt"

mkdir "$executions"
printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
mkdir "$execution"

ip link add "$proxy_link" type dummy
ip addr add 10.200.255.1/32 dev "$proxy_link"
ip link set "$proxy_link" up
ip netns add "$netns"
ip link add "$host_veth" type veth peer name eth0 netns "$netns"
ip addr add 10.201.0.2/30 dev "$host_veth"
ip link set "$host_veth" up
ip netns exec "$netns" ip link set lo up
ip netns exec "$netns" ip addr add 10.201.0.1/30 dev eth0
ip netns exec "$netns" ip link set eth0 up
ip netns exec "$netns" ip route add 10.200.255.1/32 via 10.201.0.2 dev eth0

ip netns exec "$netns" nft -f - <<'NFT'
table inet soglia {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
    }
    chain output {
        type filter hook output priority filter; policy drop;
        oif "lo" accept
        ct state established,related accept
        ip daddr 10.200.255.1 tcp dport 15001 ct state new accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
NFT

nft -f - <<'NFT'
table inet soglia_spike_s12 {
    chain input {
        type filter hook input priority filter - 10; policy accept;
        iifname "sgh-s12e1" ip saddr != 10.201.0.1 drop
        iifname "sgh-s12e1" ct state invalid drop
        iifname "sgh-s12e1" ct state new meta l4proto != tcp drop
        iifname "sgh-s12e1" ct state new ip daddr != 10.200.255.1 drop
        iifname "sgh-s12e1" ct state new tcp dport != 15001 drop
    }
    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        iifname "sgh-s12e1" drop
        oifname "sgh-s12e1" drop
    }
}
NFT

{
    echo '# S12 fresh topology'
    date -u +"UTC=%FT%TZ"
    echo "execution_id=$execution_id"
    echo "executions_inode=$(stat -c %i "$executions")"
    echo "execution_inode=$(stat -c %i "$execution")"
    echo "execution_procs=$(tr '\n' ' ' < "$execution/cgroup.procs")"
    ip -details addr show dev "$proxy_link"
    ip -details addr show dev "$host_veth"
    ip netns exec "$netns" ip -details addr show
    ip netns exec "$netns" ip route show
    ip netns exec "$netns" nft list ruleset
    nft list table inet "$host_table"
} > "$evidence/s12-topology.txt"

"$harness" \
    "$object" "$execution" "$map_pins" "$link_pins" "$netns" "$agent" \
    "$execution_id" "$exec_ident" "$ready" "$go" "$membership_ready" \
    "$membership_captured" "$overflow_ready" "$control_go" \
    > "$evidence/s12-harness.txt" 2>&1 &
harness_pid=$!

for _ in $(seq 1 5000); do
    [[ -e "$ready" ]] && break
    kill -0 "$harness_pid" 2>/dev/null || break
    sleep 0.01
done
[[ -e "$ready" ]]

bpftool -j prog show > "$evidence/s12-attached-prog.json"
bpftool -j link show > "$evidence/s12-attached-link.json"
bpftool -j map show > "$evidence/s12-attached-map.json"
bpftool -j cgroup show "$execution" > "$evidence/s12-attached-cgroup-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s12-attached-cgroup-effective.json"
find /sys/fs/bpf/soglia-spike -mindepth 1 -maxdepth 6 -printf '%y %p\n' | sort > "$evidence/s12-attached-bpffs.txt"
{
    echo '# S12 loaded map contract'
    date -u +"UTC=%FT%TZ"
    for map in soglia_tuples soglia_cookie_a soglia_sk_b soglia_map_fail_diag; do
        echo "map=$map"
        bpftool -j map show pinned "$map_pins/$map"
    done
} > "$evidence/s12-loaded-map-contract.txt"
touch "$go"

for _ in $(seq 1 5000); do
    [[ -e "$membership_ready" ]] && break
    kill -0 "$harness_pid" 2>/dev/null || break
    sleep 0.01
done
[[ -e "$membership_ready" ]]
agent_pid=$(sed -n 's/^pid=//p' "$membership_ready")
expected_membership="0::${execution#/sys/fs/cgroup}"
{
    echo '# S12 live agent membership before fill traffic'
    date -u +"UTC=%FT%TZ"
    echo "actual_agent_pid=$agent_pid"
    echo "target_cgroup=$execution"
    echo "target_cgroup_inode=$(stat -c %i "$execution")"
    echo "expected_proc_cgroup_line=$expected_membership"
    echo agent_proc_cgroup_begin
    cat "/proc/$agent_pid/cgroup"
    echo agent_proc_cgroup_end
    echo target_cgroup_procs_begin
    cat "$execution/cgroup.procs"
    echo target_cgroup_procs_end
    grep -Fxq "$expected_membership" "/proc/$agent_pid/cgroup" && echo proc_exact_membership=true || echo proc_exact_membership=false
    grep -Fxq "$agent_pid" "$execution/cgroup.procs" && echo cgroup_procs_contains_agent=true || echo cgroup_procs_contains_agent=false
    echo "agent_netns_inode=$(stat -Lc %i "/proc/$agent_pid/ns/net")"
    echo "owned_netns_inode=$(stat -Lc %i "/run/netns/$netns")"
} > "$evidence/s12-membership.txt"
touch "$membership_captured"

for _ in $(seq 1 10000); do
    [[ -e "$overflow_ready" ]] && break
    kill -0 "$harness_pid" 2>/dev/null || break
    sleep 0.01
done
[[ -e "$overflow_ready" ]]

for map in soglia_tuples soglia_cookie_a soglia_sk_b soglia_counters soglia_diag_entries soglia_map_fail_diag soglia_denies; do
    bpftool -j map dump pinned "$map_pins/$map" > "$evidence/s12-overflow-$map.json" 2> "$evidence/s12-overflow-$map.stderr" || true
done
bpftool -j prog show > "$evidence/s12-overflow-prog.json"
bpftool -j link show > "$evidence/s12-overflow-link.json"
bpftool -j map show > "$evidence/s12-overflow-map.json"
bpftool -j cgroup show "$execution" > "$evidence/s12-overflow-cgroup-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s12-overflow-cgroup-effective.json"
{
    echo '# S12 full-map and overflow kernel snapshot'
    date -u +"UTC=%FT%TZ"
    echo "tuple_occupancy=$(jq 'length' "$evidence/s12-overflow-soglia_tuples.json")"
    echo "cookie_occupancy=$(jq 'length' "$evidence/s12-overflow-soglia_cookie_a.json")"
    echo "direct_program_count=$(jq 'length' "$evidence/s12-overflow-cgroup-direct.json")"
    echo "effective_program_count=$(jq 'length' "$evidence/s12-overflow-cgroup-effective.json")"
    echo "execution_procs=$(tr '\n' ' ' < "$execution/cgroup.procs")"
    ss -tnp | grep -E ':15001\b' || true
} > "$evidence/s12-overflow-state.txt"
touch "$control_go"

set +e
wait "$harness_pid"
harness_status=$?
set -e
harness_pid=
echo "$harness_status" > "$evidence/s12-harness-exit-status.txt"
[[ "$harness_status" -eq 0 ]]

{
    echo '# S12 result summary'
    date -u +"UTC=%FT%TZ"
    grep -E '^(tuple_capacity=|cookie_capacity=|pre_exhaustion_proxy_control=|phase_a_|phase_b_|control_|capacity_restored_control=|post_connection_|S12_RESULT=)' "$evidence/s12-harness.txt" || true
} > "$evidence/s12-summary.txt"
