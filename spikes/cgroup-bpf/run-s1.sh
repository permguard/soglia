#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Creates the disposable S1 topology, records live kernel evidence, runs the experimental
# attribution harness, and removes every test-owned resource.

set -euo pipefail

evidence="${S1_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s1/placement-fixed}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
execution="$executions/s1-e1"
netns=soglia-s1-e1
host_veth=sgh-s1e1
proxy_link=soglia-proxy0
host_table=soglia_spike_s1
map_pins=/sys/fs/bpf/soglia-spike/s1/maps
link_pins=/sys/fs/bpf/soglia-spike/s1/links
ready=/run/soglia-spike-s1.ready
go=/run/soglia-spike-s1.go
host_ready=/run/soglia-spike-s1-host.ready
placement_ready=/run/soglia-spike-s1-placement.ready
placement_captured=/run/soglia-spike-s1-placement.captured
agent_ready=/run/soglia-spike-s1-agent.ready
agent_go=/run/soglia-spike-s1-agent.go
membership_ready=/run/soglia-spike-s1-membership.ready
membership_captured=/run/soglia-spike-s1-membership.captured
bpf_object="${S1_BPF_OBJECT:-/var/tmp/spike/bpf/soglia-diag.o}"
harness=/var/tmp/spike/target/release/s1_attribution
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
execution_id="${S1_EXECUTION_ID:-s1-execution-e1-generation-1}"
candidate_c_ident="${S1_CANDIDATE_C_IDENT:-1001001}"
harness_pid=
cleanup_log="${S1_CLEANUP_LOG:-}"
trusted_teardown="${S1_TRUSTED_TEARDOWN:-false}"
cleanup_cycle=0

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence"

cleanup_step() {
    [[ -z "$cleanup_log" ]] && return
    printf 'UTC=%s cycle=%s step=%s\n' "$(date -u +%FT%TZ)" "$cleanup_cycle" "$1" >> "$cleanup_log"
}

cleanup_owned_trusted() {
    cleanup_step begin
    if [[ -e "$execution/cgroup.freeze" ]]; then
        cleanup_step freeze_prevent_new_effects
        printf '1\n' > "$execution/cgroup.freeze"
        for _ in $(seq 1 100); do
            grep -q '^frozen 1$' "$execution/cgroup.events" 2>/dev/null && break
            sleep 0.01
        done
        grep '^frozen ' "$execution/cgroup.events" 2>/dev/null | sed 's/^/observed_/' >> "$cleanup_log"
    fi
    cleanup_step kill_execution_cgroup
    if [[ -e "$execution/cgroup.kill" ]]; then
        printf '1\n' > "$execution/cgroup.kill"
        for _ in $(seq 1 100); do
            [[ ! -s "$execution/cgroup.procs" ]] && break
            sleep 0.01
        done
    fi
    cleanup_step wait_reap_process_tree
    if [[ -n "$harness_pid" ]]; then
        kill -TERM "$harness_pid" 2>/dev/null || true
        wait "$harness_pid" 2>/dev/null || true
    fi
    harness_pid=
    cleanup_step remove_runtime_state
    rm -f "$ready" "$go" "$host_ready" "$placement_ready" "$placement_captured" "$agent_ready" "$agent_go" "$membership_ready" "$membership_captured"
    cleanup_step remove_nft_state
    nft list table inet "$host_table" >/dev/null 2>&1 && nft delete table inet "$host_table"
    cleanup_step remove_veth_netns
    ip link show "$host_veth" >/dev/null 2>&1 && ip link del "$host_veth"
    ip netns list | grep -q "^$netns\b" && ip netns del "$netns"
    ip link show "$proxy_link" >/dev/null 2>&1 && ip link del "$proxy_link"
    cleanup_step remove_execution_cgroups
    [[ -d "$execution" ]] && rmdir "$execution"
    [[ -d "$executions" ]] && rmdir "$executions"
    cleanup_step remove_bpf_links_maps_pins
    for pin in sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops; do
        [[ -e "$link_pins/$pin" ]] && rm "$link_pins/$pin"
    done
    for pin in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag soglia_staging; do
        [[ -e "$map_pins/$pin" ]] && rm "$map_pins/$pin"
    done
    rmdir "$link_pins" "$map_pins" /sys/fs/bpf/soglia-spike/s1 /sys/fs/bpf/soglia-spike 2>/dev/null
    if [[ -d "$execution" || -d "$executions" ]]; then
        cleanup_step retry_execution_cgroups_after_bpf_release
        [[ -d "$execution" ]] && rmdir "$execution"
        [[ -d "$executions" ]] && rmdir "$executions"
    fi
    cleanup_step release_ownership_slot
    cleanup_step complete
}

cleanup_owned() {
    set +e
    cleanup_cycle=$((cleanup_cycle + 1))
    if [[ "$trusted_teardown" == true ]]; then
        cleanup_owned_trusted
        return
    fi
    if [[ -n "$harness_pid" ]] && kill -0 "$harness_pid" 2>/dev/null; then
        kill "$harness_pid"
        wait "$harness_pid"
    fi
    if [[ -e "$execution/cgroup.kill" ]]; then
        printf '1\n' > "$execution/cgroup.kill"
        for _ in $(seq 1 100); do
            [[ ! -s "$execution/cgroup.procs" ]] && break
            sleep 0.01
        done
    fi
    ip link show "$host_veth" >/dev/null 2>&1 && ip link del "$host_veth"
    ip netns list | grep -q "^$netns\b" && ip netns del "$netns"
    ip link show "$proxy_link" >/dev/null 2>&1 && ip link del "$proxy_link"
    nft list table inet "$host_table" >/dev/null 2>&1 && nft delete table inet "$host_table"
    for pin in sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops; do
        [[ -e "$link_pins/$pin" ]] && rm "$link_pins/$pin"
    done
    for pin in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag soglia_staging; do
        [[ -e "$map_pins/$pin" ]] && rm "$map_pins/$pin"
    done
    rmdir "$link_pins" "$map_pins" /sys/fs/bpf/soglia-spike/s1 /sys/fs/bpf/soglia-spike 2>/dev/null
    rm -f "$ready" "$go" "$host_ready" "$placement_ready" "$placement_captured" "$agent_ready" "$agent_go" "$membership_ready" "$membership_captured"
    [[ -d "$execution" ]] && rmdir "$execution"
    [[ -d "$executions" ]] && rmdir "$executions"
}

record_cleanup() {
    {
        echo "# S1 cleanup verification"
        date -u +"UTC=%FT%TZ"
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        for path in "$executions" "$execution" /sys/fs/bpf/soglia-spike; do
            if [[ -e "$path" ]]; then echo "PRESENT $path"; else echo "ABSENT $path"; fi
        done
        echo "delegated_root_children_begin"
        find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
        echo "delegated_root_children_end"
        echo "cgroup_tree_begin"
        bpftool cgroup tree "$unit"
        echo "cgroup_tree_end"
        echo "bpffs_begin"
        find /sys/fs/bpf -mindepth 1 -maxdepth 4 -print | sort
        echo "bpffs_end"
        echo "netns_begin"
        ip netns list
        echo "netns_end"
        echo "owned_links_begin"
        ip -o link show | grep -E "$host_veth|$proxy_link" || true
        echo "owned_links_end"
        echo "owned_nft_begin"
        nft list tables | grep "$host_table" || true
        echo "owned_nft_end"
        echo "soglia_foreign_program_count=$(bpftool -j prog show | jq '[.[] | select(.name | startswith("soglia_") or startswith("foreign_"))] | length')"
        echo "cgroup_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
    } > "$evidence/s1-cleanup.txt"
    bpftool -j prog show > "$evidence/s1-final-prog.json"
    bpftool -j link show > "$evidence/s1-final-link.json"
}

on_exit() {
    status=$?
    cleanup_owned
    record_cleanup
    echo "$status" > "$evidence/s1-run-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

cleanup_owned

{
    echo "# S1 fresh preflight"
    date -u +"UTC=%FT%TZ"
    uname -a
    systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID -p Delegate -p DelegateControllers -p ControlGroup -p NRestarts --no-pager
    echo "delegated_root_inode=$(stat -c %i "$unit")"
    echo "delegated_root_procs=$(tr '\n' ' ' < "$unit/cgroup.procs")"
    echo "runtime_procs=$(tr '\n' ' ' < "$unit/runtime/cgroup.procs")"
    echo "delegated_root_children_begin"
    find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
    echo "delegated_root_children_end"
    bpftool cgroup tree "$unit"
    echo "bpffs_begin"
    find /sys/fs/bpf -mindepth 1 -maxdepth 4 -print | sort
    echo "bpffs_end"
    ip netns list
    ip -o link show | grep -E 'sgh-|soglia-proxy' || true
    nft list tables | grep soglia || true
} > "$evidence/s1-preflight.txt"

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
table inet soglia_spike_s1 {
    chain input {
        type filter hook input priority filter - 10; policy accept;
        iifname "sgh-s1e1" ip saddr != 10.201.0.1 drop
        iifname "sgh-s1e1" ct state invalid drop
        iifname "sgh-s1e1" ct state new meta l4proto != tcp drop
        iifname "sgh-s1e1" ct state new ip daddr != 10.200.255.1 drop
        iifname "sgh-s1e1" ct state new tcp dport != 15001 drop
    }
    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        iifname "sgh-s1e1" drop
        oifname "sgh-s1e1" drop
    }
}
NFT

{
    echo "# S1 topology after creation"
    date -u +"UTC=%FT%TZ"
    echo "execution_id=$execution_id"
    echo "candidate_c_ident=$candidate_c_ident"
    echo "delegated_root_inode=$(stat -c %i "$unit")"
    echo "executions_inode=$(stat -c %i "$executions")"
    echo "execution_cgroup_inode=$(stat -c %i "$execution")"
    echo "execution_cgroup_procs=$(tr '\n' ' ' < "$execution/cgroup.procs")"
    ip -details addr show dev "$proxy_link"
    ip -details addr show dev "$host_veth"
    ip netns exec "$netns" ip -details addr show
    ip netns exec "$netns" ip route show
    ip netns exec "$netns" nft list ruleset
    nft list table inet "$host_table"
} > "$evidence/s1-topology.txt"

{
    echo "# S1 artifact and source provenance"
    date -u +"UTC=%FT%TZ"
    sha256sum \
        /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c \
        /soglia/spikes/cgroup-bpf/harness/src/bin/s1_attribution.rs \
        /soglia/spikes/cgroup-bpf/agent/src/main.rs \
        "$bpf_object" "$harness" "$agent"
    file "$bpf_object" "$harness" "$agent"
} > "$evidence/s1-provenance.txt"

{
    echo "# S1 destination-port source and ABI contract"
    date -u +"UTC=%FT%TZ"
    uname -m
    lscpu | grep '^Byte Order:'
    echo "linux_uapi_bpf_sock_addr_begin"
    sed -n '6644,6664p' /usr/include/linux/bpf.h
    echo "linux_uapi_bpf_sock_addr_end"
    echo "linux_uapi_bpf_sock_ops_begin"
    sed -n '6673,6692p' /usr/include/linux/bpf.h
    echo "linux_uapi_bpf_sock_ops_end"
    echo "spike_tuple_declaration_begin"
    sed -n '90,122p' /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c
    echo "spike_tuple_declaration_end"
    echo "spike_connect4_begin"
    sed -n '300,350p' /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c
    echo "spike_connect4_end"
    echo "spike_key_publish_begin"
    sed -n '420,485p' /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c
    echo "spike_key_publish_end"
    echo "resolve_key_begin"
    sed -n '720,740p' /soglia/spikes/cgroup-bpf/harness/src/bin/s1_attribution.rs
    echo "resolve_key_end"
} > "$evidence/s1-port-contract.txt"

"$harness" \
    "$bpf_object" "$execution" "$map_pins" "$link_pins" "$netns" "$agent" \
    "$execution_id" 10.201.0.1 "$candidate_c_ident" "$ready" "$go" \
    "$host_ready" "$placement_ready" "$placement_captured" \
    "$agent_ready" "$agent_go" "$membership_ready" "$membership_captured" \
    > "$evidence/s1-harness.txt" 2>&1 &
harness_pid=$!

for _ in $(seq 1 3000); do
    [[ -e "$ready" ]] && break
    kill -0 "$harness_pid" 2>/dev/null || break
    sleep 0.01
done
if [[ ! -e "$ready" ]]; then
    wait "$harness_pid"
    exit $?
fi

bpftool -j prog show > "$evidence/s1-during-prog.json"
bpftool -j link show > "$evidence/s1-during-link.json"
bpftool -j cgroup show "$execution" > "$evidence/s1-during-cgroup-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s1-during-cgroup-effective.json"
bpftool -j map show > "$evidence/s1-during-map.json"
{
    echo "# S1 live attached state"
    date -u +"UTC=%FT%TZ"
    bpftool cgroup tree "$unit"
    find /sys/fs/bpf/soglia-spike -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort
    echo "execution_cgroup_procs=$(tr '\n' ' ' < "$execution/cgroup.procs")"
} > "$evidence/s1-during-state.txt"

touch "$go"

for _ in $(seq 1 3000); do
    [[ -e "$placement_ready" ]] && break
    kill -0 "$harness_pid" 2>/dev/null || break
    sleep 0.01
done
if [[ ! -e "$placement_ready" ]]; then
    set +e
    wait "$harness_pid"
    harness_status=$?
    set -e
    echo "$harness_status" > "$evidence/s1-harness-exit-status.txt"
    harness_pid=
    exit "$harness_status"
fi

host_pid=$(sed -n 's/^pid=//p' "$placement_ready")
placement_status=$(sed -n 's/^status=//p' "$placement_ready")
expected_membership="0::${execution#/sys/fs/cgroup}"
{
    echo "# S1 trusted host PID placement before network namespace entry"
    date -u +"UTC=%FT%TZ"
    echo "trusted_host_pid=$host_pid"
    echo "harness_placement_status=$placement_status"
    echo "target_cgroup=$execution"
    echo "target_cgroup_inode=$(stat -c %i "$execution")"
    echo "baseline_cgroup_procs_was_empty=true"
    echo "expected_proc_cgroup_line=$expected_membership"
    echo "host_pid_proc_cgroup_begin"
    cat "/proc/$host_pid/cgroup"
    echo "host_pid_proc_cgroup_end"
    echo "target_cgroup_procs_begin"
    cat "$execution/cgroup.procs"
    echo "target_cgroup_procs_end"
    grep '^State:' "/proc/$host_pid/status"
    if grep -Fxq "$expected_membership" "/proc/$host_pid/cgroup"; then
        echo "proc_exact_membership=true"
    else
        echo "proc_exact_membership=false"
    fi
    if grep -Fxq "$host_pid" "$execution/cgroup.procs"; then
        echo "cgroup_procs_contains_host_pid=true"
    else
        echo "cgroup_procs_contains_host_pid=false"
    fi
    echo "host_pid_netns_link=$(readlink "/proc/$host_pid/ns/net")"
    echo "host_pid_netns_inode=$(stat -Lc %i "/proc/$host_pid/ns/net")"
    echo "owned_netns_inode=$(stat -Lc %i "/run/netns/$netns")"
} > "$evidence/s1-host-placement.txt"

touch "$placement_captured"

for _ in $(seq 1 3000); do
    [[ -e "$membership_ready" ]] && break
    kill -0 "$harness_pid" 2>/dev/null || break
    sleep 0.01
done
if [[ ! -e "$membership_ready" ]]; then
    set +e
    wait "$harness_pid"
    harness_status=$?
    set -e
    echo "$harness_status" > "$evidence/s1-harness-exit-status.txt"
    harness_pid=
    exit "$harness_status"
fi

agent_pid=$(sed -n 's/^pid=//p' "$membership_ready")
membership_status=$(sed -n 's/^status=//p' "$membership_ready")
expected_membership="0::${execution#/sys/fs/cgroup}"
{
    echo "# S1 diagnostic live agent membership before connection"
    date -u +"UTC=%FT%TZ"
    echo "trusted_host_pid=$host_pid"
    echo "actual_agent_pid=$agent_pid"
    if [[ "$host_pid" == "$agent_pid" ]]; then
        echo "actual_agent_pid_matches_placed_host_pid=true"
    else
        echo "actual_agent_pid_matches_placed_host_pid=false"
    fi
    echo "harness_membership_status=$membership_status"
    echo "target_cgroup=$execution"
    echo "target_cgroup_inode=$(stat -c %i "$execution")"
    echo "expected_proc_cgroup_line=$expected_membership"
    echo "agent_proc_cgroup_begin"
    cat "/proc/$agent_pid/cgroup"
    echo "agent_proc_cgroup_end"
    echo "target_cgroup_procs_begin"
    cat "$execution/cgroup.procs"
    echo "target_cgroup_procs_end"
    if grep -Fxq "$expected_membership" "/proc/$agent_pid/cgroup"; then
        echo "proc_exact_membership=true"
    else
        echo "proc_exact_membership=false"
    fi
    if grep -Fxq "$agent_pid" "$execution/cgroup.procs"; then
        echo "cgroup_procs_contains_agent=true"
    else
        echo "cgroup_procs_contains_agent=false"
    fi
    echo "agent_netns_link=$(readlink "/proc/$agent_pid/ns/net")"
    echo "agent_netns_inode=$(stat -Lc %i "/proc/$agent_pid/ns/net")"
    echo "owned_netns_inode=$(stat -Lc %i "/run/netns/$netns")"
} > "$evidence/s1-membership.txt"

bpftool -j prog show > "$evidence/s1-before-connection-prog.json"
bpftool -j link show > "$evidence/s1-before-connection-link.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s1-before-connection-effective.json"
bpftool -j map show > "$evidence/s1-before-connection-map.json"
bpftool -j map dump pinned "$map_pins/soglia_diag_entries" > "$evidence/s1-before-connection-diag.json"
bpftool -j map dump pinned "$map_pins/soglia_port_diag" > "$evidence/s1-before-connection-port-diag.json"
bpftool -j map dump pinned "$map_pins/soglia_counters" > "$evidence/s1-before-connection-counters.json"
bpftool -j map dump pinned "$map_pins/soglia_cookie_a" > "$evidence/s1-before-connection-cookie.json"
bpftool -j map dump pinned "$map_pins/soglia_tuples" > "$evidence/s1-before-connection-tuples.json"
bpftool -j map dump pinned "$map_pins/soglia_denies" > "$evidence/s1-before-connection-denies.json"
if [[ -e "$map_pins/soglia_staging" ]]; then
    bpftool -j map dump pinned "$map_pins/soglia_staging" > "$evidence/s1-before-connection-staging.json"
fi

touch "$membership_captured"
if [[ "$membership_status" == CORRECT ]]; then
    touch "$agent_go"
fi

set +e
wait "$harness_pid"
harness_status=$?
set -e
harness_pid=
echo "$harness_status" > "$evidence/s1-harness-exit-status.txt"
[[ "$harness_status" -eq 0 ]]
