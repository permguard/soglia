#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Creates four disposable concurrent Executions for S2, captures trusted membership and kernel
# state, runs the cross-attribution harness, and verifies complete cleanup.

set -euo pipefail

evidence="${S2_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s2/run1}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
map_pins=/sys/fs/bpf/soglia-spike/s2/maps
link_pins=/sys/fs/bpf/soglia-spike/s2/links
proxy_link=soglia-proxy0
host_table=soglia_spike_s2
bpf_object=/var/tmp/spike/bpf/soglia-delay-diag.o
harness=/var/tmp/spike/target/release/s2_concurrency
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
ready=/run/soglia-spike-s2.ready
go=/run/soglia-spike-s2.go
membership_ready=/run/soglia-spike-s2-membership.ready
membership_captured=/run/soglia-spike-s2-membership.captured
harness_pid=

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence"

cleanup_owned() {
    set +e
    if [[ -n "$harness_pid" ]] && kill -0 "$harness_pid" 2>/dev/null; then
        kill "$harness_pid"
        wait "$harness_pid"
    fi
    for index in 0 1 2 3; do
        cgroup="$executions/s2-e$index"
        if [[ -e "$cgroup/cgroup.kill" ]]; then
            printf '1\n' > "$cgroup/cgroup.kill"
        fi
    done
    for index in 0 1 2 3; do
        ip link show "sgh-s2e$index" >/dev/null 2>&1 && ip link del "sgh-s2e$index"
        ip netns list | grep -q "^soglia-s2-e$index\b" && ip netns del "soglia-s2-e$index"
    done
    ip link show "$proxy_link" >/dev/null 2>&1 && ip link del "$proxy_link"
    nft list table inet "$host_table" >/dev/null 2>&1 && nft delete table inet "$host_table"
    for index in 0 1 2 3; do
        for pin in sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops; do
            [[ -e "$link_pins/e$index/$pin" ]] && rm "$link_pins/e$index/$pin"
        done
        rmdir "$link_pins/e$index" 2>/dev/null
    done
    for pin in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag soglia_staging; do
        [[ -e "$map_pins/$pin" ]] && rm "$map_pins/$pin"
    done
    rmdir "$link_pins" "$map_pins" /sys/fs/bpf/soglia-spike/s2 /sys/fs/bpf/soglia-spike 2>/dev/null
    rm -f "$ready" "$go" "$membership_ready" "$membership_captured"
    for index in 0 1 2 3; do
        rm -f "/run/soglia-spike-s2-e$index-host.ready" "/run/soglia-spike-s2-e$index-agent.ready" "/run/soglia-spike-s2-e$index-agent.go"
        [[ -d "$executions/s2-e$index" ]] && rmdir "$executions/s2-e$index"
    done
    [[ -d "$executions" ]] && rmdir "$executions"
}

record_cleanup() {
    {
        echo "# S2 cleanup verification"
        date -u +"UTC=%FT%TZ"
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        for path in "$executions" /sys/fs/bpf/soglia-spike; do
            if [[ -e "$path" ]]; then echo "PRESENT $path"; else echo "ABSENT $path"; fi
        done
        for index in 0 1 2 3; do
            path="$executions/s2-e$index"
            if [[ -e "$path" ]]; then echo "PRESENT $path"; else echo "ABSENT $path"; fi
        done
        echo "delegated_root_children_begin"
        find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
        echo "delegated_root_children_end"
        echo "cgroup_tree_begin"
        bpftool cgroup tree "$unit"
        echo "cgroup_tree_end"
        echo "bpffs_begin"
        find /sys/fs/bpf -mindepth 1 -maxdepth 5 -print | sort
        echo "bpffs_end"
        echo "netns_begin"
        ip netns list
        echo "netns_end"
        echo "owned_links_begin"
        ip -o link show | grep -E 'sgh-s2e|soglia-proxy' || true
        echo "owned_links_end"
        echo "owned_nft_begin"
        nft list tables | grep "$host_table" || true
        echo "owned_nft_end"
        echo "soglia_foreign_program_count=$(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_") or startswith("foreign_"))] | length')"
        echo "cgroup_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
    } > "$evidence/s2-cleanup.txt"
    bpftool -j prog show > "$evidence/s2-final-prog.json"
    bpftool -j link show > "$evidence/s2-final-link.json"
}

on_exit() {
    status=$?
    cleanup_owned
    record_cleanup
    echo "$status" > "$evidence/s2-run-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

cleanup_owned

{
    echo "# S2 fresh preflight"
    date -u +"UTC=%FT%TZ"
    uname -a
    systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID -p Delegate -p DelegateControllers -p ControlGroup -p NRestarts --no-pager
    echo "delegated_root_inode=$(stat -c %i "$unit")"
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
} > "$evidence/s2-preflight.txt"

mkdir "$executions"
printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
for index in 0 1 2 3; do
    mkdir "$executions/s2-e$index"
done

ip link add "$proxy_link" type dummy
ip addr add 10.200.255.1/32 dev "$proxy_link"
ip link set "$proxy_link" up

for index in 0 1 2 3; do
    network=$((index * 4))
    agent_octet=$((network + 1))
    host_octet=$((network + 2))
    netns="soglia-s2-e$index"
    veth="sgh-s2e$index"
    ip netns add "$netns"
    ip link add "$veth" type veth peer name eth0 netns "$netns"
    ip addr add "10.201.0.$host_octet/30" dev "$veth"
    ip link set "$veth" up
    ip netns exec "$netns" ip link set lo up
    ip netns exec "$netns" ip addr add "10.201.0.$agent_octet/30" dev eth0
    ip netns exec "$netns" ip link set eth0 up
    ip netns exec "$netns" ip route add 10.200.255.1/32 via "10.201.0.$host_octet" dev eth0
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
done

nft -f - <<'NFT'
table inet soglia_spike_s2 {
    chain input {
        type filter hook input priority filter - 10; policy accept;
        iifname "sgh-s2e0" ip saddr != 10.201.0.1 drop
        iifname "sgh-s2e1" ip saddr != 10.201.0.5 drop
        iifname "sgh-s2e2" ip saddr != 10.201.0.9 drop
        iifname "sgh-s2e3" ip saddr != 10.201.0.13 drop
        iifname { "sgh-s2e0", "sgh-s2e1", "sgh-s2e2", "sgh-s2e3" } ct state invalid drop
        iifname { "sgh-s2e0", "sgh-s2e1", "sgh-s2e2", "sgh-s2e3" } ct state new meta l4proto != tcp drop
        iifname { "sgh-s2e0", "sgh-s2e1", "sgh-s2e2", "sgh-s2e3" } ct state new ip daddr != 10.200.255.1 drop
        iifname { "sgh-s2e0", "sgh-s2e1", "sgh-s2e2", "sgh-s2e3" } ct state new tcp dport != 15001 drop
    }
    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        iifname { "sgh-s2e0", "sgh-s2e1", "sgh-s2e2", "sgh-s2e3" } drop
        oifname { "sgh-s2e0", "sgh-s2e1", "sgh-s2e2", "sgh-s2e3" } drop
    }
}
NFT

{
    echo "# S2 topology"
    date -u +"UTC=%FT%TZ"
    echo "executions_inode=$(stat -c %i "$executions")"
    for index in 0 1 2 3; do
        network=$((index * 4))
        echo "execution index=$index id=s2-execution-e$index-generation-1 cgroup=$executions/s2-e$index inode=$(stat -c %i "$executions/s2-e$index") ip=10.201.0.$((network + 1)) netns=soglia-s2-e$index ident=$((2001001 + index))"
        ip netns exec "soglia-s2-e$index" ip -details addr show
        ip netns exec "soglia-s2-e$index" ip route show
        ip netns exec "soglia-s2-e$index" nft list ruleset
    done
    nft list table inet "$host_table"
} > "$evidence/s2-topology.txt"

{
    echo "# S2 artifact provenance"
    date -u +"UTC=%FT%TZ"
    sha256sum \
        /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c \
        /soglia/spikes/cgroup-bpf/harness/src/bin/s2_concurrency.rs \
        /soglia/spikes/cgroup-bpf/agent/src/main.rs \
        "$bpf_object" "$harness" "$agent"
    file "$bpf_object" "$harness" "$agent"
} > "$evidence/s2-provenance.txt"

"$harness" \
    "$bpf_object" "$executions" "$map_pins" "$link_pins" "$agent" \
    "$ready" "$go" "$membership_ready" "$membership_captured" \
    > "$evidence/s2-harness.txt" 2>&1 &
harness_pid=$!

for _ in $(seq 1 3000); do
    [[ -e "$ready" ]] && break
    kill -0 "$harness_pid" 2>/dev/null || break
    sleep 0.01
done
if [[ ! -e "$ready" ]]; then
    set +e
    wait "$harness_pid"
    harness_status=$?
    set -e
    echo "$harness_status" > "$evidence/s2-harness-exit-status.txt"
    harness_pid=
    exit "$harness_status"
fi

bpftool -j prog show > "$evidence/s2-during-prog.json"
bpftool -j link show > "$evidence/s2-during-link.json"
bpftool -j map show > "$evidence/s2-during-map.json"
for index in 0 1 2 3; do
    bpftool -j cgroup show "$executions/s2-e$index" > "$evidence/s2-e$index-cgroup-direct.json"
    bpftool -j cgroup show "$executions/s2-e$index" effective > "$evidence/s2-e$index-cgroup-effective.json"
done
{
    echo "# S2 attached state before agent launch"
    date -u +"UTC=%FT%TZ"
    bpftool cgroup tree "$unit"
    find /sys/fs/bpf/soglia-spike -mindepth 1 -maxdepth 6 -printf '%y %p\n' | sort
} > "$evidence/s2-during-state.txt"

touch "$go"

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
    echo "$harness_status" > "$evidence/s2-harness-exit-status.txt"
    harness_pid=
    exit "$harness_status"
fi

{
    echo "# S2 independent live membership proof before traffic"
    date -u +"UTC=%FT%TZ"
    while read -r line; do
        echo "$line"
        index=$(sed -n 's/.*index=\([0-9]*\).*/\1/p' <<< "$line")
        pid=$(sed -n 's/.*agent_pid=\([0-9]*\).*/\1/p' <<< "$line")
        cgroup="$executions/s2-e$index"
        echo "e${index}_proc_cgroup_begin"
        cat "/proc/$pid/cgroup"
        echo "e${index}_proc_cgroup_end"
        echo "e${index}_cgroup_procs_begin"
        cat "$cgroup/cgroup.procs"
        echo "e${index}_cgroup_procs_end"
        echo "e${index}_cgroup_inode=$(stat -c %i "$cgroup")"
        echo "e${index}_agent_netns_inode=$(stat -Lc %i "/proc/$pid/ns/net")"
        echo "e${index}_owned_netns_inode=$(stat -Lc %i "/run/netns/soglia-s2-e$index")"
    done < "$membership_ready"
} > "$evidence/s2-membership.txt"

for index in 0 1 2 3; do
    bpftool -j cgroup show "$executions/s2-e$index" effective > "$evidence/s2-e$index-before-traffic-effective.json"
done
bpftool -j map dump pinned "$map_pins/soglia_diag_entries" > "$evidence/s2-before-traffic-diag.json"
bpftool -j map dump pinned "$map_pins/soglia_counters" > "$evidence/s2-before-traffic-counters.json"
bpftool -j map dump pinned "$map_pins/soglia_cookie_a" > "$evidence/s2-before-traffic-cookie.json"
bpftool -j map dump pinned "$map_pins/soglia_tuples" > "$evidence/s2-before-traffic-tuples.json"
bpftool -j map dump pinned "$map_pins/soglia_staging" > "$evidence/s2-before-traffic-staging.json"
bpftool -j map dump pinned "$map_pins/soglia_denies" > "$evidence/s2-before-traffic-denies.json"

touch "$membership_captured"

set +e
wait "$harness_pid"
harness_status=$?
set -e
harness_pid=
echo "$harness_status" > "$evidence/s2-harness-exit-status.txt"
[[ "$harness_status" -eq 0 ]]
