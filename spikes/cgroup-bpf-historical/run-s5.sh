#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Isolates the contribution of every cgroup-BPF hook used by the Phase-1 spike.

set -euo pipefail

evidence="${S5_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s5}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
execution="$executions/s5-e1"
netns=soglia-s5-e1
host_veth=sgh-s5e1
proxy_link=soglia-proxy0
host_table=soglia_spike_s5
map_pins=/sys/fs/bpf/soglia-spike/s5/maps
link_pins=/sys/fs/bpf/soglia-spike/s5/links
diag_object=/var/tmp/spike/bpf/soglia-diag.o
inet6_object=/var/tmp/spike/bpf/soglia-relax-inet6-diag.o
dgram_object=/var/tmp/spike/bpf/soglia-relax-dgram-diag.o
harness=/var/tmp/spike/target/release/s5_hook_isolation
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
harness_pid=
phases=(
    sock-create-inet6-deny sock-create-inet6-control
    connect6-deny connect6-omitted-control
    sendmsg4-deny sendmsg4-omitted-control
    sendmsg6-deny sendmsg6-omitted-control
    connect4-deny connect4-omitted-control
    sockops-present-control sockops-omitted
)

cleanup_owned() {
    set +e
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
    for phase in "${phases[@]}"; do
        for pin in sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops; do
            [[ -e "$link_pins/$phase/$pin" ]] && rm "$link_pins/$phase/$pin"
        done
        for pin in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag soglia_staging; do
            [[ -e "$map_pins/$phase/$pin" ]] && rm "$map_pins/$phase/$pin"
        done
        rmdir "$link_pins/$phase" "$map_pins/$phase" 2>/dev/null
        rm -f "/run/soglia-spike-s5-$phase-host.ready" \
            "/run/soglia-spike-s5-$phase-agent.ready" \
            "/run/soglia-spike-s5-$phase-agent.go"
    done
    rmdir "$link_pins" "$map_pins" /sys/fs/bpf/soglia-spike/s5 /sys/fs/bpf/soglia-spike 2>/dev/null
    [[ -d "$execution" ]] && rmdir "$execution"
    [[ -d "$executions" ]] && rmdir "$executions"
}

record_cleanup() {
    {
        echo "# S5 final cleanup verification"
        date -u +"UTC=%FT%TZ"
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        for path in "$executions" "$execution" /sys/fs/bpf/soglia-spike "/run/netns/$netns"; do
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
        ip -o link show | grep -E "$host_veth|$proxy_link" || true
        echo "owned_links_end"
        echo "owned_nft_begin"
        nft list tables | grep "$host_table" || true
        echo "owned_nft_end"
        echo "soglia_foreign_program_count=$(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_") or startswith("foreign_"))] | length')"
        echo "cgroup_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
    } > "$evidence/s5-cleanup.txt"
    bpftool -j prog show > "$evidence/s5-final-prog.json"
    bpftool -j link show > "$evidence/s5-final-link.json"
    bpftool -j map show > "$evidence/s5-final-map.json"
}

on_exit() {
    status=$?
    cleanup_owned
    record_cleanup
    echo "$status" > "$evidence/s5-run-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence"
cleanup_owned

{
    echo "# S5 fresh preflight"
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
} > "$evidence/s5-preflight.txt"
bpftool -j prog show > "$evidence/s5-baseline-prog.json"
bpftool -j link show > "$evidence/s5-baseline-link.json"
bpftool -j map show > "$evidence/s5-baseline-map.json"
find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s5-baseline-bpffs.txt"

mkdir "$executions"
printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
mkdir "$execution"

ip link add "$proxy_link" type dummy
ip addr add 10.200.255.1/32 dev "$proxy_link"
ip link set "$proxy_link" up
ip netns add "$netns"
ip link add "$host_veth" type veth peer name eth0 netns "$netns"
ip addr add 10.201.0.2/30 dev "$host_veth"
ip -6 addr add fd00:201::2/64 dev "$host_veth" nodad
ip link set "$host_veth" up
ip netns exec "$netns" ip link set lo up
ip netns exec "$netns" ip addr add 10.201.0.1/30 dev eth0
ip netns exec "$netns" ip -6 addr add fd00:201::1/64 dev eth0 nodad
ip netns exec "$netns" ip link set eth0 up
ip netns exec "$netns" ip route add 10.200.255.1/32 via 10.201.0.2 dev eth0

ip netns exec "$netns" nft -f - <<'NFT'
table inet soglia {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        meta l4proto ipv6-icmp accept
    }
    chain output {
        type filter hook output priority filter; policy drop;
        oif "lo" accept
        ct state established,related accept
        meta l4proto ipv6-icmp accept
        ip daddr 10.200.255.1 tcp dport 15001 ct state new accept
        ip daddr 10.201.0.2 tcp dport 16001 ct state new accept
        ip6 daddr fd00:201::2 tcp dport 16002 ct state new accept
        ip daddr 10.201.0.2 udp dport 16003 accept
        ip6 daddr fd00:201::2 udp dport 16004 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
NFT

nft -f - <<'NFT'
table inet soglia_spike_s5 {
    chain input {
        type filter hook input priority filter - 10; policy accept;
        iifname "sgh-s5e1" ip saddr != 10.201.0.1 drop
        iifname "sgh-s5e1" ip6 saddr != fd00:201::1 drop
        iifname "sgh-s5e1" ct state invalid drop
    }
    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        iifname "sgh-s5e1" drop
        oifname "sgh-s5e1" drop
    }
}
NFT

{
    echo "# S5 controlled topology"
    date -u +"UTC=%FT%TZ"
    echo "execution_id=s5-execution-generation-1"
    echo "execution_cgroup=$execution"
    echo "execution_cgroup_inode=$(stat -c %i "$execution")"
    echo "execution_cgroup_procs=$(tr '\n' ' ' < "$execution/cgroup.procs")"
    echo "owned_netns=$netns"
    echo "owned_netns_inode=$(stat -Lc %i "/run/netns/$netns")"
    ip -details addr show dev "$proxy_link"
    ip -details addr show dev "$host_veth"
    ip netns exec "$netns" ip -details addr show
    ip netns exec "$netns" ip route show
    ip netns exec "$netns" ip -6 route show
    echo "namespace_nft_begin"
    ip netns exec "$netns" nft -a list ruleset
    echo "namespace_nft_end"
    echo "host_nft_begin"
    nft -a list table inet "$host_table"
    echo "host_nft_end"
} > "$evidence/s5-topology.txt"

{
    echo "# S5 artifact provenance"
    date -u +"UTC=%FT%TZ"
    sha256sum \
        /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c \
        /soglia/spikes/cgroup-bpf/harness/src/bin/s5_hook_isolation.rs \
        /soglia/spikes/cgroup-bpf/agent/src/main.rs \
        "$diag_object" "$inet6_object" "$dgram_object" "$harness" "$agent"
    file "$diag_object" "$inet6_object" "$dgram_object" "$harness" "$agent"
} > "$evidence/s5-provenance.txt"

"$harness" \
    "$diag_object" "$inet6_object" "$dgram_object" "$execution" \
    "$map_pins" "$link_pins" "$netns" "$agent" 5001001 \
    > "$evidence/s5-harness.txt" 2>&1 &
harness_pid=$!
set +e
wait "$harness_pid"
harness_status=$?
set -e
harness_pid=
echo "$harness_status" > "$evidence/s5-harness-exit-status.txt"
[[ "$harness_status" -eq 0 ]]

{
    echo "# S5 isolated hook contribution summary"
    date -u +"UTC=%FT%TZ"
    echo "sock_create=default denied IPv6 stream creation; relaxed creation succeeded"
    echo "connect6=with sock_create relaxed, hook denied and listener saw nothing; omitting only connect6 established"
    echo "sendmsg4=with datagram creation relaxed, hook denied and listener saw nothing; omitting only sendmsg4 delivered"
    echo "sendmsg6=with datagram creation relaxed, hook denied and listener saw nothing; omitting only sendmsg6 delivered"
    echo "connect4=hook denied direct IPv4 and listener saw nothing; omitting only connect4 established"
    echo "sockops=present published and resolved; omission still established to proxy but published no tuple, timed out fail-closed, and left connect4 cookie state until map cleanup"
    echo "ip_fallback_authorization=false"
    echo "production_code_modified=false"
    echo "candidate_selected=false"
    echo "S5_RESULT=PASS"
} > "$evidence/s5-summary.txt"
