#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Characterizes cgroup-BPF pinned-link and map survival after abrupt loader loss.

set -euo pipefail

evidence="${S7_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s7}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
execution="$executions/s7-e1"
netns=soglia-s7-e1
host_veth=sgh-s7e1
host_table=soglia_spike_s7
map_pins=/sys/fs/bpf/soglia-spike/s7/maps
link_pins=/sys/fs/bpf/soglia-spike/s7/links
object=/var/tmp/spike/bpf/soglia-diag.o
loader=/var/tmp/spike/target/release/s7_pinned_loader
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
loader_ready=/run/soglia-spike-s7-loader.ready
loader_pid=
target_pid=
listener_pid=

cleanup_owned() {
    set +e
    if [[ -n "$target_pid" ]] && kill -0 "$target_pid" 2>/dev/null; then kill "$target_pid"; wait "$target_pid"; fi
    if [[ -n "$listener_pid" ]] && kill -0 "$listener_pid" 2>/dev/null; then kill "$listener_pid"; wait "$listener_pid"; fi
    if [[ -n "$loader_pid" ]] && kill -0 "$loader_pid" 2>/dev/null; then kill -KILL "$loader_pid"; wait "$loader_pid"; fi
    if [[ -e "$execution/cgroup.kill" ]]; then
        printf '1\n' > "$execution/cgroup.kill"
        for _ in $(seq 1 100); do
            [[ ! -s "$execution/cgroup.procs" ]] && break
            sleep 0.01
        done
    fi
    ip link show "$host_veth" >/dev/null 2>&1 && ip link del "$host_veth"
    ip netns list | grep -q "^$netns\b" && ip netns del "$netns"
    nft list table inet "$host_table" >/dev/null 2>&1 && nft delete table inet "$host_table"
    for pin in sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops; do
        [[ -e "$link_pins/$pin" ]] && rm "$link_pins/$pin"
    done
    for pin in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag soglia_staging; do
        [[ -e "$map_pins/$pin" ]] && rm "$map_pins/$pin"
    done
    rmdir "$link_pins" "$map_pins" /sys/fs/bpf/soglia-spike/s7 /sys/fs/bpf/soglia-spike 2>/dev/null
    rm -f "$loader_ready" /run/soglia-spike-s7-*.ready /run/soglia-spike-s7-*.go /run/soglia-spike-s7-*.host
    [[ -d "$execution" ]] && rmdir "$execution"
    [[ -d "$executions" ]] && rmdir "$executions"
}

record_cleanup() {
    {
        echo "# S7 final cleanup verification"
        date -u +"UTC=%FT%TZ"
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        for path in "$executions" "$execution" /sys/fs/bpf/soglia-spike "/run/netns/$netns"; do
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
        ip -o link show | grep "$host_veth" || true
        nft list tables | grep "$host_table" || true
        echo "soglia_foreign_program_count=$(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_") or startswith("foreign_"))] | length')"
        echo "cgroup_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
    } > "$evidence/s7-cleanup.txt"
    bpftool -j prog show > "$evidence/s7-final-prog.json"
    bpftool -j link show > "$evidence/s7-final-link.json"
    bpftool -j map show > "$evidence/s7-final-map.json"
}

on_exit() {
    status=$?
    cleanup_owned
    record_cleanup
    echo "$status" > "$evidence/s7-run-exit-status.txt"
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
    echo "# S7 fresh preflight"
    date -u +"UTC=%FT%TZ"
    uname -a
    systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID -p Delegate -p DelegateControllers -p ControlGroup -p NRestarts --no-pager
    echo "delegated_root_inode=$(stat -c %i "$unit")"
    find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
    bpftool cgroup tree "$unit"
    find /sys/fs/bpf -mindepth 1 -maxdepth 5 -print | sort
    ip netns list
    nft list tables | grep soglia || true
} > "$evidence/s7-preflight.txt"
bpftool -j prog show > "$evidence/s7-baseline-prog.json"
bpftool -j link show > "$evidence/s7-baseline-link.json"
bpftool -j map show > "$evidence/s7-baseline-map.json"
find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s7-baseline-bpffs.txt"

mkdir "$executions"
printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
mkdir "$execution"
ip netns add "$netns"
ip link add "$host_veth" type veth peer name eth0 netns "$netns"
ip addr add 10.201.0.2/30 dev "$host_veth"
ip link set "$host_veth" up
ip netns exec "$netns" ip link set lo up
ip netns exec "$netns" ip addr add 10.201.0.1/30 dev eth0
ip netns exec "$netns" ip link set eth0 up

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
        ip daddr 10.201.0.2 tcp dport 16001 ct state new accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
NFT

nft -f - <<'NFT'
table inet soglia_spike_s7 {
    chain input {
        type filter hook input priority filter - 10; policy accept;
        iifname "sgh-s7e1" ip saddr != 10.201.0.1 drop
        iifname "sgh-s7e1" ct state invalid drop
        iifname "sgh-s7e1" ct state new meta l4proto != tcp drop
    }
    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        iifname "sgh-s7e1" drop
        oifname "sgh-s7e1" drop
    }
}
NFT

{
    echo "# S7 topology"
    date -u +"UTC=%FT%TZ"
    echo "execution_cgroup=$execution"
    echo "execution_cgroup_inode=$(stat -c %i "$execution")"
    echo "owned_netns_inode=$(stat -Lc %i "/run/netns/$netns")"
    echo "direct_path_exposed_by_nft=true"
    ip -details addr show dev "$host_veth"
    ip netns exec "$netns" ip -details addr show
    ip netns exec "$netns" nft -a list ruleset
    nft -a list table inet "$host_table"
} > "$evidence/s7-topology.txt"

{
    echo "# S7 artifact provenance"
    date -u +"UTC=%FT%TZ"
    sha256sum \
        /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c \
        /soglia/spikes/cgroup-bpf/harness/src/bin/s7_pinned_loader.rs \
        /soglia/spikes/cgroup-bpf/agent/src/main.rs \
        "$object" "$loader" "$agent"
    file "$object" "$loader" "$agent"
} > "$evidence/s7-provenance.txt"

"$loader" "$object" "$execution" "$map_pins" "$link_pins" "$loader_ready" \
    > "$evidence/s7-loader.txt" 2>&1 &
loader_pid=$!
for _ in $(seq 1 3000); do
    [[ -e "$loader_ready" ]] && break
    kill -0 "$loader_pid" 2>/dev/null || break
    sleep 0.01
done
[[ -e "$loader_ready" ]]
announced_loader_pid=$(tr -d '\n' < "$loader_ready")
[[ "$announced_loader_pid" == "$loader_pid" ]]

bpftool -j prog show > "$evidence/s7-before-loss-prog.json"
bpftool -j link show > "$evidence/s7-before-loss-link.json"
bpftool -j map show > "$evidence/s7-before-loss-map.json"
bpftool -j cgroup show "$execution" > "$evidence/s7-before-loss-cgroup-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s7-before-loss-cgroup-effective.json"
find /sys/fs/bpf/soglia-spike/s7 -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s7-before-loss-bpffs.txt"

kill -KILL "$loader_pid"
set +e
wait "$loader_pid"
loader_status=$?
set -e
echo "$loader_status" > "$evidence/s7-loader-exit-status.txt"
[[ "$loader_status" -eq 137 ]]
if [[ -e "/proc/$loader_pid" ]]; then loader_absent=false; else loader_absent=true; fi

bpftool -j prog show > "$evidence/s7-after-loss-prog.json"
bpftool -j link show > "$evidence/s7-after-loss-link.json"
bpftool -j map show > "$evidence/s7-after-loss-map.json"
bpftool -j cgroup show "$execution" > "$evidence/s7-after-loss-cgroup-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s7-after-loss-cgroup-effective.json"
find /sys/fs/bpf/soglia-spike/s7 -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s7-after-loss-bpffs.txt"

before_ids=$(jq -c 'map({id,name,attach_type}) | sort_by(.id)' "$evidence/s7-before-loss-cgroup-direct.json")
after_ids=$(jq -c 'map({id,name,attach_type}) | sort_by(.id)' "$evidence/s7-after-loss-cgroup-direct.json")
before_bpffs=$(sed 's#^.[[:space:]]##' "$evidence/s7-before-loss-bpffs.txt")
after_bpffs=$(sed 's#^.[[:space:]]##' "$evidence/s7-after-loss-bpffs.txt")
link_pin_count=$(find "$link_pins" -mindepth 1 -maxdepth 1 -type f | wc -l)
map_pin_count=$(find "$map_pins" -mindepth 1 -maxdepth 1 -type f | wc -l)
{
    echo "loader_pid=$loader_pid"
    echo "loader_signal=SIGKILL"
    echo "loader_exit_status=$loader_status"
    echo "loader_proc_absent=$loader_absent"
    echo "before_cgroup_programs=$before_ids"
    echo "after_cgroup_programs=$after_ids"
    echo "cgroup_program_identity_preserved=$([[ "$before_ids" == "$after_ids" ]] && echo true || echo false)"
    echo "bpffs_pin_set_preserved=$([[ "$before_bpffs" == "$after_bpffs" ]] && echo true || echo false)"
    echo "link_pin_count=$link_pin_count"
    echo "link_pins_preserved=$([[ "$link_pin_count" -eq 6 ]] && echo true || echo false)"
    echo "map_pin_count=$map_pin_count"
    echo "map_pins_preserved=$([[ "$map_pin_count" -eq 10 ]] && echo true || echo false)"
} > "$evidence/s7-loader-loss.txt"
[[ "$before_ids" == "$after_ids" ]]
[[ "$before_bpffs" == "$after_bpffs" ]]
[[ "$link_pin_count" -eq 6 ]]
[[ "$map_pin_count" -eq 10 ]]
[[ "$loader_absent" == true ]]

run_direct_attempt() {
    local label="$1" expected_agent_ok="$2" expected_listener_ok="$3"
    local host_ready="/run/soglia-spike-s7-$label.host"
    local agent_ready="/run/soglia-spike-s7-$label.ready"
    local agent_go="/run/soglia-spike-s7-$label.go"
    "$agent" "listen4-once 10.201.0.2:16001 2500" > "$evidence/s7-$label-listener.txt" 2>&1 &
    listener_pid=$!
    bash -c 'set -euo pipefail; printf "%s\n" "$$" > "$1"; kill -STOP "$$"; exec ip netns exec "$2" "$3" "barrier $4 $5 15" "direct 10.201.0.2:16001"' \
        s7-launcher "$host_ready" "$netns" "$agent" "$agent_ready" "$agent_go" \
        > "$evidence/s7-$label-agent.txt" 2>&1 &
    target_pid=$!
    for _ in $(seq 1 500); do [[ -e "$host_ready" ]] && break; sleep 0.01; done
    [[ -e "$host_ready" ]]
    printf '%s\n' "$target_pid" > "$execution/cgroup.procs"
    kill -CONT "$target_pid"
    for _ in $(seq 1 500); do [[ -e "$agent_ready" ]] && break; sleep 0.01; done
    [[ -e "$agent_ready" ]]
    actual_pid=$(tr -d '\n' < "$agent_ready")
    expected_line="0::${execution#/sys/fs/cgroup}"
    {
        echo "label=$label"
        echo "trusted_pid=$target_pid"
        echo "actual_agent_pid=$actual_pid"
        echo "target_cgroup_inode=$(stat -c %i "$execution")"
        echo "expected_proc_cgroup=$expected_line"
        cat "/proc/$actual_pid/cgroup"
        echo "target_cgroup_procs=$(tr '\n' ' ' < "$execution/cgroup.procs")"
        echo "agent_netns_inode=$(stat -Lc %i "/proc/$actual_pid/ns/net")"
        echo "owned_netns_inode=$(stat -Lc %i "/run/netns/$netns")"
    } > "$evidence/s7-$label-membership.txt"
    [[ "$actual_pid" == "$target_pid" ]]
    grep -Fxq "$expected_line" "/proc/$actual_pid/cgroup"
    grep -Fxq "$actual_pid" "$execution/cgroup.procs"
    [[ $(stat -Lc %i "/proc/$actual_pid/ns/net") -eq $(stat -Lc %i "/run/netns/$netns") ]]
    touch "$agent_go"
    wait "$target_pid"
    target_pid=
    wait "$listener_pid"
    listener_pid=
    grep -q "\"cmd\":\"direct 10.201.0.2:16001\",\"ok\":$expected_agent_ok" "$evidence/s7-$label-agent.txt"
    grep -q "\"cmd\":\"listen4-once 10.201.0.2:16001 2500\",\"ok\":$expected_listener_ok" "$evidence/s7-$label-listener.txt"
}

run_direct_attempt after-loader-loss false false
bpftool -j map dump pinned "$map_pins/soglia_diag_entries" > "$evidence/s7-after-deny-diag.json"
bpftool -j map dump pinned "$map_pins/soglia_counters" > "$evidence/s7-after-deny-counters.json"
bpftool -j map dump pinned "$map_pins/soglia_denies" > "$evidence/s7-after-deny-denies.json"
[[ $(jq '[.[] | select(.formatted.key == 1 and .formatted.value == 1)] | length' "$evidence/s7-after-deny-diag.json") -eq 1 ]]
[[ $(jq '[.[] | select(.formatted.key == 4 and .formatted.value == 1)] | length' "$evidence/s7-after-deny-counters.json") -eq 1 ]]
[[ $(jq 'length' "$evidence/s7-after-deny-denies.json") -eq 1 ]]

rm "$link_pins/connect4"
bpftool -j cgroup show "$execution" > "$evidence/s7-after-connect4-unpin-cgroup-direct.json"
bpftool -j link show > "$evidence/s7-after-connect4-unpin-link.json"
[[ $(jq 'length' "$evidence/s7-after-connect4-unpin-cgroup-direct.json") -eq 5 ]]
[[ $(jq '[.[] | select(.name == "soglia_connect4")] | length' "$evidence/s7-after-connect4-unpin-cgroup-direct.json") -eq 0 ]]
run_direct_attempt after-connect4-unpin true true

{
    echo "# S7 result"
    date -u +"UTC=%FT%TZ"
    echo "loader_loss=SIGKILL status 137 and /proc PID absent"
    echo "pinned_link_identity_preserved=true"
    echo "pinned_maps_preserved=true"
    echo "kernel_connect4_deny_after_loader_loss=true"
    echo "direct_listener_accept_after_loader_loss=false"
    echo "connect4_unpin_detached_only_connect4=true"
    echo "direct_path_after_connect4_unpin=established"
    echo "lost_userspace_functionality=loader no longer owns FDs, consumes ring events, manages policy, or performs automatic unpin/cleanup"
    echo "retained_kernel_functionality=pinned programs execute and pinned maps retain/update state"
    echo "S7_RESULT=PASS"
} > "$evidence/s7-summary.txt"
