#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
# shellcheck source=spikes/cgroup-bpf/runner/scripts/systemd-cgroup-common.sh
source "$scripts/systemd-cgroup-common.sh"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 EVIDENCE_DIR" >&2
    exit 64
fi
if [[ $EUID -ne 0 ]]; then
    echo "b6-kernel-released-target: root is required" >&2
    exit 77
fi

evidence=$1
loader=/var/tmp/soglia-spike-2/bin/b1-attach-diag
object=/var/tmp/soglia-b6-kernel-released-target.o
source=/soglia/crates/soglia-enforcer/bpf/candidate_a.c
cgroup_root=/sys/fs/cgroup/soglia-b6-kernel-released-target
pin_root=/sys/fs/bpf/soglia-b6-kernel-released-target
scratch=/var/tmp/soglia-b6-kernel-released-target
unit=soglia-b6-kernel-released-target.service
loader_pid=
readonly DETACH_WAIT_TIMEOUT_MS=5000
readonly DETACH_POLL_INTERVAL_MS=10

mkdir -p "$evidence"

cleanup() {
    set +e
    if [[ -n $loader_pid ]]; then
        touch "$scratch/stop"
        wait "$loader_pid" 2>/dev/null
    fi
    stop_and_prune_unit_cgroup "$unit" "$evidence/abort-unit-stop" >/dev/null 2>&1
    systemctl reset-failed "$unit" >/dev/null 2>&1
    rm -f "$pin_root/manual-link" "$pin_root/systemd-link"
    rmdir "$pin_root" 2>/dev/null
    rmdir "$cgroup_root/manual" 2>/dev/null
    rmdir "$cgroup_root" 2>/dev/null
    rm -rf "$scratch"
    rm -f "$object"
}
trap cleanup EXIT

for path in "$cgroup_root" "$pin_root" "$scratch"; do
    if [[ -e $path ]]; then
        echo "refusing pre-existing probe path $path" >&2
        exit 78
    fi
done
if systemctl cat "$unit" >/dev/null 2>&1; then
    echo "refusing pre-existing probe unit $unit" >&2
    exit 78
fi
if [[ ! -x $loader || ! -r $source ]]; then
    echo "required diagnostic artifacts are absent" >&2
    exit 69
fi

mkdir -p "$scratch" "$cgroup_root" "$pin_root"
clang -target bpf -O2 -g -Wall -Werror -D__TARGET_ARCH_arm64 \
    -I/usr/include/aarch64-linux-gnu -c "$source" -o "$object"

capture_link() {
    local pin=$1 output=$2 trace=$3
    set +e
    bpftool -j -p link show pinned "$pin" > "$output" 2> "$output.stderr"
    local direct_status=$?
    strace -qq -f -e trace=bpf -o "$trace" bpftool -j link show pinned "$pin" \
        > "$output.trace-query.json" 2> "$output.trace-query.stderr"
    local trace_status=$?
    set -e
    printf '%s\n' "$direct_status" > "$output.exit"
    printf '%s\n' "$trace_status" > "$output.trace-query.exit"
    jq -e '.id > 0 and .prog_id > 0 and .type == "cgroup"' "$output" >/dev/null
    jq -e --slurpfile direct "$output" '
        .id == $direct[0].id and
        .prog_id == $direct[0].prog_id and
        .cgroup_id == $direct[0].cgroup_id and
        .attach_type == $direct[0].attach_type
    ' "$output.trace-query.json" >/dev/null
    grep -q 'BPF_OBJ_GET_INFO_BY_FD' "$trace"
}

wait_for_detached_link() {
    local pin=$1 prefix=$2
    local observations="$evidence/$prefix-detach-observations.jsonl"
    local started_ns deadline_ns attempt=0
    started_ns=$(date +%s%N)
    deadline_ns=$((started_ns + DETACH_WAIT_TIMEOUT_MS * 1000000))
    : > "$observations"
    while true; do
        local sample="$scratch/$prefix-detach-sample.json"
        set +e
        bpftool -j link show pinned "$pin" > "$sample" 2> "$sample.stderr"
        local status=$?
        set -e
        local observed_ns elapsed_ms
        observed_ns=$(date +%s%N)
        elapsed_ms=$(((observed_ns - started_ns) / 1000000))
        jq -e '.id > 0 and .prog_id > 0 and .type == "cgroup"' "$sample" >/dev/null
        jq -c --argjson attempt "$attempt" --argjson command_exit "$status" \
            --argjson elapsed_ms "$elapsed_ms" \
            --argjson timeout_ms "$DETACH_WAIT_TIMEOUT_MS" \
            --argjson poll_interval_ms "$DETACH_POLL_INTERVAL_MS" \
            --arg timestamp_ns "$observed_ns" '
            . + {
              attempt: $attempt,
              command_exit: $command_exit,
              timestamp_ns: $timestamp_ns,
              elapsed_ms: $elapsed_ms,
              timeout_ms: $timeout_ms,
              poll_interval_ms: $poll_interval_ms
            }' \
            "$sample" >> "$observations"
        if [[ $(jq -r '.cgroup_id' "$sample") == 0 && $observed_ns -le $deadline_ns ]]; then
            return 0
        fi
        if ((observed_ns >= deadline_ns)); then
            break
        fi
        attempt=$((attempt + 1))
        sleep 0.010
    done
    echo "link did not report cgroup_id zero inside the bounded detach window" >&2
    return 1
}

attach_and_pin() {
    local cgroup=$1 pin=$2 prefix=$3
    rm -f "$scratch/ready" "$scratch/stop"
    "$loader" "$object" "$cgroup" "$scratch/unused-pin" soglia_connect4 single \
        "$scratch/ready" "$scratch/stop" >"$evidence/$prefix-loader.stdout" \
        2>"$evidence/$prefix-loader.stderr" &
    loader_pid=$!
    for _ in $(seq 1 500); do
        [[ -e $scratch/ready ]] && break
        kill -0 "$loader_pid" 2>/dev/null || break
        sleep 0.01
    done
    [[ -e $scratch/ready ]] || {
        echo "loader did not publish ready for $prefix" >&2
        return 1
    }
    jq -e '.status == "ATTACHED"' "$scratch/ready" >/dev/null
    cp "$scratch/ready" "$evidence/$prefix-loader-ready.json"

    local cgroup_id link_id
    cgroup_id=$(stat -c %i "$cgroup")
    link_id=$(bpftool -j link show | jq -r --argjson id "$cgroup_id" \
        '[.[] | select(.type == "cgroup" and .cgroup_id == $id)] | if length == 1 then .[0].id else empty end')
    [[ $link_id =~ ^[0-9]+$ ]] || {
        bpftool -j -p link show > "$evidence/$prefix-link-discovery-failure.json"
        echo "could not identify exactly one link for cgroup id $cgroup_id" >&2
        return 1
    }
    bpftool link pin id "$link_id" "$pin"
    printf '%s\n' "$cgroup_id" > "$evidence/$prefix-cgroup-id.txt"
    printf '%s\n' "$link_id" > "$evidence/$prefix-link-id.txt"
    capture_link "$pin" "$evidence/$prefix-link-before.json" \
        "$evidence/$prefix-bpf-syscalls-before.txt"
    jq -r '.prog_id' "$evidence/$prefix-link-before.json" > "$evidence/$prefix-program-id.txt"
    bpftool -j -p prog show id "$(cat "$evidence/$prefix-program-id.txt")" \
        > "$evidence/$prefix-program-before.json"

    touch "$scratch/stop"
    wait "$loader_pid"
    loader_pid=
}

record_release() {
    local old_id=$1 current_path=$2 pin=$3 prefix=$4
    wait_for_detached_link "$pin" "$prefix"
    capture_link "$pin" "$evidence/$prefix-link-after.json" \
        "$evidence/$prefix-bpf-syscalls-after.txt"
    bpftool -j -p prog show id "$(cat "$evidence/$prefix-program-id.txt")" \
        > "$evidence/$prefix-program-after.json"
    find /sys/fs/cgroup -xdev -inum "$old_id" -print \
        > "$evidence/$prefix-old-id-paths.txt"
    if [[ -e $current_path ]]; then
        stat -Lc '{"path":"%n","inode":%i,"owner_uid":%u,"owner_gid":%g,"mode":"%a"}' \
            "$current_path" > "$evidence/$prefix-current-target.json"
    else
        printf '{"path":"%s","state":"ABSENT"}\n' "$current_path" \
            > "$evidence/$prefix-current-target.json"
    fi
}

bpftool -j -p prog show > "$evidence/baseline-programs.json"
bpftool -j -p link show > "$evidence/baseline-links.json"
bpftool -j -p map show > "$evidence/baseline-maps.json"
uname -a > "$evidence/uname.txt"
systemd --version > "$evidence/systemd-version.txt"
bpftool version > "$evidence/bpftool-version.txt"
printf '{"timeout_ms":%d,"poll_interval_ms":%d}\n' \
    "$DETACH_WAIT_TIMEOUT_MS" "$DETACH_POLL_INTERVAL_MS" \
    > "$evidence/detach-wait-parameters.json"
sha256sum "$object" "$loader" > "$evidence/artifact-sha256.txt"

# Direct kernel release: an empty cgroup with a pinned cgroup BPF link.
mkdir "$cgroup_root/manual"
attach_and_pin "$cgroup_root/manual" "$pin_root/manual-link" manual
manual_id=$(cat "$evidence/manual-cgroup-id.txt")
if rmdir "$cgroup_root/manual" 2> "$evidence/manual-rmdir.stderr"; then
    printf '0\n' > "$evidence/manual-rmdir.exit"
else
    status=$?
    printf '%s\n' "$status" > "$evidence/manual-rmdir.exit"
    echo "kernel did not release the empty cgroup while its pinned BPF link existed" >&2
    exit "$status"
fi
record_release "$manual_id" "$cgroup_root/manual" "$pin_root/manual-link" manual

# Real systemd Restart=on-failure. The transient unit's delegated cgroup is the
# parent of the attachment target, matching the production topology.
systemd-run --unit="$unit" --property=Type=exec --property=Delegate=yes \
    --property=KillMode=mixed --property=Restart=on-failure \
    --property=RestartSec=100ms --property=StartLimitBurst=5 \
    /usr/bin/sleep infinity > "$evidence/systemd-run.txt"
for _ in $(seq 1 500); do
    [[ $(systemctl show -P ActiveState "$unit") == active ]] && break
    sleep 0.01
done
unit_cgroup=$(systemctl show -P ControlGroup "$unit")
target="/sys/fs/cgroup$unit_cgroup/executions"
mkdir "$target"
systemctl show "$unit" -p MainPID -p NRestarts -p ControlGroup -p Delegate -p KillMode \
    > "$evidence/systemd-before.properties"
attach_and_pin "$target" "$pin_root/systemd-link" systemd
systemd_id=$(cat "$evidence/systemd-cgroup-id.txt")
old_main=$(systemctl show -P MainPID "$unit")
kill -KILL "$old_main"
for _ in $(seq 1 1000); do
    new_main=$(systemctl show -P MainPID "$unit")
    restarts=$(systemctl show -P NRestarts "$unit")
    if [[ $restarts -ge 1 && $new_main -gt 0 && $new_main != "$old_main" ]]; then
        break
    fi
    sleep 0.01
done
[[ ${restarts:-0} -ge 1 && ${new_main:-0} -gt 0 && $new_main != "$old_main" ]] || {
    echo "systemd did not complete the expected restart" >&2
    exit 1
}
unit_cgroup_after=$(systemctl show -P ControlGroup "$unit")
target_after="/sys/fs/cgroup$unit_cgroup_after/executions"
mkdir -p "$target_after"
systemctl show "$unit" -p MainPID -p NRestarts -p ControlGroup -p Delegate -p KillMode \
    > "$evidence/systemd-after.properties"
record_release "$systemd_id" "$target_after" "$pin_root/systemd-link" systemd

bpftool -j -p prog show > "$evidence/final-programs-before-cleanup.json"
bpftool -j -p link show > "$evidence/final-links-before-cleanup.json"
bpftool -j -p map show > "$evidence/final-maps-before-cleanup.json"
journalctl -u "$unit" --no-pager -o short-precise > "$evidence/systemd-journal.txt"

# The evaluator intentionally runs before cleanup while both defunct pinned
# links still exist.
build_case_result() {
    local name=$1
    jq -n \
        --slurpfile before "$evidence/$name-link-before.json" \
        --slurpfile after "$evidence/$name-link-after.json" \
        --slurpfile current "$evidence/$name-current-target.json" \
        --slurpfile detach_observations "$evidence/$name-detach-observations.jsonl" \
        --slurpfile program_before "$evidence/$name-program-before.json" \
        --slurpfile program_after "$evidence/$name-program-after.json" \
        --arg case_name "$name" \
        --argjson old_id "$(cat "$evidence/$name-cgroup-id.txt")" \
        --rawfile old_paths "$evidence/$name-old-id-paths.txt" '
        ($before[0]) as $before |
        ($after[0]) as $after |
        ($current[0]) as $current |
        ($program_before[0]) as $program_before |
        ($program_after[0]) as $program_after |
        ($old_paths | split("\n") | map(select(length > 0))) as $old_paths |
        {
          old_cgroup_id: $old_id,
          new_cgroup_id: $current.inode,
          old_id_paths: $old_paths,
          detach_observations: $detach_observations,
          link_before: $before,
          link_after: $after,
          program_before: $program_before,
          program_after: $program_after,
          assertions: {
            old_id_unresolvable: ($old_paths | length == 0),
            detach_converged_within_bound: (
              ($detach_observations | length) > 0 and
              ($detach_observations[-1].cgroup_id == 0)
            ),
            released_target_state_is_exact: (
              if $case_name == "systemd"
              then $current.inode != null and $current.inode != $old_id
              else $current.state == "ABSENT" and $current.inode == null
              end
            ),
            link_reports_detached: ($after.cgroup_id == 0),
            link_identity_preserved: (
              $after.id == $before.id and
              $after.prog_id == $before.prog_id and
              $after.attach_type == $before.attach_type
            ),
            program_remains_referenced: ($program_after.id == $before.prog_id)
          }
        }'
}

build_case_result manual > "$evidence/manual-result.json"
build_case_result systemd > "$evidence/systemd-result.json"
jq -n \
    --slurpfile manual "$evidence/manual-result.json" \
    --slurpfile systemd "$evidence/systemd-result.json" '
    {
      authoritative: false,
      purpose: "kernel proof for a released cgroup-BPF attachment target",
      cases: {manual: $manual[0], systemd: $systemd[0]}
    }
    | .verdict = (
        if all(.cases[]; all(.assertions[]; .)) then "PASS" else "UNPROVEN" end
      )' > "$evidence/result.json"
jq -e '.verdict == "PASS"' "$evidence/result.json" >/dev/null
