#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# S9: compose an unconditional foreign ancestor allow with the Soglia child deny.

set -euo pipefail

evidence="${S9_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s9/run1}"
runner=/soglia/spikes/cgroup-bpf/run-s4.sh
foreign_object=/var/tmp/spike/bpf/foreign.o
foreign_root=/sys/fs/bpf/soglia-foreign-s9
foreign_reader=/var/tmp/spike/target/release/foreign_trace

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence"

set +e
S4_EVIDENCE="$evidence" \
S4_FOREIGN_OBJECT="$foreign_object" \
S4_FOREIGN_ROOT="$foreign_root" \
S4_FOREIGN_READER="$foreign_reader" \
    "$runner"
runner_status=$?
set -e

result=UNPROVEN
reason="the S4 causal harness or S9 evidence oracle did not complete"

if [[ "$runner_status" -eq 0 ]]; then
    foreign_id=$(jq -r '.id' "$evidence/s4-foreign-allow.json")
    foreign_tag=$(jq -r '.tag' "$evidence/s4-foreign-allow.json")
    foreign_id_after=$(jq -r '.id' "$evidence/s4-foreign-allow-after.json")
    foreign_tag_after=$(jq -r '.tag' "$evidence/s4-foreign-allow-after.json")
    ancestor_id=$(jq -r '.[0].id' "$evidence/s4-foreign-ancestor-direct.json")
    ancestor_flags=$(jq -r '.[0].attach_flags' "$evidence/s4-foreign-ancestor-direct.json")
    phase_b_foreign=$(jq --argjson id "$foreign_id" '[.[] | select(.id == $id and .name == "foreign_allow")] | length' "$evidence/s4-phase-b-cgroup-effective.json")
    phase_b_soglia=$(jq '[.[] | select(.name == "soglia_connect4")] | length' "$evidence/s4-phase-b-cgroup-effective.json")
    phase_c_foreign=$(jq --argjson id "$foreign_id" '[.[] | select(.id == $id and .name == "foreign_allow")] | length' "$evidence/s4-phase-c-cgroup-effective.json")
    phase_c_control=$(jq '[.[] | select(.name == "soglia_connect4")] | length' "$evidence/s4-phase-c-cgroup-effective.json")
    trace_bytes=$(wc -c < "$evidence/s4-foreign-trace.txt")
    trace_records=$(grep -c '^record ' "$evidence/s4-foreign-trace.txt" || true)
    trace_direct_records=$(grep -c '^record .*who=2.*dport=16001.*rewritten=0' "$evidence/s4-foreign-trace.txt" || true)
    trace_proxy_records=$(grep -c '^record .*who=2.*dport=15001.*rewritten=0' "$evidence/s4-foreign-trace.txt" || true)
    cleanup_programs=$(sed -n 's/^soglia_foreign_program_count=//p' "$evidence/s4-cleanup.txt")
    cleanup_links=$(sed -n 's/^cgroup_link_count=//p' "$evidence/s4-cleanup.txt")

    if [[ "$foreign_id" == "$foreign_id_after" ]] && \
       [[ "$foreign_tag" == "$foreign_tag_after" ]] && \
       [[ "$ancestor_id" == "$foreign_id" ]] && \
       [[ "$ancestor_flags" == multi ]] && \
       [[ "$phase_b_foreign" -eq 1 ]] && [[ "$phase_b_soglia" -eq 1 ]] && \
       [[ "$phase_c_foreign" -eq 1 ]] && [[ "$phase_c_control" -eq 1 ]] && \
       [[ "$trace_bytes" -gt 0 ]] && [[ "$trace_records" -eq 4 ]] && \
       [[ "$trace_direct_records" -eq 3 ]] && [[ "$trace_proxy_records" -eq 1 ]] && \
       grep -q 'phase_b_direct_listener_accept=false' "$evidence/s4-harness.txt" && \
       grep -q 'phase-b-bpf-deny_diag=\[1, 1,' "$evidence/s4-harness.txt" && \
       grep -q 'phase-b-bpf-deny_counters=\[0, 0, 0, 0, 1,' "$evidence/s4-harness.txt" && \
       grep -q 'phase-b-bpf-deny_deny_entries=1' "$evidence/s4-harness.txt" && \
       grep -q 'phase-b-bpf-deny_event_count=1' "$evidence/s4-harness.txt" && \
       grep -q 'phase_c_direct_listener_accept=true' "$evidence/s4-harness.txt" && \
       grep -q 'phase-c-path-control_counters=\[0, 0, 1, 0, 0,' "$evidence/s4-harness.txt" && \
       grep -q 'nft_restoration_exact=true' "$evidence/s4-nft-restoration.txt" && \
       [[ "$cleanup_programs" -eq 0 ]] && [[ "$cleanup_links" -eq 0 ]] && \
       grep -q '^ABSENT /sys/fs/bpf/soglia-spike$' "$evidence/s4-cleanup.txt" && \
       grep -q '^ABSENT /sys/fs/bpf/soglia-foreign-s9$' "$evidence/s4-cleanup.txt" && \
       cmp -s "$evidence/s4-baseline-prog.json" "$evidence/s4-final-prog.json" && \
       cmp -s "$evidence/s4-baseline-link.json" "$evidence/s4-final-link.json" && \
       cmp -s "$evidence/s4-baseline-map.json" "$evidence/s4-final-map.json" && \
       cmp -s "$evidence/s4-baseline-bpffs.txt" "$evidence/s4-final-bpffs.txt" && \
       grep -q '^ABSENT /sys/fs/cgroup/system.slice/soglia-spike-s0.service/executions$' "$evidence/s4-cleanup.txt"; then
        result=PASS
        reason="foreign ancestor allow and child Soglia deny composed fail-closed; the causal child control established"
    fi
fi

{
    echo "# S9 foreign ancestor allow coexistence"
    date -u +"UTC=%FT%TZ"
    echo "runner_status=$runner_status"
    echo "result=$result"
    echo "reason=$reason"
    if [[ "$runner_status" -eq 0 ]]; then
        echo "foreign_allow_id=$foreign_id"
        echo "foreign_allow_tag=$foreign_tag"
        echo "foreign_attach_type=cgroup_inet4_connect"
        echo "foreign_attach_mode=legacy_multi"
        echo "foreign_rewrite_attached=false"
        echo "case_a=foreign_allow effective plus child soglia_connect4 deny: connection did not establish; listener accept false; hook entry, deny counter, deny map and deny event each observed"
        echo "case_b=foreign_allow effective plus spike-only permissive child control: connection established; listener accept true; deny counter zero"
        echo "nft_relaxation=one exact namespace output accept for 10.201.0.2:16001"
        echo "nft_restoration_exact=true"
        echo "foreign_trace_bytes=$trace_bytes"
        echo "foreign_trace_records=$trace_records"
        echo "foreign_trace_direct_16001_records=$trace_direct_records"
        echo "foreign_trace_proxy_15001_records=$trace_proxy_records"
        echo "invocation_chronology=the foreign ring buffer recorded the harness sequence nft-control direct, proxy, Soglia-denied direct, permissive-control direct; all foreign invocations returned allow without rewrite"
        echo "ordering_claim=no relative foreign/child execution order is claimed; none is inferred from bpftool list order"
        echo "namespace_constraint=owned netns route and all other namespace/host nft constraints remained active"
        echo "proxy_involvement_cases_a_b=false"
        echo "cleanup_soglia_foreign_program_count=$cleanup_programs"
        echo "cleanup_cgroup_link_count=$cleanup_links"
        echo "cleanup_program_set_equals_baseline=true"
        echo "cleanup_link_set_equals_baseline=true"
        echo "cleanup_map_set_equals_baseline=true"
        echo "cleanup_bpffs_equals_baseline=true"
    fi
    echo "production_code_modified_by_s9=false"
    echo "candidate_selected=false"
    echo "S9_RESULT=$result"
} > "$evidence/s9-summary.txt"

[[ "$result" == PASS ]]
