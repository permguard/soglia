#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# T10: exact eBPF dependencies in the default build, and no eBPF/PIC/gRPC/TLS in the
# explicit no-default-features compatibility build.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

forbidden_control_plane='^(pic-protocol|pic-continuity|tonic|prost|grpcio|rustls|openssl|native-tls|rcgen)$'
known_ebpf='^(aya|aya-obj|aya-log|libbpf-rs|libbpf-sys|redbpf)$'
expected_ebpf=$'aya\naya-obj\nlibbpf-rs\nlibbpf-sys'
status=0

package_set() {
    local target=$1
    shift
    cargo tree --locked -p soglia -e normal --target "$target" "$@" \
        --prefix none --format '{p}' | awk '{print $1}' | sort -u
}

for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
    default_linked=$(package_set "$target")
    found=$(grep -E "$forbidden_control_plane" <<< "$default_linked" || true)
    if [[ -n $found ]]; then
        printf 'the default production binary links forbidden control-plane/TLS crates for %s:\n%s\n' \
            "$target" "$found" >&2
        status=1
    fi
    observed_ebpf=$(grep -E "$known_ebpf" <<< "$default_linked" || true)
    if [[ $observed_ebpf != "$expected_ebpf" ]]; then
        printf 'the default production binary has an unexpected eBPF dependency set for %s:\nexpected:\n%s\nobserved:\n%s\n' \
            "$target" "$expected_ebpf" "$observed_ebpf" >&2
        status=1
    fi

    compatibility_linked=$(package_set "$target" --no-default-features)
    found=$(grep -E "$forbidden_control_plane|$known_ebpf" <<< "$compatibility_linked" || true)
    if [[ -n $found ]]; then
        printf 'the no-default-features compatibility binary links forbidden crates for %s:\n%s\n' \
            "$target" "$found" >&2
        status=1
    fi
done

[[ $status -eq 0 ]] || exit 1
printf 'ok: default build links exactly the reviewed eBPF set and no PIC/gRPC/TLS crates\n'
printf 'ok: no-default-features build links no eBPF, PIC, gRPC or TLS crate\n'
