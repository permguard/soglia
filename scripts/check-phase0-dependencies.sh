#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# T10's other half: the Phase-0 binary links nothing of the later phases.
#
# The acceptance suite proves T1-T9 pass with those components inactive and that asking for one is
# refused. This proves none of them is even linked: no PIC protocol crate, no gRPC stack, no eBPF
# loader, and no TLS stack, since Phase 0 neither terminates nor originates TLS.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

forbidden='^(pic-protocol|pic-continuity|tonic|prost|grpcio|aya|libbpf-rs|libbpf-sys|redbpf|rustls|openssl|native-tls|rcgen)$'
status=0

for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
    linked="$(cargo tree --locked -p soglia -e normal --target "${target}" --prefix none --format '{p}' \
        | awk '{print $1}' | sort -u)"
    found="$(grep -E "${forbidden}" <<< "${linked}" || true)"
    if [ -n "${found}" ]; then
        printf 'the Phase-0 binary links later-phase crates for %s:\n%s\n' "${target}" "${found}" >&2
        status=1
    fi
done

if [ "${status}" -ne 0 ]; then
    exit 1
fi

printf 'ok: the Phase-0 binary links no PIC, gRPC, eBPF or TLS crate\n'
