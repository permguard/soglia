#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
    build-essential \
    ca-certificates \
    clang \
    curl \
    iproute2 \
    jq \
    libbpf-dev \
    linux-libc-dev \
    linux-tools-common \
    "linux-tools-$(uname -r)" \
    llvm \
    musl-tools \
    nftables \
    pkg-config \
    runc

if [[ ! -x /root/.cargo/bin/rustup ]]; then
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
        https://sh.rustup.rs -o /var/tmp/soglia-rustup.sh
    sh /var/tmp/soglia-rustup.sh -y --profile minimal --default-toolchain 1.97.0
    rm -f /var/tmp/soglia-rustup.sh
fi

/root/.cargo/bin/rustup toolchain install 1.97.0 --profile minimal

case "$(uname -m)" in
    aarch64) musl_target=aarch64-unknown-linux-musl ;;
    x86_64) musl_target=x86_64-unknown-linux-musl ;;
    *)
        echo "unsupported guest architecture: $(uname -m)" >&2
        exit 15
        ;;
esac

/root/.cargo/bin/rustup target add --toolchain 1.97.0 "$musl_target"

install -d -m 0700 /var/lib/soglia-spike-runner
mountpoint -q /sys/fs/bpf || mount -t bpf -o mode=700 bpf /sys/fs/bpf
