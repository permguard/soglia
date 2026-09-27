#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

spike=/soglia/spikes/cgroup-bpf
artifacts=/var/tmp/soglia-spike-2
cargo_target="$artifacts/cargo-target"
production_target="$artifacts/production-target"
rustup=/root/.cargo/bin/rustup
cargo=/root/.cargo/bin/cargo

case "$(uname -m)" in
    aarch64) musl_target=aarch64-unknown-linux-musl ;;
    x86_64) musl_target=x86_64-unknown-linux-musl ;;
    *)
        echo "unsupported guest architecture: $(uname -m)" >&2
        exit 15
        ;;
esac

install -d -m 0755 "$artifacts/bin" "$artifacts/bpf" "$cargo_target" "$production_target"

export CARGO_TARGET_DIR="$cargo_target"
"$cargo" +1.97.0 build \
    --manifest-path "$spike/Cargo.toml" \
    --release \
    --package soglia-spike-runner \
    --bins
"$cargo" +1.97.0 build \
    --manifest-path "$spike/Cargo.toml" \
    --release \
    --package soglia-spike-agent \
    --target "$musl_target"

CARGO_TARGET_DIR="$production_target" "$cargo" +1.97.0 build \
    --manifest-path /soglia/Cargo.toml \
    --release \
    --bin soglia

install -m 0755 "$cargo_target/release/soglia-spike-runner" "$artifacts/bin/soglia-spike-runner"
install -m 0755 "$cargo_target/release/s2_helper" "$artifacts/bin/s2-helper"
install -m 0755 "$cargo_target/release/s5_helper" "$artifacts/bin/s5-helper"
install -m 0755 "$cargo_target/release/s7_loader" "$artifacts/bin/s7-loader"
install -m 0755 "$cargo_target/release/s14_loader" "$artifacts/bin/s14-loader"
install -m 0755 "$cargo_target/release/b2_driver" "$artifacts/bin/b2-driver"
install -m 0755 \
    "$cargo_target/$musl_target/release/soglia-spike-agent" \
    "$artifacts/bin/soglia-spike-agent"
install -m 0755 "$production_target/release/soglia" "$artifacts/bin/soglia"

"$spike/build.sh" "$artifacts/bpf"

sha256sum \
    "$artifacts"/bin/* \
    "$artifacts"/bpf/*
