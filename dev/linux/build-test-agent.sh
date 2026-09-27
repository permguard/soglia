#!/bin/sh
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the static test agent and prints its path. A static binary needs nothing else inside the
# Execution's root filesystem.

set -eu

target="$(uname -m)-unknown-linux-musl"
cargo build --quiet --release -p soglia-test-agent --target "$target"
echo "$(pwd)/target/$target/release/soglia-test-agent"
