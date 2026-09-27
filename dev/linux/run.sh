#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Runs a command inside the Linux development container, from the repository root.
#
#   dev/linux/run.sh cargo test --workspace
#   dev/linux/run.sh --privileged cargo test --workspace -- --ignored
#
# `--privileged` adds what the Phase-0 acceptance suite needs: a privileged container with its own
# cgroup namespace, and `cgroup-init.sh` delegating `/sys/fs/cgroup/soglia` inside it.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

privileged=()
entrypoint=()
if [ "${1:-}" = "--privileged" ]; then
    privileged=(--privileged --cgroupns=private)
    entrypoint=(dev/linux/cgroup-init.sh)
    shift
fi

docker volume create soglia-cargo >/dev/null
docker volume create soglia-target >/dev/null

exec docker run --rm ${privileged[@]+"${privileged[@]}"} \
    --volume "$PWD":/work \
    --volume soglia-cargo:/usr/local/cargo/registry \
    --volume soglia-target:/work/target \
    soglia-dev:local ${entrypoint[@]+"${entrypoint[@]}"} "$@"
