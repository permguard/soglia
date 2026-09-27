#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Keeps one delegated systemd cgroup alive while two complete Soglia processes run in sequence.

set -euo pipefail

binary="${1:?usage: b1-service-loop.sh <soglia> <config> <control-dir>}"
config="${2:?usage: b1-service-loop.sh <soglia> <config> <control-dir>}"
control="${3:?usage: b1-service-loop.sh <soglia> <config> <control-dir>}"
mkdir -p "$control"

for cycle in 1 2; do
  "$binary" run -f "$config" > "$control/cycle-$cycle.log" 2>&1 &
  child=$!
  printf '%s\n' "$child" > "$control/cycle-$cycle.pid"
  set +e
  wait "$child"
  status=$?
  set -e
  printf '%s\n' "$status" > "$control/cycle-$cycle.exit"
  if [[ "$cycle" == 1 ]]; then
    while [[ ! -e "$control/next" ]]; do sleep 0.01; done
    rm "$control/next"
  fi
done

while [[ ! -e "$control/stop" ]]; do sleep 0.05; done
