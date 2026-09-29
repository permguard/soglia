#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Keep the delegated unit alive while a failed B4 driver is recovered from durable ownership.

set -uo pipefail

if [[ $# -ne 5 ]]; then
  echo 'usage: b4-driver-guard.sh <driver> <soglia> <config> <evidence> <recovery-evidence>' >&2
  exit 13
fi
driver=$1
binary=$2
config=$3
evidence=$4
recovery_evidence=$5

"$driver" "$binary" "$config" "$evidence"
driver_status=$?
if [[ $driver_status -eq 0 ]]; then
  exit 0
fi

"$driver" "$binary" "$config" "$recovery_evidence" --cleanup-recovery
recovery_status=$?
printf '%s\n' "$driver_status" > "$recovery_evidence/original-driver-status.txt"
printf '%s\n' "$recovery_status" > "$recovery_evidence/recovery-status.txt"
if [[ $recovery_status -ne 0 ]]; then
  echo "B4 production recovery failed with status $recovery_status" >&2
fi
exit "$driver_status"
